package jwt

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// Verifier verifies compact signed JWTs and validates typed claims.
type Verifier struct {
	resolver KeyResolver
	config   verifierConfig
	parser   *jwt.Parser
}

// NewVerifier creates an immutable verifier.
func NewVerifier(
	resolver KeyResolver,
	options ...VerifierOption,
) (*Verifier, error) {
	if resolver == nil {
		return nil, fmt.Errorf("%w: key resolver is nil", ErrInvalidConfig)
	}

	config := verifierConfig{
		maxSize:    DefaultMaxTokenSize,
		requireExp: true,
		clock:      time.Now,
	}

	for _, option := range options {
		if option == nil {
			return nil, fmt.Errorf("%w: nil verifier option", ErrInvalidConfig)
		}

		if err := option.applyVerifier(&config); err != nil {
			return nil, err
		}
	}

	if len(config.methods) == 0 {
		return nil, fmt.Errorf("%w: WithMethods is required", ErrInvalidConfig)
	}

	return &Verifier{
		resolver: resolver,
		config:   config,
		parser: jwt.NewParser(
			config.parserOptions()...,
		),
	}, nil
}

// Verify verifies raw and decodes its payload into claims.
//
// Claims must be non-nil and must not be used concurrently. It may be
// partially modified when verification returns an error.
func (verifier *Verifier) Verify(
	ctx context.Context,
	raw string,
	claims jwt.Claims,
) error {
	_, err := verifier.VerifyToken(ctx, raw, claims)
	return err
}

// VerifyToken verifies raw and decodes its payload into claims.
//
// Claims must be a non-nil initialized value and must not be used
// concurrently. It may be partially modified when verification returns
// an error.
func (verifier *Verifier) VerifyToken(
	ctx context.Context,
	raw string,
	claims jwt.Claims,
) (Header, error) {
	if verifier == nil {
		return Header{}, fmt.Errorf("%w: verifier is nil", ErrInvalidConfig)
	}
	if claims == nil {
		return Header{}, fmt.Errorf("%w: claims are nil", ErrInvalidClaims)
	}
	if ctx == nil {
		return Header{}, fmt.Errorf("%w: context is nil", ErrInvalidConfig)
	}

	if err := validateRawToken(raw, verifier.config.maxSize); err != nil {
		return Header{}, err
	}

	header, err := verifier.parse(ctx, raw, claims)
	if err != nil {
		return Header{}, err
	}

	if err := verifier.validatePolicy(header, claims); err != nil {
		return Header{}, err
	}

	return header, nil
}

func (verifier *Verifier) parse(
	ctx context.Context,
	raw string,
	claims jwt.Claims,
) (Header, error) {
	var header Header

	token, err := verifier.parser.ParseWithClaims(
		raw,
		claims,
		func(token *jwt.Token) (any, error) {
			parsedHeader, err := parseTokenHeader(token)
			if err != nil {
				return nil, err
			}

			header = parsedHeader

			return verifier.resolveKey(ctx, parsedHeader)
		},
	)
	if err != nil {
		return Header{}, classifyVerifyError(err)
	}

	if token == nil || !token.Valid {
		return Header{}, ErrInvalidSignature
	}

	return header, nil
}

func (verifier *Verifier) resolveKey(
	ctx context.Context,
	header Header,
) (any, error) {
	key, err := verifier.resolver.Resolve(ctx, header)
	if err != nil {
		return nil, err
	}

	if key.method == nil || key.key == nil {
		return nil, fmt.Errorf(
			"%w: resolver returned an uninitialized verification key",
			ErrInvalidKey,
		)
	}

	if key.method.Alg() != header.Algorithm {
		return nil, ErrUnexpectedAlgorithm
	}

	return key.key, nil
}

func validateRawToken(raw string, maxSize int) error {
	if raw == "" {
		return ErrMissingToken
	}

	if len(raw) > maxSize {
		return fmt.Errorf(
			"%w: got %d bytes, limit is %d",
			ErrTokenTooLarge,
			len(raw),
			maxSize,
		)
	}

	return nil
}

func (verifier *Verifier) validatePolicy(header Header, claims jwt.Claims) error {
	if verifier.config.typ != "" && header.Type != verifier.config.typ {
		return ErrUnexpectedType
	}

	return validateLifetime(claims, verifier.config)
}

func validateLifetime(claims jwt.Claims, config verifierConfig) error {
	// Skip reading iat when no configured policy depends on it.
	if !config.requireIAT &&
		!config.validateIAT &&
		config.maxAge == 0 &&
		config.maxLifetime == 0 {
		return nil
	}

	issuedAt, err := claims.GetIssuedAt()
	if err != nil {
		return fmt.Errorf(
			"%w: read iat: %w",
			ErrInvalidLifetime,
			err,
		)
	}

	// iat remains optional unless RequireIssuedAt was configured.
	// Age and lifetime limits are applied only when the claim is present.
	if issuedAt == nil {
		if config.requireIAT {
			return fmt.Errorf(
				"%w: iat is required",
				ErrInvalidLifetime,
			)
		}

		return nil
	}

	// Future-time and maximum-age policies depend on the current time.
	// Leeway applies to both checks.
	if config.validateIAT || config.maxAge > 0 {
		now := config.clock()

		if issuedAt.After(now.Add(config.leeway)) {
			return ErrIssuedInFuture
		}

		if config.maxAge > 0 {
			oldestAllowed := now.Add(
				-config.maxAge - config.leeway,
			)

			if issuedAt.Before(oldestAllowed) {
				return ErrInvalidLifetime
			}
		}
	}

	// Maximum lifetime compares exp with iat and does not depend on the
	// current time. The policy is skipped when exp is absent.
	if config.maxLifetime == 0 {
		return nil
	}

	expiresAt, err := claims.GetExpirationTime()
	if err != nil {
		return fmt.Errorf(
			"%w: read exp: %w",
			ErrInvalidLifetime,
			err,
		)
	}

	if expiresAt == nil {
		return nil
	}

	lifetime := expiresAt.Sub(issuedAt.Time)
	if lifetime <= 0 ||
		lifetime > config.maxLifetime {
		return ErrInvalidLifetime
	}

	return nil
}

func classifyVerifyError(err error) error {
	switch {
	case errors.Is(err, context.Canceled),
		errors.Is(err, context.DeadlineExceeded):
		return err

	case errors.Is(err, jwt.ErrTokenMalformed):
		return fmt.Errorf("%w: %w",
			ErrMalformedToken,
			err,
		)

	case errors.Is(err, ErrInvalidHeader):
		return fmt.Errorf(
			"%w: %w",
			ErrMalformedToken,
			err,
		)

	case errors.Is(err, jwt.ErrTokenExpired):
		return fmt.Errorf(
			"%w: %w",
			ErrExpiredToken,
			err,
		)

	case errors.Is(err, jwt.ErrTokenNotValidYet):
		return fmt.Errorf(
			"%w: %w",
			ErrNotYetValid,
			err,
		)

	case errors.Is(err, jwt.ErrTokenUsedBeforeIssued):
		return fmt.Errorf(
			"%w: %w",
			ErrIssuedInFuture,
			err,
		)

	case errors.Is(err, jwt.ErrTokenSignatureInvalid):
		return fmt.Errorf(
			"%w: %w",
			ErrInvalidSignature,
			err,
		)

	case errors.Is(err, jwt.ErrTokenRequiredClaimMissing):
		return fmt.Errorf(
			"%w: %w",
			ErrInvalidClaims,
			err,
		)

	case errors.Is(err, jwt.ErrTokenInvalidAudience),
		errors.Is(err, jwt.ErrTokenInvalidIssuer),
		errors.Is(err, jwt.ErrTokenInvalidSubject),
		errors.Is(err, jwt.ErrTokenInvalidClaims):
		return fmt.Errorf(
			"%w: %w",
			ErrInvalidClaims,
			err,
		)

	case errors.Is(err, ErrUnknownKey),
		errors.Is(err, ErrMissingKeyID),
		errors.Is(err, ErrUnexpectedAlgorithm),
		errors.Is(err, ErrKeyUnavailable),
		errors.Is(err, ErrInvalidKey):
		return err

	default:
		return fmt.Errorf(
			"%w: %w",
			ErrVerify,
			err,
		)
	}
}
