package xjwt

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

			return verifier.resolveKey(ctx, parsedHeader, token)
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
	token *jwt.Token,
) (any, error) {
	if token.Method == nil || token.Method.Alg() != header.Algorithm {
		return nil, ErrUnexpectedAlgorithm
	}

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

	if key.method.Alg() != token.Method.Alg() {
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
	needsIssuedAt := config.requireIAT ||
		config.validateIAT ||
		config.maxLifetime > 0 ||
		config.maxAge > 0
	if !needsIssuedAt {
		return nil
	}

	issuedAt, err := claims.GetIssuedAt()
	if err != nil {
		return fmt.Errorf("%w: read iat: %w", ErrInvalidLifetime, err)
	}
	if issuedAt == nil {
		if config.requireIAT {
			return fmt.Errorf("%w: iat is required", ErrInvalidLifetime)
		}

		return nil
	}

	now := config.clock()
	if (config.validateIAT || config.maxAge > 0) &&
		issuedAt.After(now.Add(config.leeway)) {
		return ErrIssuedInFuture
	}

	if config.maxAge > 0 &&
		now.Sub(issuedAt.Time) > config.maxAge+config.leeway {
		return ErrInvalidLifetime
	}

	if config.maxLifetime == 0 {
		return nil
	}

	expiresAt, err := claims.GetExpirationTime()
	if err != nil {
		return fmt.Errorf("%w: read exp: %w", ErrInvalidLifetime, err)
	}
	if expiresAt == nil {
		return nil
	}
	if !expiresAt.After(issuedAt.Time) {
		return ErrInvalidLifetime
	}
	if expiresAt.Sub(issuedAt.Time) > config.maxLifetime {
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
