package xjwt

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// VerifiedToken contains a fully verified JOSE header and typed claims.
type VerifiedToken[C jwt.Claims] struct {
	Header Header
	Claims C
}

// Verifier verifies compact signed JWTs and validates typed claims.
type Verifier[C jwt.Claims] struct {
	factory  func() C
	resolver KeyResolver
	config   verifierConfig
	parser   *jwt.Parser
}

// NewVerifier creates an immutable verifier.
func NewVerifier[C jwt.Claims](
	factory func() C,
	resolver KeyResolver,
	options ...VerifierOption,
) (*Verifier[C], error) {
	if factory == nil {
		return nil, fmt.Errorf("%w: claims factory is nil", ErrInvalidConfig)
	}
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

	methodNames := make([]string, 0, len(config.methods))
	for _, method := range config.methods {
		methodNames = append(methodNames, method.Alg())
	}

	parserOptions := []jwt.ParserOption{
		jwt.WithValidMethods(methodNames),
		jwt.WithStrictDecoding(),
		jwt.WithTimeFunc(config.clock),
	}

	if config.requireExp {
		parserOptions = append(parserOptions, jwt.WithExpirationRequired())
	}
	if config.requireNBF {
		parserOptions = append(parserOptions, jwt.WithNotBeforeRequired())
	}
	if config.validateIAT {
		parserOptions = append(parserOptions, jwt.WithIssuedAt())
	}
	if config.issuer != "" {
		parserOptions = append(parserOptions, jwt.WithIssuer(config.issuer))
	}
	if len(config.audiences) != 0 {
		if config.audienceMode == audienceAll {
			parserOptions = append(parserOptions, jwt.WithAllAudiences(config.audiences...))
		} else {
			parserOptions = append(parserOptions, jwt.WithAudience(config.audiences...))
		}
	}
	if config.subject != "" {
		parserOptions = append(parserOptions, jwt.WithSubject(config.subject))
	}
	if config.leeway != 0 {
		parserOptions = append(parserOptions, jwt.WithLeeway(config.leeway))
	}

	return &Verifier[C]{
		factory:  factory,
		resolver: resolver,
		config:   config,
		parser:   jwt.NewParser(parserOptions...),
	}, nil
}

// Verify verifies raw and returns typed claims.
func (verifier *Verifier[C]) Verify(ctx context.Context, raw string) (C, error) {
	verified, err := verifier.VerifyToken(ctx, raw)

	return verified.Claims, err
}

// VerifyToken verifies raw and returns both the trusted header and typed claims.
func (verifier *Verifier[C]) VerifyToken(
	ctx context.Context,
	raw string,
) (VerifiedToken[C], error) {
	var zero VerifiedToken[C]

	if verifier == nil {
		return zero, fmt.Errorf("%w: verifier is nil", ErrInvalidConfig)
	}
	if ctx == nil {
		return zero, fmt.Errorf("%w: context is nil", ErrInvalidConfig)
	}
	if err := ctx.Err(); err != nil {
		return zero, err
	}

	compact, err := parseCompactToken(raw, verifier.config.maxSize)
	if err != nil {
		return zero, err
	}

	claims := verifier.factory()
	if any(claims) == nil {
		return zero, fmt.Errorf("%w: claims factory returned nil", ErrInvalidConfig)
	}

	header := compact.header

	token, err := verifier.parser.ParseWithClaims(
		raw,
		claims,
		func(token *jwt.Token) (any, error) {
			if token.Method == nil || token.Method.Alg() != header.Algorithm {
				return nil, ErrUnexpectedAlgorithm
			}

			key, resolveErr := verifier.resolver.Resolve(ctx, header)
			if resolveErr != nil {
				return nil, resolveErr
			}
			if key.method == nil || key.method.Alg() != token.Method.Alg() {
				return nil, ErrUnexpectedAlgorithm
			}

			return key.key, nil
		},
	)
	if err != nil {
		return zero, classifyVerifyError(err)
	}
	if token == nil || !token.Valid {
		return zero, ErrInvalidSignature
	}

	if verifier.config.typ != "" && header.Type != verifier.config.typ {
		return zero, ErrUnexpectedType
	}
	if verifier.config.cty != "" && header.ContentType != verifier.config.cty {
		return zero, ErrUnexpectedContentType
	}
	if err := validateRequiredClaims(compact.claimMembers, verifier.config.requiredClaims); err != nil {
		return zero, err
	}
	if err := validateLifetime(claims, verifier.config); err != nil {
		return zero, err
	}

	return VerifiedToken[C]{
		Header: header,
		Claims: claims,
	}, nil
}

func validateRequiredClaims(
	members map[string]json.RawMessage,
	required []string,
) error {
	for _, name := range required {
		if _, exists := members[name]; !exists {
			return fmt.Errorf("%w: required claim %q is missing", ErrInvalidClaims, name)
		}
	}

	return nil
}

func validateLifetime(claims jwt.Claims, config verifierConfig) error {
	if !config.requireIAT && config.maxLifetime == 0 && config.maxAge == 0 {
		return nil
	}

	issuedAt, err := claims.GetIssuedAt()
	if err != nil {
		return fmt.Errorf("%w: read iat: %w", ErrInvalidLifetime, err)
	}
	if issuedAt == nil {
		return fmt.Errorf("%w: iat is required", ErrInvalidLifetime)
	}

	now := config.clock()
	if issuedAt.Time.After(now.Add(config.leeway)) {
		return ErrIssuedInFuture
	}

	if config.maxAge > 0 && now.Sub(issuedAt.Time) > config.maxAge+config.leeway {
		return ErrInvalidLifetime
	}

	if config.maxLifetime > 0 {
		expiresAt, expirationErr := claims.GetExpirationTime()
		if expirationErr != nil {
			return fmt.Errorf("%w: read exp: %w", ErrInvalidLifetime, expirationErr)
		}
		if expiresAt == nil {
			return fmt.Errorf("%w: exp is required", ErrInvalidLifetime)
		}
		if expiresAt.Time.Before(issuedAt.Time) {
			return ErrInvalidLifetime
		}
		if expiresAt.Time.Sub(issuedAt.Time) > config.maxLifetime {
			return ErrInvalidLifetime
		}
	}

	return nil
}

func classifyVerifyError(err error) error {
	switch {
	case errors.Is(err, context.Canceled),
		errors.Is(err, context.DeadlineExceeded):
		return err

	case errors.Is(err, jwt.ErrTokenExpired):
		return fmt.Errorf("%w: %w", ErrExpiredToken, err)

	case errors.Is(err, jwt.ErrTokenNotValidYet):
		return fmt.Errorf("%w: %w", ErrNotYetValid, err)

	case errors.Is(err, jwt.ErrTokenUsedBeforeIssued):
		return fmt.Errorf("%w: %w", ErrIssuedInFuture, err)

	case errors.Is(err, jwt.ErrTokenSignatureInvalid):
		return fmt.Errorf("%w: %w", ErrInvalidSignature, err)

	case errors.Is(err, jwt.ErrTokenRequiredClaimMissing):
		return fmt.Errorf("%w: %w", ErrInvalidClaims, err)

	case errors.Is(err, jwt.ErrTokenInvalidAudience),
		errors.Is(err, jwt.ErrTokenInvalidIssuer),
		errors.Is(err, jwt.ErrTokenInvalidSubject),
		errors.Is(err, jwt.ErrTokenInvalidClaims):
		return fmt.Errorf("%w: %w", ErrInvalidClaims, err)

	case errors.Is(err, ErrUnknownKey),
		errors.Is(err, ErrMissingKeyID),
		errors.Is(err, ErrUnexpectedAlgorithm),
		errors.Is(err, ErrKeyUnavailable):
		return err

	default:
		return fmt.Errorf("%w: %w", ErrVerify, err)
	}
}
