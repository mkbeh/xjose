package xjwt

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	jwtv5 "github.com/golang-jwt/jwt/v5"
)

// VerifiedToken contains a trusted JOSE header and freshly decoded typed
// claims. Header is returned only after successful signature and claims
// verification.
type VerifiedToken[C jwtv5.Claims] struct {
	Header Header
	Claims C
}

// Verifier validates compact signed JWTs and returns freshly decoded typed
// claims. newClaims must return a fresh value suitable for JSON decoding.
type Verifier[C jwtv5.Claims] struct {
	resolver            KeyResolver
	newClaims           func() C
	validator           *jwtv5.Validator
	algorithms          map[Algorithm]struct{}
	expectedType        string
	expectedContentType string
	clock               func() time.Time
	leeway              time.Duration
	maxSize             int
	requireIat          bool
	maxLifetime         time.Duration
	maxTokenAge         time.Duration
	requiredClaims      []string
}

// NewVerifier creates a strict typed JWT verifier. WithAlgorithms is mandatory.
// exp is required by default; use AllowMissingExpiration only for an explicitly
// non-expiring token profile.
func NewVerifier[C jwtv5.Claims](
	newClaims func() C,
	resolver KeyResolver,
	options ...VerifierOption,
) (*Verifier[C], error) {
	if newClaims == nil {
		return nil, fmt.Errorf("%w: claims factory is nil", ErrInvalidConfig)
	}
	if resolver == nil {
		return nil, fmt.Errorf("%w: key resolver is nil", ErrInvalidConfig)
	}
	config := verifierConfig{clock: time.Now, maxSize: DefaultMaxTokenSize, requireExp: true}
	for index, option := range options {
		if option == nil {
			return nil, fmt.Errorf("%w: verifier option %d is nil", ErrInvalidConfig, index)
		}
		if err := option.applyVerifier(&config); err != nil {
			return nil, fmt.Errorf("apply verifier option %d: %w", index, err)
		}
	}
	if len(config.algorithms) == 0 {
		return nil, fmt.Errorf("%w: WithAlgorithms is required", ErrInvalidConfig)
	}
	algorithms := make(map[Algorithm]struct{}, len(config.algorithms))
	for _, algorithm := range config.algorithms {
		algorithms[algorithm] = struct{}{}
	}
	return &Verifier[C]{
		resolver:            resolver,
		newClaims:           newClaims,
		validator:           jwtv5.NewValidator(validatorOptions(config)...),
		algorithms:          algorithms,
		expectedType:        config.expectedType,
		expectedContentType: config.expectedContentType,
		clock:               config.clock,
		leeway:              config.leeway,
		maxSize:             config.maxSize,
		requireIat:          config.requireIat,
		maxLifetime:         config.maxLifetime,
		maxTokenAge:         config.maxTokenAge,
		requiredClaims:      append([]string(nil), config.requiredClaims...),
	}, nil
}

// Verify validates a compact JWT and returns typed claims.
func (v *Verifier[C]) Verify(ctx context.Context, raw string) (C, error) {
	var zero C
	verified, err := v.VerifyToken(ctx, raw)
	if err != nil {
		return zero, err
	}
	return verified.Claims, nil
}

// VerifyToken validates a compact JWT and returns its trusted header together
// with typed claims.
func (v *Verifier[C]) VerifyToken(ctx context.Context, raw string) (VerifiedToken[C], error) {
	var zero VerifiedToken[C]
	if v == nil || v.resolver == nil || v.newClaims == nil || v.validator == nil ||
		v.clock == nil || len(v.algorithms) == 0 || v.maxSize <= 0 {
		return zero, ErrInvalidConfig
	}
	if err := ctx.Err(); err != nil {
		return zero, err
	}

	parsed, err := parseCompactToken(raw, v.maxSize)
	if err != nil {
		return zero, fmt.Errorf("%w: parse compact token: %w", ErrVerify, err)
	}
	if _, allowed := v.algorithms[parsed.header.Algorithm]; !allowed {
		return zero, fmt.Errorf("%w: %w: %s", ErrVerify, ErrUnexpectedAlgorithm, parsed.header.Algorithm)
	}
	if v.expectedType != "" && parsed.header.Type != v.expectedType {
		return zero, fmt.Errorf(
			"%w: %w: expected %q, got %q",
			ErrVerify,
			ErrUnexpectedType,
			v.expectedType,
			parsed.header.Type,
		)
	}
	if v.expectedContentType != "" && parsed.header.ContentType != v.expectedContentType {
		return zero, fmt.Errorf("%w: %w: expected %q, got %q", ErrVerify, ErrUnexpectedContentType,
			v.expectedContentType, parsed.header.ContentType)
	}

	key, err := v.resolver.Resolve(ctx, parsed.header)
	if err != nil {
		return zero, classifyResolverError(err)
	}
	if key.value == nil {
		return zero, fmt.Errorf("%w: %w: resolved key is not initialized: %w", ErrVerify, ErrKeyUnavailable, ErrInvalidKey)
	}
	if key.algorithm != parsed.header.Algorithm {
		return zero, fmt.Errorf("%w: %w: resolver returned %s for %s", ErrVerify, ErrUnexpectedAlgorithm,
			key.algorithm, parsed.header.Algorithm)
	}
	if key.id != parsed.header.KeyID {
		return zero, fmt.Errorf("%w: %w", ErrVerify, ErrKeyIDMismatch)
	}
	if err := ctx.Err(); err != nil {
		return zero, err
	}

	if err := verifySignature(parsed.header.Algorithm, key, parsed.signingInput, parsed.signature); err != nil {
		return zero, fmt.Errorf("%w: %w", ErrVerify, ErrInvalidSignature)
	}
	if err := ctx.Err(); err != nil {
		return zero, err
	}

	claims := v.newClaims()
	// Decode through a pointer to C so both pointer claims structs and map-based
	// claims values can be used without reflection.
	if err := json.Unmarshal(parsed.payload, &claims); err != nil {
		return zero, fmt.Errorf("%w: %w: decode typed claims: %w", ErrVerify, ErrInvalidClaims, err)
	}
	if err := validateRequiredClaims(parsed.claimMembers, v.requiredClaims); err != nil {
		return zero, fmt.Errorf("%w: %w", ErrVerify, err)
	}
	if err := v.validator.Validate(claims); err != nil {
		return zero, classifyClaimsError(err)
	}
	if v.requireIat {
		issuedAt, err := claims.GetIssuedAt()
		if err != nil {
			return zero, fmt.Errorf("%w: %w: read iat: %w", ErrVerify, ErrInvalidClaims, err)
		}
		if issuedAt == nil {
			return zero, fmt.Errorf("%w: %w: iat", ErrVerify, ErrMissingClaim)
		}
	}
	if err := v.validateLifetime(claims); err != nil {
		return zero, err
	}
	if err := ctx.Err(); err != nil {
		return zero, err
	}
	return VerifiedToken[C]{Header: parsed.header, Claims: claims}, nil
}

func (v *Verifier[C]) validateLifetime(claims jwtv5.Claims) error {
	if v.maxLifetime == 0 && v.maxTokenAge == 0 {
		return nil
	}
	issuedAt, err := claims.GetIssuedAt()
	if err != nil {
		return fmt.Errorf("%w: %w: read iat: %w", ErrVerify, ErrInvalidClaims, err)
	}
	if issuedAt == nil {
		return fmt.Errorf("%w: %w: iat", ErrVerify, ErrMissingClaim)
	}
	if v.maxLifetime != 0 {
		expiresAt, err := claims.GetExpirationTime()
		if err != nil {
			return fmt.Errorf("%w: %w: read exp: %w", ErrVerify, ErrInvalidClaims, err)
		}
		if expiresAt == nil {
			return fmt.Errorf("%w: %w: exp", ErrVerify, ErrMissingClaim)
		}
		lifetime := expiresAt.Time.Sub(issuedAt.Time)
		if lifetime <= 0 || lifetime > v.maxLifetime {
			return fmt.Errorf("%w: %w: got %s, limit is %s", ErrVerify, ErrInvalidLifetime, lifetime, v.maxLifetime)
		}
	}
	if v.maxTokenAge != 0 {
		now := v.clock()
		if now.After(issuedAt.Time.Add(v.maxTokenAge).Add(v.leeway)) {
			return fmt.Errorf("%w: %w: maximum age %s exceeded", ErrVerify, ErrExpiredToken, v.maxTokenAge)
		}
	}
	return nil
}

func validateRequiredClaims(members map[string]json.RawMessage, required []string) error {
	for _, name := range required {
		raw, exists := members[name]
		if !exists || bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
			return fmt.Errorf("%w: %s", ErrMissingClaim, name)
		}
	}
	return nil
}

func classifyResolverError(err error) error {
	switch {
	case errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded):
		return err
	case errors.Is(err, ErrUnknownKey), errors.Is(err, ErrMissingKeyID),
		errors.Is(err, ErrKeyIDMismatch), errors.Is(err, ErrUnexpectedAlgorithm):
		return fmt.Errorf("%w: resolve key: %w", ErrVerify, err)
	case errors.Is(err, ErrKeyUnavailable):
		return fmt.Errorf("%w: resolve key: %w", ErrVerify, err)
	case errors.Is(err, ErrInvalidKey), errors.Is(err, ErrInvalidConfig):
		return fmt.Errorf("%w: %w: resolve key: %w", ErrVerify, ErrKeyUnavailable, err)
	default:
		return fmt.Errorf("%w: %w: resolve key: %w", ErrVerify, ErrKeyUnavailable, err)
	}
}

func classifyClaimsError(err error) error {
	switch {
	case errors.Is(err, jwtv5.ErrTokenExpired):
		return fmt.Errorf("%w: %w: %w", ErrVerify, ErrExpiredToken, err)
	case errors.Is(err, jwtv5.ErrTokenNotValidYet):
		return fmt.Errorf("%w: %w: %w", ErrVerify, ErrNotYetValid, err)
	case errors.Is(err, jwtv5.ErrTokenUsedBeforeIssued):
		return fmt.Errorf("%w: %w: %w", ErrVerify, ErrIssuedInFuture, err)
	case errors.Is(err, jwtv5.ErrTokenRequiredClaimMissing):
		return fmt.Errorf("%w: %w: %w", ErrVerify, ErrMissingClaim, err)
	default:
		return fmt.Errorf("%w: %w: %w", ErrVerify, ErrInvalidClaims, err)
	}
}
