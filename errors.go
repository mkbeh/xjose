package xjwt

import "errors"

var (
	// ErrInvalidConfig indicates invalid signer, verifier, key, or option
	// configuration.
	ErrInvalidConfig = errors.New("invalid jwt configuration")

	// ErrInvalidAlgorithm indicates an unsupported JWS algorithm.
	ErrInvalidAlgorithm = errors.New("invalid jwt algorithm")

	// ErrInvalidKey indicates key material incompatible with its algorithm or
	// below the minimum security requirements.
	ErrInvalidKey = errors.New("invalid jwt key")

	// ErrInvalidKeyID indicates an invalid JOSE kid value.
	ErrInvalidKeyID = errors.New("invalid jwt key id")

	// ErrDuplicateKeyID indicates that a key set contains the same kid more than once.
	ErrDuplicateKeyID = errors.New("duplicate jwt key id")

	// ErrMissingKeyID indicates that a named verification key requires kid but
	// the token omitted it.
	ErrMissingKeyID = errors.New("missing jwt key id")

	// ErrUnknownKey indicates that no verification key matches the token header.
	ErrUnknownKey = errors.New("unknown jwt verification key")

	// ErrKeyIDMismatch indicates that a resolver returned a key with a different
	// identifier from the token header.
	ErrKeyIDMismatch = errors.New("jwt key id mismatch")

	// ErrKeyUnavailable indicates that verification key resolution could not be
	// completed because an external dependency was unavailable.
	ErrKeyUnavailable = errors.New("jwt verification key unavailable")

	// ErrMissingToken indicates an empty compact JWT input.
	ErrMissingToken = errors.New("missing jwt")

	// ErrMalformedToken indicates an invalid compact serialization, base64url
	// encoding, JSON object, or JOSE header.
	ErrMalformedToken = errors.New("malformed jwt")

	// ErrTokenTooLarge indicates that a compact JWT exceeds its configured size
	// limit.
	ErrTokenTooLarge = errors.New("jwt exceeds size limit")

	// ErrInvalidHeader indicates a malformed or unsupported JOSE header.
	ErrInvalidHeader = errors.New("invalid jwt header")

	// ErrUnsupportedCriticalHeader indicates that a token requests a critical
	// JOSE extension not implemented by xjwt.
	ErrUnsupportedCriticalHeader = errors.New("unsupported jwt critical header")

	// ErrUnexpectedAlgorithm indicates that alg is not allowed by verifier
	// policy or does not match the selected key.
	ErrUnexpectedAlgorithm = errors.New("unexpected jwt algorithm")

	// ErrUnexpectedType indicates an unexpected or missing typ header.
	ErrUnexpectedType = errors.New("unexpected jwt type")

	// ErrUnexpectedContentType indicates an unexpected or missing cty header.
	ErrUnexpectedContentType = errors.New("unexpected jwt content type")

	// ErrInvalidSignature indicates failed cryptographic signature verification.
	ErrInvalidSignature = errors.New("invalid jwt signature")

	// ErrInvalidClaims indicates failed registered or application-specific claims
	// validation.
	ErrInvalidClaims = errors.New("invalid jwt claims")

	// ErrMissingClaim indicates that verifier policy requires a missing claim.
	ErrMissingClaim = errors.New("missing required jwt claim")

	// ErrExpiredToken indicates that exp or maximum token age has elapsed.
	ErrExpiredToken = errors.New("expired jwt")

	// ErrNotYetValid indicates that nbf is in the future.
	ErrNotYetValid = errors.New("jwt is not valid yet")

	// ErrIssuedInFuture indicates that iat is in the future.
	ErrIssuedInFuture = errors.New("jwt issued in the future")

	// ErrInvalidLifetime indicates an invalid or excessive exp-to-iat lifetime.
	ErrInvalidLifetime = errors.New("invalid jwt lifetime")

	// ErrSign classifies failures while creating a compact signed JWT.
	ErrSign = errors.New("sign jwt")

	// ErrVerify classifies failures while parsing or verifying a compact JWT.
	ErrVerify = errors.New("verify jwt")
)
