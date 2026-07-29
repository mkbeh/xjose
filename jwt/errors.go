package jwt

import "errors"

var (
	// ErrInvalidConfig indicates that a signer, verifier, key set, or related
	// JWT component was configured with invalid or conflicting options.
	ErrInvalidConfig = errors.New("invalid jwt configuration")

	// ErrInvalidKey indicates that the supplied key material is missing,
	// unsupported, or incompatible with the requested operation.
	ErrInvalidKey = errors.New("invalid jwt key")

	// ErrInvalidKeyID indicates that a supplied key identifier is invalid.
	ErrInvalidKeyID = errors.New("invalid jwt key id")

	// ErrDuplicateKeyID indicates that more than one key uses the same key
	// identifier where identifiers must be unique.
	ErrDuplicateKeyID = errors.New("duplicate jwt key id")

	// ErrMissingKeyID indicates that a required key identifier is absent.
	ErrMissingKeyID = errors.New("missing jwt key id")

	// ErrUnknownKey indicates that no matching key could be resolved.
	ErrUnknownKey = errors.New("unknown jwt key")

	// ErrKeyUnavailable indicates that the required key cannot currently be
	// obtained or used.
	ErrKeyUnavailable = errors.New("jwt key unavailable")

	// ErrMissingToken indicates that no JWT was provided.
	ErrMissingToken = errors.New("missing jwt")

	// ErrMalformedToken indicates that the JWT cannot be parsed because its
	// structure or encoding is invalid.
	ErrMalformedToken = errors.New("malformed jwt")

	// ErrTokenTooLarge indicates that the JWT exceeds the configured maximum
	// token size.
	ErrTokenTooLarge = errors.New("jwt is too large")

	// ErrInvalidHeader indicates that the JWT header is malformed or contains
	// an invalid value.
	ErrInvalidHeader = errors.New("invalid jwt header")

	// ErrUnexpectedAlgorithm indicates that the JWT uses an algorithm that is
	// not allowed by the verification policy.
	ErrUnexpectedAlgorithm = errors.New("unexpected jwt algorithm")

	// ErrUnexpectedType indicates that the JWT type does not match the type
	// required by the verification policy.
	ErrUnexpectedType = errors.New("unexpected jwt type")

	// ErrInvalidSignature indicates that signature verification failed.
	ErrInvalidSignature = errors.New("invalid jwt signature")

	// ErrInvalidClaims indicates that the JWT claims are malformed or violate
	// the configured validation policy.
	ErrInvalidClaims = errors.New("invalid jwt claims")

	// ErrExpiredToken indicates that the JWT has passed its expiration time.
	ErrExpiredToken = errors.New("expired jwt")

	// ErrNotYetValid indicates that the JWT cannot be accepted before its
	// not-before time.
	ErrNotYetValid = errors.New("jwt is not valid yet")

	// ErrIssuedInFuture indicates that the JWT issue time is later than allowed
	// by the configured clock and leeway.
	ErrIssuedInFuture = errors.New("jwt issued in the future")

	// ErrInvalidLifetime indicates that the JWT lifetime violates the
	// configured validation policy.
	ErrInvalidLifetime = errors.New("invalid jwt lifetime")

	// ErrSign indicates that a JWT signing operation failed.
	ErrSign = errors.New("sign jwt")

	// ErrVerify indicates that a JWT verification operation failed.
	ErrVerify = errors.New("verify jwt")
)
