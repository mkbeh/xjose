package jws

import "errors"

var (
	// ErrInvalidConfig indicates an invalid constructor option, key, algorithm,
	// policy, or an uninitialized receiver.
	ErrInvalidConfig = errors.New("invalid jws configuration")

	// ErrMissingToken indicates that an empty serialized JWS was provided.
	ErrMissingToken = errors.New("missing jws")

	// ErrMissingPayload indicates that a nil payload was provided.
	ErrMissingPayload = errors.New("missing jws payload")

	// ErrPayloadTooLarge indicates that a payload exceeds the configured limit.
	ErrPayloadTooLarge = errors.New("jws payload is too large")

	// ErrTokenTooLarge indicates that serialized JWS data exceeds the configured
	// limit.
	ErrTokenTooLarge = errors.New("jws is too large")

	// ErrTooManySignatures indicates that a JWS JSON object contains or would
	// create more signatures than configured.
	ErrTooManySignatures = errors.New("too many jws signatures")

	// ErrMalformedToken indicates that serialized JWS data or its JOSE headers
	// are malformed or unsupported by this package.
	ErrMalformedToken = errors.New("malformed jws")

	// ErrUnexpectedType indicates that the protected typ header does not match
	// the configured value.
	ErrUnexpectedType = errors.New("unexpected jws type")

	// ErrUnexpectedContentType indicates that the protected cty header does not
	// match the configured value.
	ErrUnexpectedContentType = errors.New("unexpected jws content type")

	// ErrKeyNotFound indicates that a resolver has no trusted verification key
	// for a signature. MultiVerifier treats this as a failed signature and may
	// continue according to its policy.
	ErrKeyNotFound = errors.New("jws verification key not found")

	// ErrVerificationPolicy indicates that the valid signatures do not satisfy
	// the configured multi-signature policy.
	ErrVerificationPolicy = errors.New("jws verification policy not satisfied")

	// ErrSign indicates that JWS signing or serialization failed.
	ErrSign = errors.New("sign jws")

	// ErrVerify indicates that JWS cryptographic verification failed.
	ErrVerify = errors.New("verify jws")
)
