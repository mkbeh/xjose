package jwe

import "errors"

var (
	// ErrInvalidConfig is returned when a constructor, option, or runtime
	// component has an invalid or uninitialized configuration.
	ErrInvalidConfig = errors.New("invalid jwe configuration")

	// ErrMissingToken is returned when an operation requiring serialized JWE
	// receives an empty token.
	ErrMissingToken = errors.New("missing jwe")

	// ErrMissingPlaintext is returned when encryption receives empty plaintext.
	ErrMissingPlaintext = errors.New("missing jwe plaintext")

	// ErrTokenTooLarge is returned when an input or generated JWE exceeds the
	// configured maximum token size.
	ErrTokenTooLarge = errors.New("jwe is too large")

	// ErrPlaintextTooLarge is returned when plaintext supplied for encryption or
	// produced by decryption exceeds the configured maximum plaintext size.
	ErrPlaintextTooLarge = errors.New("jwe plaintext is too large")

	// ErrMalformedToken is returned when JWE serialization cannot be parsed or
	// violates JOSE structural or algorithm constraints enforced during parsing.
	ErrMalformedToken = errors.New("malformed jwe")

	// ErrUnexpectedType is returned when the JWE typ header does not satisfy the
	// configured type policy.
	ErrUnexpectedType = errors.New("unexpected jwe type")

	// ErrUnexpectedContentType is returned when the JWE cty header does not
	// satisfy the configured content type policy.
	ErrUnexpectedContentType = errors.New("unexpected jwe content type")

	// ErrEncrypt is returned when creating an encryption backend, encrypting
	// plaintext, or serializing JWE fails.
	ErrEncrypt = errors.New("encrypt jwe")

	// ErrDecrypt is returned when JWE decryption or authentication fails.
	ErrDecrypt = errors.New("decrypt jwe")

	// ErrUnexpectedCompression is returned when the JWE zip header declares a
	// compression algorithm that is not permitted by the configured policy.
	ErrUnexpectedCompression = errors.New("unexpected jwe compression")
)
