package jwk

import "errors"

var (
	// ErrInvalid indicates a malformed JSON Web Key.
	ErrInvalid = errors.New("invalid JWK")

	// ErrUnsupportedKeyType indicates a key type that this package does not
	// implement for JWT signature verification.
	ErrUnsupportedKeyType = errors.New("unsupported JWK key type")

	// ErrUnsupportedCurve indicates an unsupported JWK curve.
	ErrUnsupportedCurve = errors.New("unsupported JWK curve")

	// ErrNotForSignature indicates a JWK whose declared use, operations, or
	// algorithm does not permit signature verification.
	ErrNotForSignature = errors.New("JWK is not usable for signature verification")

	// ErrPrivateKeyMaterial indicates that a public verification JWK contains
	// private or symmetric key material.
	ErrPrivateKeyMaterial = errors.New("JWK contains non-public key material")

	// ErrInvalidKeyOperation indicates invalid or contradictory key_ops values.
	ErrInvalidKeyOperation = errors.New("invalid JWK key operation")
)
