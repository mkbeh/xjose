package jwks

import "errors"

var (
	// ErrInvalidSet indicates a malformed JSON Web Key Set.
	ErrInvalidSet = errors.New("invalid JWKS")

	// ErrNoUsableKeys indicates that a JWK Set contains no supported public
	// signature-verification keys.
	ErrNoUsableKeys = errors.New("JWKS contains no usable verification keys")

	// ErrTooManyKeys indicates that a JWK Set exceeds its configured key limit.
	ErrTooManyKeys = errors.New("JWKS contains too many keys")
)
