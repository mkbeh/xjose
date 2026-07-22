package jwe

import "errors"

var (
	ErrInvalidConfig         = errors.New("invalid jwe configuration")
	ErrMissingToken          = errors.New("missing jwe")
	ErrMissingPlaintext      = errors.New("missing jwe plaintext")
	ErrTokenTooLarge         = errors.New("jwe is too large")
	ErrPlaintextTooLarge     = errors.New("jwe plaintext is too large")
	ErrMalformedToken        = errors.New("malformed jwe")
	ErrUnexpectedType        = errors.New("unexpected jwe type")
	ErrUnexpectedContentType = errors.New("unexpected jwe content type")
	ErrEncrypt               = errors.New("encrypt jwe")
	ErrDecrypt               = errors.New("decrypt jwe")
	ErrUnexpectedCompression = errors.New("unexpected jwe compression")
)
