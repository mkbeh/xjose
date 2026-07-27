package jwe

import "fmt"

func validateRawToken(raw string, maxSize int) error {
	if raw == "" {
		return ErrMissingToken
	}

	return validateRawTokenSize(raw, maxSize)
}

func validateRawTokenSize(raw string, maxSize int) error {
	if exceedsLimit(len(raw), maxSize) {
		return fmt.Errorf(
			"%w: got %d bytes, limit is %d",
			ErrTokenTooLarge,
			len(raw),
			maxSize,
		)
	}

	return nil
}

func validatePlaintext(plaintext []byte, maxSize int) error {
	if len(plaintext) == 0 {
		return ErrMissingPlaintext
	}

	return validatePlaintextSize(plaintext, maxSize)
}

func validatePlaintextSize(plaintext []byte, maxSize int) error {
	if exceedsLimit(len(plaintext), maxSize) {
		return fmt.Errorf(
			"%w: got %d bytes, limit is %d",
			ErrPlaintextTooLarge,
			len(plaintext),
			maxSize,
		)
	}

	return nil
}

func validateAuthDataSize(authData []byte, maxSize int) error {
	if len(authData) > maxSize {
		return fmt.Errorf(
			"%w: authenticated data is %d bytes, token limit is %d",
			ErrTokenTooLarge,
			len(authData),
			maxSize,
		)
	}

	return nil
}

// exceedsLimit reports whether the length of value exceeds limit.
func exceedsLimit(size, limit int) bool {
	return size > limit
}
