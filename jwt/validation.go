package jwt

import "fmt"

func validateRawToken(raw string, maxSize int) error {
	if raw == "" {
		return ErrMissingToken
	}

	if exceedsLimit(raw, maxSize) {
		return fmt.Errorf(
			"%w: got %d bytes, limit is %d",
			ErrTokenTooLarge,
			len(raw),
			maxSize,
		)
	}

	return nil
}

// exceedsLimit reports whether the length of value exceeds limit.
func exceedsLimit(value string, limit int) bool {
	return len(value) > limit
}
