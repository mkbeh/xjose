package jws

import (
	"fmt"

	"github.com/go-jose/go-jose/v4"
)

func validateRaw(raw string, maxSize int) error {
	if raw == "" {
		return fmt.Errorf(
			"%w: serialized JWS is empty",
			ErrMissingToken,
		)
	}

	return validateRawSize(raw, maxSize)
}

func validateRawSize(raw string, maxSize int) error {
	if len(raw) > maxSize {
		return fmt.Errorf(
			"%w: got %d bytes, limit is %d",
			ErrTokenTooLarge,
			len(raw),
			maxSize,
		)
	}

	return nil
}

func validatePayload(payload []byte, maxSize int) error {
	if payload == nil {
		return ErrMissingPayload
	}

	return validatePayloadSize(payload, maxSize)
}

func validatePayloadSize(payload []byte, maxSize int) error {
	if len(payload) > maxSize {
		return fmt.Errorf(
			"%w: got %d bytes, limit is %d",
			ErrPayloadTooLarge,
			len(payload),
			maxSize,
		)
	}

	return nil
}

func validateSignatures(
	object *jose.JSONWebSignature,
	maxSignatures int,
) error {
	if object == nil || len(object.Signatures) == 0 {
		return fmt.Errorf(
			"%w: JWS contains no signatures",
			ErrMalformedToken,
		)
	}

	if len(object.Signatures) > maxSignatures {
		return fmt.Errorf(
			"%w: got %d signatures, limit is %d",
			ErrTooManySignatures,
			len(object.Signatures),
			maxSignatures,
		)
	}

	return nil
}
