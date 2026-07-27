package jwt

import (
	"fmt"

	"github.com/golang-jwt/jwt/v5"
)

const (
	headerParamAlgorithm = "alg"
	headerParamKeyID     = "kid"
	headerParamType      = "typ"
	headerParamCritical  = "crit"
	headerParamBase64    = "b64"

	maxAlgorithmLength = 64
	maxKeyIDLength     = 256
	maxTypeLength      = 128
)

// Header contains the protected JOSE header values.
type Header struct {
	Algorithm string
	KeyID     string
	Type      string
}

func (h Header) validate(expectedAlgorithm string) error {
	if err := validateHeaderValue(headerParamAlgorithm, h.Algorithm, maxAlgorithmLength); err != nil {
		return fmt.Errorf("%w: %w", ErrInvalidHeader, err)
	}

	// Ensure that the signing method selected from the registry reports the
	// same algorithm identifier as the protected header.
	if h.Algorithm != expectedAlgorithm {
		return ErrUnexpectedAlgorithm
	}

	if h.KeyID != "" {
		if err := validateHeaderValue(headerParamKeyID, h.KeyID, maxKeyIDLength); err != nil {
			return fmt.Errorf("%w: %w", ErrInvalidHeader, err)
		}
	}

	if h.Type != "" {
		if err := validateHeaderValue(headerParamType, h.Type, maxTypeLength); err != nil {
			return fmt.Errorf("%w: %w", ErrInvalidHeader, err)
		}
	}

	return nil
}

func parseTokenHeader(token *jwt.Token) (Header, error) {
	if token == nil || token.Method == nil {
		return Header{}, fmt.Errorf(
			"%w: signing method is missing",
			ErrInvalidHeader,
		)
	}

	if err := validateJWTHeaderExtensions(token.Header); err != nil {
		return Header{}, err
	}

	algorithm, err := headerString(token.Header, headerParamAlgorithm)
	if err != nil {
		return Header{}, err
	}

	keyID, err := headerString(token.Header, headerParamKeyID)
	if err != nil {
		return Header{}, err
	}

	typ, err := headerString(token.Header, headerParamType)
	if err != nil {
		return Header{}, err
	}

	header := Header{
		Algorithm: algorithm,
		KeyID:     keyID,
		Type:      typ,
	}

	if err := header.validate(token.Method.Alg()); err != nil {
		return Header{}, err
	}

	return header, nil
}

func headerString(header map[string]any, name string) (string, error) {
	value, exists := header[name]
	if !exists {
		return "", nil
	}

	text, ok := value.(string)
	if !ok {
		return "", fmt.Errorf(
			"%w: %s must be a string",
			ErrInvalidHeader,
			name,
		)
	}

	return text, nil
}

func validateHeaderValue(name, value string, maxLength int) error {
	if value == "" {
		return fmt.Errorf("%s must not be empty", name)
	}

	if exceedsLimit(value, maxLength) {
		return fmt.Errorf("%s exceeds %d bytes", name, maxLength)
	}

	return nil
}

func validateJWTHeaderExtensions(header map[string]any) error {
	// JWT payloads must remain Base64URL-encoded. The b64 extension enables
	// unencoded JWS payloads, which are not permitted for JWT.
	if _, exists := header[headerParamBase64]; exists {
		return fmt.Errorf(
			"%w: b64 header parameter is not supported for JWT",
			ErrInvalidHeader,
		)
	}

	// Critical header parameters require explicit processing by the verifier.
	// Reject crit because silently ignoring mandatory extensions could change
	// the token's security semantics.
	if _, exists := header[headerParamCritical]; exists {
		return fmt.Errorf(
			"%w: critical headers are not supported",
			ErrInvalidHeader,
		)
	}

	return nil
}
