package xjwt

import (
	"fmt"
	"unicode"
	"unicode/utf8"

	"github.com/golang-jwt/jwt/v5"
)

const (
	headerParamAlgorithm = "alg"
	headerParamKeyID     = "kid"
	headerParamType      = "typ"
	headerParamCritical  = "crit"
	headerParamBase64    = "b64"

	algorithmNone = "none"

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

func parseTokenHeader(token *jwt.Token) (Header, error) {
	if token == nil || token.Method == nil {
		return Header{}, invalidHeader(
			"signing method is missing",
		)
	}

	if _, exists := token.Header[headerParamCritical]; exists {
		return Header{}, invalidHeader(
			"critical headers are not supported",
		)
	}

	if _, exists := token.Header[headerParamBase64]; exists {
		return Header{}, invalidHeader(
			"unencoded payloads are not supported",
		)
	}

	algorithm, err := headerString(
		token.Header,
		headerParamAlgorithm,
		maxAlgorithmLength,
		true,
	)
	if err != nil {
		return Header{}, err
	}

	if algorithm == algorithmNone || algorithm != token.Method.Alg() {
		return Header{}, ErrUnexpectedAlgorithm
	}

	keyID, err := headerString(
		token.Header,
		headerParamKeyID,
		maxKeyIDLength,
		false,
	)
	if err != nil {
		return Header{}, err
	}

	if err := validateKeyID(keyID); err != nil {
		return Header{}, fmt.Errorf(
			"%w: %w",
			ErrInvalidHeader,
			err,
		)
	}

	typ, err := headerString(
		token.Header,
		headerParamType,
		maxTypeLength,
		false,
	)
	if err != nil {
		return Header{}, err
	}

	return Header{
		Algorithm: algorithm,
		KeyID:     keyID,
		Type:      typ,
	}, nil
}

func headerString(
	header map[string]any,
	name string,
	maxLength int,
	required bool,
) (string, error) {
	value, exists := header[name]
	if !exists {
		if required {
			return "", fmt.Errorf(
				"%w: %s is required",
				ErrInvalidHeader,
				name,
			)
		}

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

	if err := validateHeaderValue(name, text, maxLength); err != nil {
		return "", fmt.Errorf(
			"%w: %w",
			ErrInvalidHeader,
			err,
		)
	}

	return text, nil
}

func validateHeaderValue(name, value string, maxLength int) error {
	if value == "" {
		return fmt.Errorf(
			"%s must not be empty",
			name,
		)
	}

	if len(value) > maxLength {
		return fmt.Errorf(
			"%s exceeds %d bytes",
			name,
			maxLength,
		)
	}

	if !utf8.ValidString(value) {
		return fmt.Errorf(
			"%s is not valid UTF-8",
			name,
		)
	}

	for _, character := range value {
		if unicode.IsControl(character) {
			return fmt.Errorf(
				"%s contains control characters",
				name,
			)
		}
	}

	return nil
}

func invalidHeader(message string) error {
	return fmt.Errorf(
		"%w: %s",
		ErrInvalidHeader,
		message,
	)
}
