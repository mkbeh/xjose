package xjwt

import (
	"encoding/json"
	"fmt"
	"unicode"
	"unicode/utf8"
)

const (
	maxKeyIDLength       = 256
	maxTypeLength        = 128
	maxContentTypeLength = 128
)

// Header contains the JOSE header values used by xjwt. Values passed to a
// KeyResolver are parsed but remain untrusted until Verify succeeds.
type Header struct {
	Algorithm   Algorithm
	KeyID       string
	Type        string
	ContentType string
}

type encodedHeader struct {
	Algorithm   Algorithm `json:"alg"`
	Type        string    `json:"typ,omitempty"`
	ContentType string    `json:"cty,omitempty"`
	KeyID       string    `json:"kid,omitempty"`
}

func marshalHeader(header Header) ([]byte, error) {
	return json.Marshal(encodedHeader{
		Algorithm:   header.Algorithm,
		Type:        header.Type,
		ContentType: header.ContentType,
		KeyID:       header.KeyID,
	})
}

func parseHeader(data []byte) (Header, error) {
	members, err := parseJSONObject(data)
	if err != nil {
		return Header{}, fmt.Errorf("%w: %w", ErrInvalidHeader, err)
	}
	if _, exists := members["crit"]; exists {
		return Header{}, fmt.Errorf("%w: %w", ErrInvalidHeader, ErrUnsupportedCriticalHeader)
	}
	if _, exists := members["b64"]; exists {
		return Header{}, fmt.Errorf("%w: unencoded payloads are not supported", ErrInvalidHeader)
	}

	algorithmText, err := requiredStringMember(members, "alg", 32)
	if err != nil {
		return Header{}, fmt.Errorf("%w: %w", ErrInvalidHeader, err)
	}
	algorithm := Algorithm(algorithmText)
	if _, err := algorithm.spec(); err != nil {
		return Header{}, fmt.Errorf("%w: %w", ErrInvalidHeader, err)
	}

	keyID, err := optionalStringMember(members, "kid", maxKeyIDLength)
	if err != nil {
		return Header{}, fmt.Errorf("%w: %w", ErrInvalidHeader, err)
	}
	tokenType, err := optionalStringMember(members, "typ", maxTypeLength)
	if err != nil {
		return Header{}, fmt.Errorf("%w: %w", ErrInvalidHeader, err)
	}
	contentType, err := optionalStringMember(members, "cty", maxContentTypeLength)
	if err != nil {
		return Header{}, fmt.Errorf("%w: %w", ErrInvalidHeader, err)
	}

	return Header{
		Algorithm:   algorithm,
		KeyID:       keyID,
		Type:        tokenType,
		ContentType: contentType,
	}, nil
}

func requiredStringMember(members map[string]json.RawMessage, name string, maxLength int) (string, error) {
	raw, exists := members[name]
	if !exists {
		return "", fmt.Errorf("%s must be present", name)
	}
	return decodeHeaderString(raw, name, maxLength)
}

func optionalStringMember(members map[string]json.RawMessage, name string, maxLength int) (string, error) {
	raw, exists := members[name]
	if !exists {
		return "", nil
	}
	return decodeHeaderString(raw, name, maxLength)
}

func decodeHeaderString(raw json.RawMessage, name string, maxLength int) (string, error) {
	var value string
	if err := json.Unmarshal(raw, &value); err != nil {
		return "", fmt.Errorf("%s must be a string", name)
	}
	if err := validateHeaderValue(name, value, maxLength); err != nil {
		return "", err
	}
	return value, nil
}

func validateKeyID(id string) error {
	if id == "" {
		return nil
	}
	if err := validateHeaderValue("kid", id, maxKeyIDLength); err != nil {
		return fmt.Errorf("%w: %w", ErrInvalidKeyID, err)
	}
	return nil
}

func validateHeaderValue(name, value string, maxLength int) error {
	if value == "" || len(value) > maxLength || !utf8.ValidString(value) {
		return fmt.Errorf("%s must contain 1 to %d UTF-8 bytes", name, maxLength)
	}
	for _, r := range value {
		if unicode.IsControl(r) {
			return fmt.Errorf("%s must not contain control characters", name)
		}
	}
	return nil
}
