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

type Header struct {
	Algorithm   string
	KeyID       string
	Type        string
	ContentType string
}

func parseHeader(data []byte) (Header, error) {
	members, err := parseJSONObject(data)
	if err != nil {
		return Header{}, fmt.Errorf("%w: %w", ErrInvalidHeader, err)
	}
	if _, ok := members["crit"]; ok {
		return Header{}, fmt.Errorf("%w: critical headers are not supported", ErrInvalidHeader)
	}
	if _, ok := members["b64"]; ok {
		return Header{}, fmt.Errorf("%w: b64 header is not supported", ErrInvalidHeader)
	}
	alg, err := requiredStringMember(members, "alg", 64)
	if err != nil || alg == "none" {
		return Header{}, ErrInvalidHeader
	}
	kid, err := optionalStringMember(members, "kid", maxKeyIDLength)
	if err != nil {
		return Header{}, ErrInvalidHeader
	}
	typ, err := optionalStringMember(members, "typ", maxTypeLength)
	if err != nil {
		return Header{}, ErrInvalidHeader
	}
	cty, err := optionalStringMember(members, "cty", maxContentTypeLength)
	if err != nil {
		return Header{}, ErrInvalidHeader
	}
	return Header{Algorithm: alg, KeyID: kid, Type: typ, ContentType: cty}, nil
}
func requiredStringMember(m map[string]json.RawMessage, n string, max int) (string, error) {
	r, ok := m[n]
	if !ok {
		return "", fmt.Errorf("%s is required", n)
	}
	return decodeHeaderString(r, n, max)
}
func optionalStringMember(m map[string]json.RawMessage, n string, max int) (string, error) {
	r, ok := m[n]
	if !ok {
		return "", nil
	}
	return decodeHeaderString(r, n, max)
}
func decodeHeaderString(raw json.RawMessage, n string, max int) (string, error) {
	var v string
	if err := json.Unmarshal(raw, &v); err != nil {
		return "", fmt.Errorf("%s must be a string", n)
	}
	if err := validateHeaderValue(n, v, max); err != nil {
		return "", err
	}
	return v, nil
}
func validateHeaderValue(n, v string, max int) error {
	if v == "" || len(v) > max || !utf8.ValidString(v) {
		return fmt.Errorf("%s must contain 1 to %d UTF-8 bytes", n, max)
	}
	for _, r := range v {
		if unicode.IsControl(r) {
			return fmt.Errorf("%s contains control characters", n)
		}
	}
	return nil
}
