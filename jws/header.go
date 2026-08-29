package jws

import (
	"fmt"
	"unicode/utf8"

	"github.com/go-jose/go-jose/v4"
)

const maxAlgorithmLength = 64

// Header contains parameters from a JWS Protected Header.
//
// The parameters are authenticated only after the corresponding signature has
// been successfully verified. Header values are read-only; JSONWebKey and
// ExtraHeaders reference values produced by go-jose and must not be mutated.
type Header struct {
	Algorithm    jose.SignatureAlgorithm
	KeyID        string
	Type         string
	ContentType  string
	Nonce        string
	JSONWebKey   *jose.JSONWebKey
	ExtraHeaders map[jose.HeaderKey]any
}

func (header Header) validate() error {
	check := func(name jose.HeaderKey, value string, maxLength int) error {
		if err := validateHeaderValue(name, value, maxLength); err != nil {
			return fmt.Errorf("%w: %w", ErrMalformedToken, err)
		}

		return nil
	}

	if err := check(headerAlgorithm, string(header.Algorithm), maxAlgorithmLength); err != nil {
		return err
	}

	// Key ID is optional and validated when present.
	if header.KeyID != "" {
		if err := check(headerKeyID, header.KeyID, maxKeyIDLength); err != nil {
			return err
		}
	}

	// Optional application metadata is validated when present.
	if header.Type != "" {
		if err := check(jose.HeaderType, header.Type, maxTypeLength); err != nil {
			return err
		}
	}

	if header.ContentType != "" {
		if err := check(jose.HeaderContentType, header.ContentType, maxContentTypeLength); err != nil {
			return err
		}
	}

	return nil
}

func parseProtectedHeader(source jose.Header) (Header, error) {
	if source.Algorithm == "" {
		return Header{}, fmt.Errorf(
			"%w: alg header is required and must be protected",
			ErrMalformedToken,
		)
	}

	if _, exists := source.ExtraHeaders[headerCritical]; exists {
		return Header{}, fmt.Errorf(
			"%w: critical headers are not supported",
			ErrMalformedToken,
		)
	}

	if _, exists := source.ExtraHeaders[headerBase64]; exists {
		return Header{}, fmt.Errorf(
			"%w: unencoded payloads are not supported",
			ErrMalformedToken,
		)
	}

	typ, err := headerString(source.ExtraHeaders, jose.HeaderType)
	if err != nil {
		return Header{}, err
	}

	contentType, err := headerString(source.ExtraHeaders, jose.HeaderContentType)
	if err != nil {
		return Header{}, err
	}

	header := Header{
		Algorithm:    jose.SignatureAlgorithm(source.Algorithm),
		KeyID:        source.KeyID,
		Type:         typ,
		ContentType:  contentType,
		Nonce:        source.Nonce,
		JSONWebKey:   source.JSONWebKey,
		ExtraHeaders: source.ExtraHeaders,
	}

	if err := header.validate(); err != nil {
		return Header{}, err
	}

	return header, nil
}

func validateHeaderValue(name jose.HeaderKey, value string, maxLength int) error {
	if value == "" {
		return fmt.Errorf(
			"%s must not be empty",
			name,
		)
	}

	if exceedsLimit(len(value), maxLength) {
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

	return nil
}

func validateHeaderPolicy(config config, header Header) error {
	if config.typ != "" && header.Type != config.typ {
		return fmt.Errorf(
			"%w: got %q, expected %q",
			ErrUnexpectedType,
			header.Type,
			config.typ,
		)
	}
	if config.cty != "" && header.ContentType != config.cty {
		return fmt.Errorf(
			"%w: got %q, expected %q",
			ErrUnexpectedContentType,
			header.ContentType,
			config.cty,
		)
	}

	return nil
}

func headerString(header map[jose.HeaderKey]any, name jose.HeaderKey) (string, error) {
	value, exists := header[name]
	if !exists {
		return "", nil
	}

	text, ok := value.(string)
	if !ok {
		return "", fmt.Errorf(
			"%w: %s must be a string", ErrMalformedToken, name,
		)
	}

	return text, nil
}
