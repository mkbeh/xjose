package jws

import (
	"fmt"

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

func parseProtectedHeader(header jose.Header) (Header, error) {
	if header.Algorithm == "" {
		return Header{}, fmt.Errorf(
			"%w: alg header is required and must be protected",
			ErrMalformedToken,
		)
	}

	if err := validateHeaderText(headerAlgorithm, header.Algorithm, maxAlgorithmLength); err != nil {
		return Header{}, fmt.Errorf("%w: %w", ErrMalformedToken, err)
	}

	if header.KeyID != "" {
		if err := validateHeaderText(headerKeyID, header.KeyID, maxKeyIDLength); err != nil {
			return Header{}, fmt.Errorf("%w: %w", ErrMalformedToken, err)
		}
	}

	if _, exists := header.ExtraHeaders[headerCritical]; exists {
		return Header{}, fmt.Errorf("%w: critical headers are not supported", ErrMalformedToken)
	}

	if _, exists := header.ExtraHeaders[headerBase64]; exists {
		return Header{}, fmt.Errorf("%w: unencoded payloads are not supported", ErrMalformedToken)
	}

	typ, err := headerString(header.ExtraHeaders, jose.HeaderType, maxTypeLength)
	if err != nil {
		return Header{}, err
	}

	contentType, err := headerString(header.ExtraHeaders, jose.HeaderContentType, maxContentTypeLength)
	if err != nil {
		return Header{}, err
	}

	return Header{
		Algorithm:    jose.SignatureAlgorithm(header.Algorithm),
		KeyID:        header.KeyID,
		Type:         typ,
		ContentType:  contentType,
		Nonce:        header.Nonce,
		JSONWebKey:   header.JSONWebKey,
		ExtraHeaders: header.ExtraHeaders,
	}, nil
}

func validateUnprotectedHeader(header jose.Header) error {
	if header.Algorithm != "" ||
		header.KeyID != "" ||
		header.JSONWebKey != nil ||
		header.Nonce != "" {
		return fmt.Errorf(
			"%w: alg, kid, jwk, and nonce headers must be protected",
			ErrMalformedToken,
		)
	}

	for name := range header.ExtraHeaders {
		switch name {
		case jose.HeaderType,
			jose.HeaderContentType,
			headerCritical,
			headerBase64:
			return fmt.Errorf(
				"%w: %s header must be protected",
				ErrMalformedToken,
				name,
			)
		}
	}

	return nil
}

func validateExpectedHeaders(config config, header Header) error {
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

func headerString(header map[jose.HeaderKey]any, name jose.HeaderKey, maxLength int) (string, error) {
	value, exists := header[name]
	if !exists {
		return "", nil
	}

	text, ok := value.(string)
	if !ok {
		return "", fmt.Errorf("%w: %s header must be a string", ErrMalformedToken, name)
	}
	if err := validateHeaderText(name, text, maxLength); err != nil {
		return "", fmt.Errorf("%w: %w", ErrMalformedToken, err)
	}

	return text, nil
}
