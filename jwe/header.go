package jwe

import (
	"fmt"

	"github.com/go-jose/go-jose/v4"
)

const (
	headerAlgorithm   jose.HeaderKey = "alg"
	headerType        jose.HeaderKey = "typ"
	headerContentType jose.HeaderKey = "cty"
	headerEncryption  jose.HeaderKey = "enc"
	headerCompression jose.HeaderKey = "zip"
	headerCritical    jose.HeaderKey = "crit"
)

// Header is a normalized view of JOSE header parameters associated with a JWE.
//
// Header values passed to a KeyResolver must be treated as untrusted until
// decryption and authentication succeed. Compact JWE carries only a protected
// header. JWE JSON Serialization may also contribute shared and recipient-
// specific unprotected parameters, so callers must not assume every field in a
// merged Header is integrity protected.
type Header struct {
	// Algorithm is the key management algorithm from the alg parameter.
	Algorithm jose.KeyAlgorithm

	// Encryption is the content encryption algorithm from the enc parameter.
	Encryption jose.ContentEncryption

	// Compression is the plaintext compression algorithm from the zip
	// parameter. jose.NONE means that compression is not declared.
	Compression jose.CompressionAlgorithm

	// KeyID is the key identifier from the kid parameter.
	KeyID string

	// Type is the media type from the typ parameter.
	Type string

	// ContentType is the media type of the secured content from the cty
	// parameter.
	ContentType string

	// ExtraHeaders preserves the raw parameter map exposed by go-jose,
	// including custom parameters. The map is shallow-copied before it is
	// returned, but mutable values stored in it are not deep-copied.
	ExtraHeaders map[jose.HeaderKey]any
}

// parseHeader converts a go-jose header into Header and validates the
// structurally supported parameter subset.
func parseHeader(header jose.Header) (Header, error) {
	if _, exists := header.ExtraHeaders[headerCritical]; exists {
		return Header{}, fmt.Errorf(
			"%w: critical headers are not supported",
			ErrMalformedToken,
		)
	}

	if err := validateHeaderValue(
		headerAlgorithm,
		header.Algorithm,
		maxAlgorithmLength,
	); err != nil {
		return Header{}, fmt.Errorf(
			"%w: %w",
			ErrMalformedToken,
			err,
		)
	}

	encryption, err := headerString(
		header.ExtraHeaders,
		headerEncryption,
		true,
		maxAlgorithmLength,
	)
	if err != nil {
		return Header{}, err
	}

	typ, err := headerString(
		header.ExtraHeaders,
		jose.HeaderType,
		false,
		maxTypeLength,
	)
	if err != nil {
		return Header{}, err
	}

	contentType, err := headerString(
		header.ExtraHeaders,
		jose.HeaderContentType,
		false,
		maxContentTypeLength,
	)
	if err != nil {
		return Header{}, err
	}

	compression, err := headerString(
		header.ExtraHeaders,
		headerCompression,
		false,
		maxAlgorithmLength,
	)
	if err != nil {
		return Header{}, err
	}

	return Header{
		Algorithm:    jose.KeyAlgorithm(header.Algorithm),
		Encryption:   jose.ContentEncryption(encryption),
		Compression:  jose.CompressionAlgorithm(compression),
		KeyID:        header.KeyID,
		Type:         typ,
		ContentType:  contentType,
		ExtraHeaders: cloneExtraHeaders(header.ExtraHeaders),
	}, nil
}

func headerString(
	header map[jose.HeaderKey]any,
	name jose.HeaderKey,
	required bool,
	maxLength int,
) (string, error) {
	value, exists := header[name]
	if !exists {
		if required {
			return "", fmt.Errorf(
				"%w: %s header is required",
				ErrMalformedToken,
				name,
			)
		}

		return "", nil
	}

	text, ok := value.(string)
	if !ok {
		return "", fmt.Errorf(
			"%w: %s header must be a string",
			ErrMalformedToken,
			name,
		)
	}

	if err := validateHeaderValue(name, text, maxLength); err != nil {
		return "", fmt.Errorf(
			"%w: %w",
			ErrMalformedToken,
			err,
		)
	}

	return text, nil
}

func cloneExtraHeaders(
	headers map[jose.HeaderKey]any,
) map[jose.HeaderKey]any {
	if len(headers) == 0 {
		return nil
	}

	result := make(
		map[jose.HeaderKey]any,
		len(headers),
	)

	for name, value := range headers {
		result[name] = value
	}

	return result
}
