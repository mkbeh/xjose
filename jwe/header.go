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

// Header contains the protected JOSE header parameters used by the decrypter.
type Header struct {
	Algorithm    jose.KeyAlgorithm
	Encryption   jose.ContentEncryption
	Compression  jose.CompressionAlgorithm
	KeyID        string
	Type         string
	ContentType  string
	ExtraHeaders map[jose.HeaderKey]any
}

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
