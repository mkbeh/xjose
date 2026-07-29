package jwe

import (
	"fmt"
	"unicode/utf8"

	"github.com/go-jose/go-jose/v4"
)

const (
	maxAlgorithmLength   = 64
	maxTypeLength        = 128
	maxContentTypeLength = 128

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

func (header Header) validate() error {
	check := func(name jose.HeaderKey, value string, maxLength int) error {
		if err := validateHeaderValue(name, value, maxLength); err != nil {
			return fmt.Errorf("%w: %w", ErrMalformedToken, err)
		}
		return nil
	}

	// Encryption is required for every JWE serialization.
	if header.Encryption == "" {
		return fmt.Errorf(
			"%w: %s header is required",
			ErrMalformedToken,
			headerEncryption,
		)
	}

	if err := check(headerEncryption, string(header.Encryption), maxAlgorithmLength); err != nil {
		return err
	}

	// Algorithm may be absent from a shared multi-recipient header.
	if header.Algorithm != "" {
		if err := check(headerAlgorithm, string(header.Algorithm), maxAlgorithmLength); err != nil {
			return err
		}
	}

	// Optional application metadata is validated when present.
	if header.Type != "" {
		if err := check(headerType, header.Type, maxTypeLength); err != nil {
			return err
		}
	}

	if header.ContentType != "" {
		if err := check(headerContentType, header.ContentType, maxContentTypeLength); err != nil {
			return err
		}
	}

	// Compression is optional and jose.NONE represents its absence.
	if header.Compression != jose.NONE {
		if err := check(headerCompression, string(header.Compression), maxAlgorithmLength); err != nil {
			return err
		}
	}

	return nil
}

// parseHeader converts a go-jose header into Header and validates the
// structurally supported parameter subset.
func parseHeader(source jose.Header) (Header, error) {
	if _, exists := source.ExtraHeaders[headerCritical]; exists {
		return Header{}, fmt.Errorf(
			"%w: critical headers are not supported",
			ErrMalformedToken,
		)
	}

	encryption, err := headerString(source.ExtraHeaders, headerEncryption)
	if err != nil {
		return Header{}, err
	}
	typ, err := headerString(source.ExtraHeaders, jose.HeaderType)
	if err != nil {
		return Header{}, err
	}
	contentType, err := headerString(source.ExtraHeaders, jose.HeaderContentType)
	if err != nil {
		return Header{}, err
	}
	compression, err := headerString(source.ExtraHeaders, headerCompression)
	if err != nil {
		return Header{}, err
	}

	header := Header{
		Algorithm:    jose.KeyAlgorithm(source.Algorithm),
		Encryption:   jose.ContentEncryption(encryption),
		Compression:  jose.CompressionAlgorithm(compression),
		KeyID:        source.KeyID,
		Type:         typ,
		ContentType:  contentType,
		ExtraHeaders: cloneExtraHeaders(source.ExtraHeaders),
	}

	if header.Algorithm == "" {
		return Header{}, fmt.Errorf(
			"%w: %s header is required",
			ErrMalformedToken,
			headerAlgorithm,
		)
	}

	if err := header.validate(); err != nil {
		return Header{}, err
	}

	return header, nil
}

// parseMultiSharedHeader allows alg and kid to be absent because they normally
// live in the per-recipient header and are unavailable before DecryptMulti.
func parseMultiSharedHeader(source jose.Header) (Header, error) {
	if _, exists := source.ExtraHeaders[headerCritical]; exists {
		return Header{}, fmt.Errorf(
			"%w: critical headers are not supported",
			ErrMalformedToken,
		)
	}

	encryption, err := headerString(source.ExtraHeaders, headerEncryption)
	if err != nil {
		return Header{}, err
	}
	typ, err := headerString(source.ExtraHeaders, jose.HeaderType)
	if err != nil {
		return Header{}, err
	}
	contentType, err := headerString(source.ExtraHeaders, jose.HeaderContentType)
	if err != nil {
		return Header{}, err
	}
	compression, err := headerString(source.ExtraHeaders, headerCompression)
	if err != nil {
		return Header{}, err
	}

	header := Header{
		Algorithm:    jose.KeyAlgorithm(source.Algorithm),
		Encryption:   jose.ContentEncryption(encryption),
		Compression:  jose.CompressionAlgorithm(compression),
		KeyID:        source.KeyID,
		Type:         typ,
		ContentType:  contentType,
		ExtraHeaders: cloneExtraHeaders(source.ExtraHeaders),
	}

	if err := header.validate(); err != nil {
		return Header{}, err
	}

	return header, nil
}

func headerString(
	header map[jose.HeaderKey]any,
	name jose.HeaderKey,
) (string, error) {
	value, exists := header[name]
	if !exists {
		return "", nil
	}

	text, ok := value.(string)
	if !ok {
		return "", fmt.Errorf(
			"%w: %s must be a string",
			ErrMalformedToken,
			name,
		)
	}

	return text, nil
}

func validateHeaderValue(name jose.HeaderKey, value string, maxLength int) error {
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

	return nil
}

func cloneExtraHeaders(headers map[jose.HeaderKey]any) map[jose.HeaderKey]any {
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
