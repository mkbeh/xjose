package jwe

import (
	"fmt"
	"unicode"
	"unicode/utf8"

	"github.com/go-jose/go-jose/v4"
)

const (
	// DefaultMaxTokenSize is the default maximum compact JWE size accepted or
	// produced by this package.
	DefaultMaxTokenSize = 32 << 10

	// DefaultMaxPlaintextSize is the default maximum plaintext size accepted
	// before encryption or returned after decryption.
	DefaultMaxPlaintextSize = 16 << 10

	maxAlgorithmLength   = 64
	maxTypeLength        = 128
	maxContentTypeLength = 128
)

type Option interface {
	apply(*config) error
}

type config struct {
	typ         string
	cty         string
	compression jose.CompressionAlgorithm

	maxTokenSize     int
	maxPlaintextSize int

	extraHeaders map[jose.HeaderKey]any
}

type typeOption string

// WithType sets the typ protected header for encryption and requires the same
// value during decryption.
func WithType(value string) Option {
	return typeOption(value)
}

func (option typeOption) apply(config *config) error {
	value := string(option)

	if err := validateHeaderValue(headerType, value, maxTypeLength); err != nil {
		return fmt.Errorf(
			"%w: %w",
			ErrInvalidConfig,
			err,
		)
	}

	config.typ = value

	return nil
}

type contentTypeOption string

// WithContentType sets the cty protected header for encryption and requires
// the same value during decryption.
func WithContentType(value string) Option {
	return contentTypeOption(value)
}

func (option contentTypeOption) apply(config *config) error {
	value := string(option)

	if err := validateHeaderValue(headerContentType, value, maxContentTypeLength); err != nil {
		return fmt.Errorf(
			"%w: %w",
			ErrInvalidConfig,
			err,
		)
	}

	config.cty = value

	return nil
}

type compressionOption jose.CompressionAlgorithm

// WithCompression configures plaintext compression.
//
// Compression is disabled by default. Use jose.NONE to disable it explicitly.
func WithCompression(algorithm jose.CompressionAlgorithm) Option {
	return compressionOption(algorithm)
}

func (option compressionOption) apply(config *config) error {
	config.compression = jose.CompressionAlgorithm(option)

	return nil
}

type maxTokenSizeOption int

// WithMaxTokenSize sets the maximum compact JWE size accepted or produced.
func WithMaxTokenSize(size int) Option {
	return maxTokenSizeOption(size)
}

func (option maxTokenSizeOption) apply(config *config) error {
	size := int(option)

	if size <= 0 {
		return fmt.Errorf(
			"%w: maximum token size must be positive",
			ErrInvalidConfig,
		)
	}

	config.maxTokenSize = size

	return nil
}

type maxPlaintextSizeOption int

// WithMaxPlaintextSize sets the maximum plaintext size accepted before
// encryption or returned after decryption.
func WithMaxPlaintextSize(size int) Option {
	return maxPlaintextSizeOption(size)
}

func (option maxPlaintextSizeOption) apply(config *config) error {
	size := int(option)

	if size <= 0 {
		return fmt.Errorf(
			"%w: maximum plaintext size must be positive",
			ErrInvalidConfig,
		)
	}

	config.maxPlaintextSize = size

	return nil
}

type headerOption struct {
	name  jose.HeaderKey
	value any
}

// WithHeader adds an arbitrary value to the protected JWE header.
//
// The caller is responsible for avoiding incompatible or conflicting JOSE
// header parameters.
func WithHeader(name jose.HeaderKey, value any) Option {
	return headerOption{
		name:  name,
		value: value,
	}
}

func (option headerOption) apply(config *config) error {
	if config.extraHeaders == nil {
		config.extraHeaders = make(map[jose.HeaderKey]any)
	}

	config.extraHeaders[option.name] = option.value

	return nil
}

func makeConfig(options []Option) (config, error) {
	config := config{
		compression:      jose.NONE,
		maxTokenSize:     DefaultMaxTokenSize,
		maxPlaintextSize: DefaultMaxPlaintextSize,
	}

	for _, option := range options {
		if option == nil {
			return config, fmt.Errorf(
				"%w: option is nil",
				ErrInvalidConfig,
			)
		}

		if err := option.apply(&config); err != nil {
			return config, err
		}
	}

	return config, nil
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
