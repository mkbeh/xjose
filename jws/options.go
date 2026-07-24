package jws

import (
	"fmt"
	"unicode/utf8"

	"github.com/go-jose/go-jose/v4"
)

const (
	// DefaultMaxTokenSize is the default maximum serialized JWS size.
	DefaultMaxTokenSize = 32 << 20

	// DefaultMaxPayloadSize is the default maximum payload size.
	DefaultMaxPayloadSize = 16 << 20

	// DefaultMaxSignatures is the default maximum signature count for JWS JSON.
	DefaultMaxSignatures = 16

	maxTypeLength        = 256
	maxContentTypeLength = 256
)

const (
	headerAlgorithm jose.HeaderKey = "alg"
	headerKeyID     jose.HeaderKey = "kid"
	headerCritical  jose.HeaderKey = "crit"
	headerBase64    jose.HeaderKey = "b64"
)

type config struct {
	typ string
	cty string

	maxTokenSize   int
	maxPayloadSize int
	maxSignatures  int

	extraHeaders    map[jose.HeaderKey]any
	customHeaderSet bool
	policy          SignaturePolicy
	policySet       bool
}

// Option configures JWS signers and verifiers.
type Option interface {
	apply(*config) error
}

type typeOption string

// WithType sets the protected typ header on signatures and requires the same
// value during verification.
func WithType(value string) Option {
	return typeOption(value)
}

func (option typeOption) apply(config *config) error {
	value := string(option)

	config.typ = value
	setHeader(
		config,
		jose.HeaderType,
		jose.ContentType(value),
	)

	return nil
}

type contentTypeOption string

// WithContentType sets the protected cty header on signatures and requires the
// same value during verification.
func WithContentType(value string) Option {
	return contentTypeOption(value)
}

func (option contentTypeOption) apply(config *config) error {
	value := string(option)

	config.cty = value
	setHeader(
		config,
		jose.HeaderContentType,
		jose.ContentType(value),
	)

	return nil
}

type maxTokenSizeOption int

// WithMaxTokenSize sets the maximum serialized JWS size in bytes.
func WithMaxTokenSize(size int) Option {
	return maxTokenSizeOption(size)
}

func (option maxTokenSizeOption) apply(config *config) error {
	if option <= 0 {
		return fmt.Errorf(
			"%w: maximum token size must be positive",
			ErrInvalidConfig,
		)
	}

	config.maxTokenSize = int(option)
	return nil
}

type maxPayloadSizeOption int

// WithMaxPayloadSize sets the maximum payload size in bytes.
func WithMaxPayloadSize(size int) Option {
	return maxPayloadSizeOption(size)
}

func (option maxPayloadSizeOption) apply(config *config) error {
	if option <= 0 {
		return fmt.Errorf(
			"%w: maximum payload size must be positive",
			ErrInvalidConfig,
		)
	}

	config.maxPayloadSize = int(option)
	return nil
}

type maxSignaturesOption int

// WithMaxSignatures sets the maximum number of signatures accepted or created
// by JWS JSON operations.
func WithMaxSignatures(count int) Option {
	return maxSignaturesOption(count)
}

func (option maxSignaturesOption) apply(config *config) error {
	if option <= 0 {
		return fmt.Errorf(
			"%w: maximum signature count must be positive",
			ErrInvalidConfig,
		)
	}

	config.maxSignatures = int(option)
	return nil
}

type headerOption struct {
	name  jose.HeaderKey
	value any
}

// WithHeader adds an arbitrary protected header to signatures.
//
// The value is passed directly to go-jose. When multiple options set the same
// header, the last applied option wins.
func WithHeader(name jose.HeaderKey, value any) Option {
	return headerOption{
		name:  name,
		value: value,
	}
}

func (option headerOption) apply(config *config) error {
	setHeader(config, option.name, option.value)
	config.customHeaderSet = true

	return nil
}

type signaturePolicyOption struct {
	policy SignaturePolicy
}

// WithSignaturePolicy sets the acceptance policy used by MultiVerifier.
//
// The default is RequireAnySignature, matching the acceptance semantics of
// go-jose VerifyMulti. This option is not valid for Signer, MultiSigner, or
// Verifier.
func WithSignaturePolicy(policy SignaturePolicy) Option {
	return signaturePolicyOption{policy: policy}
}

func (option signaturePolicyOption) apply(config *config) error {
	if option.policy == nil {
		return fmt.Errorf(
			"%w: signature policy is nil",
			ErrInvalidConfig,
		)
	}
	if validator, ok := option.policy.(policyValidator); ok {
		if err := validator.validate(); err != nil {
			return fmt.Errorf("%w: %w", ErrInvalidConfig, err)
		}
	}

	config.policy = option.policy
	config.policySet = true
	return nil
}

func makeConfig(options []Option) (config, error) {
	config := config{
		maxTokenSize:   DefaultMaxTokenSize,
		maxPayloadSize: DefaultMaxPayloadSize,
		maxSignatures:  DefaultMaxSignatures,
		policy:         RequireAnySignature(),
	}

	for index, option := range options {
		if option == nil {
			return config, fmt.Errorf(
				"%w: option %d is nil",
				ErrInvalidConfig,
				index,
			)
		}

		if err := option.apply(&config); err != nil {
			return config, err
		}
	}

	return config, nil
}

func (config config) signerOptions() *jose.SignerOptions {
	options := new(jose.SignerOptions)

	for name, value := range config.extraHeaders {
		options.WithHeader(name, value)
	}

	return options
}

func (config config) validateSigner() error {
	if config.policySet {
		return fmt.Errorf(
			"%w: WithSignaturePolicy is only supported by MultiVerifier",
			ErrInvalidConfig,
		)
	}
	return nil
}

func (config config) validateVerifier() error {
	if config.customHeaderSet {
		return fmt.Errorf(
			"%w: WithHeader is only supported by signers",
			ErrInvalidConfig,
		)
	}
	if config.policySet {
		return fmt.Errorf(
			"%w: WithSignaturePolicy is only supported by MultiVerifier",
			ErrInvalidConfig,
		)
	}
	return nil
}

func (config config) validateMultiVerifier() error {
	if config.customHeaderSet {
		return fmt.Errorf(
			"%w: WithHeader is only supported by signers",
			ErrInvalidConfig,
		)
	}
	if config.policy == nil {
		return fmt.Errorf(
			"%w: signature policy is required",
			ErrInvalidConfig,
		)
	}
	return nil
}

func validateHeaderText(name jose.HeaderKey, value string, maxLength int) error {
	if value == "" {
		return fmt.Errorf("%s header is empty", name)
	}
	if !utf8.ValidString(value) {
		return fmt.Errorf("%s header is not valid UTF-8", name)
	}
	if len(value) > maxLength {
		return fmt.Errorf(
			"%s header is %d bytes, limit is %d",
			name,
			len(value),
			maxLength,
		)
	}
	for _, character := range value {
		if character < 0x20 || character == 0x7f {
			return fmt.Errorf(
				"%s header contains a control character",
				name,
			)
		}
	}

	return nil
}

func setHeader(config *config, name jose.HeaderKey, value any) {
	if config.extraHeaders == nil {
		config.extraHeaders = make(map[jose.HeaderKey]any)
	}

	config.extraHeaders[name] = value
}
