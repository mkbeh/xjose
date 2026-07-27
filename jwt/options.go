package jwt

import (
	"fmt"
	"slices"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// SignerOption configures Signer.
type SignerOption interface {
	applySigner(*signerConfig) error
}

// VerifierOption configures Verifier.
type VerifierOption interface {
	applyVerifier(*verifierConfig) error
}

// Option configures both Signer and Verifier.
type Option interface {
	SignerOption
	VerifierOption
}

type signerConfig struct {
	typ     string
	maxSize int
}

type audienceMode uint8

const (
	audienceAny audienceMode = iota
	audienceAll
)

type verifierConfig struct {
	methods []jwt.SigningMethod

	issuer       string
	audiences    []string
	audienceMode audienceMode
	subject      string
	leeway       time.Duration
	clock        func() time.Time

	typ string

	maxSize     int
	maxLifetime time.Duration
	maxAge      time.Duration

	requireExp  bool
	requireNBF  bool
	validateIAT bool
	requireIAT  bool
}

func (config verifierConfig) parserOptions() []jwt.ParserOption {
	methods := make([]string, len(config.methods))

	for index, method := range config.methods {
		methods[index] = method.Alg()
	}

	options := []jwt.ParserOption{
		jwt.WithValidMethods(methods),
		jwt.WithStrictDecoding(),
		jwt.WithTimeFunc(config.clock),
	}

	if config.requireExp {
		options = append(
			options,
			jwt.WithExpirationRequired(),
		)
	}

	if config.requireNBF {
		options = append(
			options,
			jwt.WithNotBeforeRequired(),
		)
	}

	if config.validateIAT {
		options = append(
			options,
			jwt.WithIssuedAt(),
		)
	}

	if config.issuer != "" {
		options = append(
			options,
			jwt.WithIssuer(config.issuer),
		)
	}

	if len(config.audiences) != 0 {
		if config.audienceMode == audienceAll {
			options = append(
				options,
				jwt.WithAllAudiences(
					config.audiences...,
				),
			)
		} else {
			options = append(
				options,
				jwt.WithAudience(
					config.audiences...,
				),
			)
		}
	}

	if config.subject != "" {
		options = append(
			options,
			jwt.WithSubject(config.subject),
		)
	}

	if config.leeway != 0 {
		options = append(
			options,
			jwt.WithLeeway(config.leeway),
		)
	}

	return options
}

type typeOption string

// WithType sets typ when signing and requires the same typ when verifying.
func WithType(value string) Option {
	return typeOption(value)
}

func (option typeOption) applySigner(config *signerConfig) error {
	value := string(option)

	if err := validateHeaderValue(headerParamType, value, maxTypeLength); err != nil {
		return fmt.Errorf("%w: %w", ErrInvalidConfig, err)
	}

	config.typ = value

	return nil
}

func (option typeOption) applyVerifier(config *verifierConfig) error {
	value := string(option)

	if err := validateHeaderValue(headerParamType, value, maxTypeLength); err != nil {
		return fmt.Errorf("%w: %w", ErrInvalidConfig, err)
	}

	config.typ = value

	return nil
}

type maxTokenSizeOption int

// WithMaxTokenSize changes the maximum compact JWT size accepted or produced.
func WithMaxTokenSize(size int) Option {
	return maxTokenSizeOption(size)
}

func (option maxTokenSizeOption) applySigner(config *signerConfig) error {
	if option <= 0 {
		return fmt.Errorf("%w: max token size must be positive", ErrInvalidConfig)
	}

	config.maxSize = int(option)

	return nil
}

func (option maxTokenSizeOption) applyVerifier(config *verifierConfig) error {
	if option <= 0 {
		return fmt.Errorf("%w: max token size must be positive", ErrInvalidConfig)
	}

	config.maxSize = int(option)

	return nil
}

type methodsOption []jwt.SigningMethod

// WithMethods sets the only signing methods accepted by Verifier.
func WithMethods(methods ...jwt.SigningMethod) VerifierOption {
	return methodsOption(append([]jwt.SigningMethod(nil), methods...))
}

func (option methodsOption) applyVerifier(config *verifierConfig) error {
	if len(option) == 0 {
		return fmt.Errorf("%w: at least one signing method is required", ErrInvalidConfig)
	}

	seen := make(map[string]struct{}, len(option))
	methods := make([]jwt.SigningMethod, 0, len(option))

	for _, method := range option {
		if method == nil || method.Alg() == "" {
			return fmt.Errorf("%w: invalid signing method", ErrInvalidConfig)
		}
		if _, exists := seen[method.Alg()]; exists {
			return fmt.Errorf("%w: duplicate signing method %q", ErrInvalidConfig, method.Alg())
		}

		seen[method.Alg()] = struct{}{}
		methods = append(methods, method)
	}

	config.methods = methods

	return nil
}

type issuerOption string

// WithIssuer requires an exact iss claim.
func WithIssuer(issuer string) VerifierOption {
	return issuerOption(issuer)
}

func (option issuerOption) applyVerifier(config *verifierConfig) error {
	if option == "" {
		return fmt.Errorf("%w: issuer is empty", ErrInvalidConfig)
	}

	config.issuer = string(option)

	return nil
}

type audienceOption struct {
	values []string
	mode   audienceMode
}

// WithAudience requires at least one of the supplied audiences.
func WithAudience(audiences ...string) VerifierOption {
	return audienceOption{
		values: append([]string(nil), audiences...),
		mode:   audienceAny,
	}
}

// WithAllAudiences requires every supplied audience.
func WithAllAudiences(audiences ...string) VerifierOption {
	return audienceOption{
		values: append([]string(nil), audiences...),
		mode:   audienceAll,
	}
}

func (option audienceOption) applyVerifier(config *verifierConfig) error {
	if len(option.values) == 0 {
		return fmt.Errorf(
			"%w: at least one audience is required",
			ErrInvalidConfig,
		)
	}

	for _, value := range option.values {
		if value == "" {
			return fmt.Errorf(
				"%w: audience must not be empty",
				ErrInvalidConfig,
			)
		}
	}

	config.audiences = slices.Clone(option.values)
	config.audienceMode = option.mode

	return nil
}

type subjectOption string

// WithSubject requires an exact sub claim.
func WithSubject(subject string) VerifierOption {
	return subjectOption(subject)
}

func (option subjectOption) applyVerifier(config *verifierConfig) error {
	if option == "" {
		return fmt.Errorf("%w: subject is empty", ErrInvalidConfig)
	}

	config.subject = string(option)

	return nil
}

type leewayOption time.Duration

// WithLeeway allows the given clock-skew window for time-based claims.
func WithLeeway(leeway time.Duration) VerifierOption {
	return leewayOption(leeway)
}

func (option leewayOption) applyVerifier(config *verifierConfig) error {
	if option < 0 {
		return fmt.Errorf("%w: leeway must not be negative", ErrInvalidConfig)
	}

	config.leeway = time.Duration(option)

	return nil
}

type clockOption struct {
	clock func() time.Time
}

// WithClock replaces the clock used by registered-claim and lifetime validation.
func WithClock(clock func() time.Time) VerifierOption {
	return clockOption{clock: clock}
}

func (option clockOption) applyVerifier(config *verifierConfig) error {
	if option.clock == nil {
		return fmt.Errorf("%w: clock is nil", ErrInvalidConfig)
	}

	config.clock = option.clock

	return nil
}

type requireExpirationOption struct{}

// RequireExpiration requires exp. This is already the secure default.
func RequireExpiration() VerifierOption {
	return requireExpirationOption{}
}

func (requireExpirationOption) applyVerifier(config *verifierConfig) error {
	config.requireExp = true

	return nil
}

type allowMissingExpirationOption struct{}

// AllowMissingExpiration disables the secure default requiring exp.
func AllowMissingExpiration() VerifierOption {
	return allowMissingExpirationOption{}
}

func (allowMissingExpirationOption) applyVerifier(config *verifierConfig) error {
	config.requireExp = false

	return nil
}

type requireNotBeforeOption struct{}

// RequireNotBefore requires nbf in addition to validating it.
func RequireNotBefore() VerifierOption {
	return requireNotBeforeOption{}
}

func (requireNotBeforeOption) applyVerifier(config *verifierConfig) error {
	config.requireNBF = true

	return nil
}

type validateIssuedAtOption struct{}

// ValidateIssuedAt validates iat when it is present.
func ValidateIssuedAt() VerifierOption {
	return validateIssuedAtOption{}
}

func (validateIssuedAtOption) applyVerifier(config *verifierConfig) error {
	config.validateIAT = true

	return nil
}

type requireIssuedAtOption struct{}

// RequireIssuedAt requires iat and validates it.
func RequireIssuedAt() VerifierOption {
	return requireIssuedAtOption{}
}

func (requireIssuedAtOption) applyVerifier(config *verifierConfig) error {
	config.validateIAT = true
	config.requireIAT = true

	return nil
}

type maxLifetimeOption time.Duration

// WithMaxLifetime limits exp-iat when both claims are present.
func WithMaxLifetime(lifetime time.Duration) VerifierOption {
	return maxLifetimeOption(lifetime)
}

func (option maxLifetimeOption) applyVerifier(config *verifierConfig) error {
	if option <= 0 {
		return fmt.Errorf("%w: max lifetime must be positive", ErrInvalidConfig)
	}

	config.maxLifetime = time.Duration(option)

	return nil
}

type maxTokenAgeOption time.Duration

// WithMaxTokenAge limits now-iat when iat is present.
func WithMaxTokenAge(age time.Duration) VerifierOption {
	return maxTokenAgeOption(age)
}

func (option maxTokenAgeOption) applyVerifier(config *verifierConfig) error {
	if option <= 0 {
		return fmt.Errorf("%w: max token age must be positive", ErrInvalidConfig)
	}

	config.maxAge = time.Duration(option)

	return nil
}
