package xjwt

import (
	"fmt"
	"time"
	"unicode"
	"unicode/utf8"

	jwtv5 "github.com/golang-jwt/jwt/v5"
)

// SignerOption configures Signer.
type SignerOption interface{ applySigner(*signerConfig) error }

// VerifierOption configures Verifier.
type VerifierOption interface{ applyVerifier(*verifierConfig) error }

// Option configures both Signer and Verifier.
type Option interface {
	SignerOption
	VerifierOption
}

type signerConfig struct {
	tokenType   string
	includeType bool
	contentType string
	maxSize     int
}

type verifierConfig struct {
	algorithms          []Algorithm
	expectedType        string
	expectedContentType string
	issuer              string
	audiences           []string
	requireAllAudiences bool
	subject             string
	leeway              time.Duration
	clock               func() time.Time
	maxSize             int
	requireExp          bool
	requireNbf          bool
	validateIat         bool
	requireIat          bool
	maxLifetime         time.Duration
	maxTokenAge         time.Duration
	requiredClaims      []string
}

type typeOption string

// WithType makes a Signer emit typ and makes a Verifier require the same exact
// typ value.
func WithType(value string) Option { return typeOption(value) }
func (o typeOption) applySigner(config *signerConfig) error {
	if err := validateHeaderValue("typ", string(o), maxTypeLength); err != nil {
		return fmt.Errorf("%w: %w", ErrInvalidConfig, err)
	}
	config.tokenType, config.includeType = string(o), true
	return nil
}
func (o typeOption) applyVerifier(config *verifierConfig) error {
	if err := validateHeaderValue("typ", string(o), maxTypeLength); err != nil {
		return fmt.Errorf("%w: %w", ErrInvalidConfig, err)
	}
	config.expectedType = string(o)
	return nil
}

type withoutTypeOption struct{}

// WithoutType disables the default typ=JWT header emitted by Signer.
func WithoutType() SignerOption { return withoutTypeOption{} }
func (withoutTypeOption) applySigner(config *signerConfig) error {
	config.tokenType, config.includeType = "", false
	return nil
}

type contentTypeOption string

// WithContentType makes a Signer emit cty and makes a Verifier require the same
// exact cty value.
func WithContentType(value string) Option { return contentTypeOption(value) }
func (o contentTypeOption) applySigner(config *signerConfig) error {
	if err := validateHeaderValue("cty", string(o), maxContentTypeLength); err != nil {
		return fmt.Errorf("%w: %w", ErrInvalidConfig, err)
	}
	config.contentType = string(o)
	return nil
}
func (o contentTypeOption) applyVerifier(config *verifierConfig) error {
	if err := validateHeaderValue("cty", string(o), maxContentTypeLength); err != nil {
		return fmt.Errorf("%w: %w", ErrInvalidConfig, err)
	}
	config.expectedContentType = string(o)
	return nil
}

type maxTokenSizeOption int

// WithMaxTokenSize configures the maximum compact JWT size for a Signer or
// Verifier.
func WithMaxTokenSize(size int) Option { return maxTokenSizeOption(size) }
func (o maxTokenSizeOption) applySigner(config *signerConfig) error {
	if o <= 0 {
		return fmt.Errorf("%w: maximum token size must be positive", ErrInvalidConfig)
	}
	config.maxSize = int(o)
	return nil
}
func (o maxTokenSizeOption) applyVerifier(config *verifierConfig) error {
	if o <= 0 {
		return fmt.Errorf("%w: maximum token size must be positive", ErrInvalidConfig)
	}
	config.maxSize = int(o)
	return nil
}

type algorithmsOption []Algorithm

// WithAlgorithms configures the verifier algorithm allowlist. This option is
// mandatory.
func WithAlgorithms(algorithms ...Algorithm) VerifierOption {
	return algorithmsOption(append([]Algorithm(nil), algorithms...))
}
func (o algorithmsOption) applyVerifier(config *verifierConfig) error {
	if len(o) == 0 {
		return fmt.Errorf("%w: at least one algorithm is required", ErrInvalidConfig)
	}
	seen := make(map[Algorithm]struct{}, len(o))
	algorithms := make([]Algorithm, 0, len(o))
	for _, algorithm := range o {
		if _, err := algorithm.spec(); err != nil {
			return fmt.Errorf("%w: %w", ErrInvalidConfig, err)
		}
		if _, exists := seen[algorithm]; exists {
			continue
		}
		seen[algorithm] = struct{}{}
		algorithms = append(algorithms, algorithm)
	}
	config.algorithms = algorithms
	return nil
}

type issuerOption string

// WithIssuer requires the exact iss claim.
func WithIssuer(issuer string) VerifierOption { return issuerOption(issuer) }
func (o issuerOption) applyVerifier(config *verifierConfig) error {
	if err := validateClaimString("issuer", string(o)); err != nil {
		return err
	}
	config.issuer = string(o)
	return nil
}

type audienceOption struct {
	values     []string
	requireAll bool
}

// WithAudience requires at least one configured audience in aud.
func WithAudience(audiences ...string) VerifierOption {
	return audienceOption{values: append([]string(nil), audiences...)}
}

// WithAllAudiences requires all configured audiences in aud.
func WithAllAudiences(audiences ...string) VerifierOption {
	return audienceOption{values: append([]string(nil), audiences...), requireAll: true}
}
func (o audienceOption) applyVerifier(config *verifierConfig) error {
	if len(o.values) == 0 {
		return fmt.Errorf("%w: at least one audience is required", ErrInvalidConfig)
	}
	for _, audience := range o.values {
		if err := validateClaimString("audience", audience); err != nil {
			return err
		}
	}
	config.audiences = append([]string(nil), o.values...)
	config.requireAllAudiences = o.requireAll
	return nil
}

type subjectOption string

// WithSubject requires the exact sub claim.
func WithSubject(subject string) VerifierOption { return subjectOption(subject) }
func (o subjectOption) applyVerifier(config *verifierConfig) error {
	if err := validateClaimString("subject", string(o)); err != nil {
		return err
	}
	config.subject = string(o)
	return nil
}

type leewayOption time.Duration

// WithLeeway configures clock-skew tolerance.
func WithLeeway(leeway time.Duration) VerifierOption { return leewayOption(leeway) }
func (o leewayOption) applyVerifier(config *verifierConfig) error {
	if o < 0 {
		return fmt.Errorf("%w: leeway must not be negative", ErrInvalidConfig)
	}
	config.leeway = time.Duration(o)
	return nil
}

type clockOption struct{ clock func() time.Time }

// WithClock configures the verifier clock.
func WithClock(clock func() time.Time) VerifierOption { return clockOption{clock: clock} }
func (o clockOption) applyVerifier(config *verifierConfig) error {
	if o.clock == nil {
		return fmt.Errorf("%w: clock is nil", ErrInvalidConfig)
	}
	config.clock = o.clock
	return nil
}

type expirationOption bool

// RequireExpiration requires exp. This is the default.
func RequireExpiration() VerifierOption { return expirationOption(true) }

// AllowMissingExpiration permits tokens without exp.
func AllowMissingExpiration() VerifierOption { return expirationOption(false) }
func (o expirationOption) applyVerifier(config *verifierConfig) error {
	config.requireExp = bool(o)
	return nil
}

type requireNotBeforeOption struct{}

// RequireNotBefore requires nbf in addition to validating it.
func RequireNotBefore() VerifierOption { return requireNotBeforeOption{} }
func (requireNotBeforeOption) applyVerifier(config *verifierConfig) error {
	config.requireNbf = true
	return nil
}

type issuedAtOption struct{ require bool }

// ValidateIssuedAt validates iat when present.
func ValidateIssuedAt() VerifierOption { return issuedAtOption{} }

// RequireIssuedAt requires iat and validates that it is not in the future.
func RequireIssuedAt() VerifierOption { return issuedAtOption{require: true} }
func (o issuedAtOption) applyVerifier(config *verifierConfig) error {
	config.validateIat = true
	if o.require {
		config.requireIat = true
	}
	return nil
}

type maxLifetimeOption time.Duration

// WithMaxLifetime requires exp and iat and limits exp-iat.
func WithMaxLifetime(lifetime time.Duration) VerifierOption { return maxLifetimeOption(lifetime) }
func (o maxLifetimeOption) applyVerifier(config *verifierConfig) error {
	if o <= 0 {
		return fmt.Errorf("%w: maximum lifetime must be positive", ErrInvalidConfig)
	}
	config.maxLifetime = time.Duration(o)
	config.requireExp, config.validateIat, config.requireIat = true, true, true
	return nil
}

type maxTokenAgeOption time.Duration

// WithMaxTokenAge requires iat and limits token age independently of exp.
func WithMaxTokenAge(age time.Duration) VerifierOption { return maxTokenAgeOption(age) }
func (o maxTokenAgeOption) applyVerifier(config *verifierConfig) error {
	if o <= 0 {
		return fmt.Errorf("%w: maximum token age must be positive", ErrInvalidConfig)
	}
	config.maxTokenAge = time.Duration(o)
	config.validateIat, config.requireIat = true, true
	return nil
}

type requiredClaimsOption []string

// WithRequiredClaims requires the listed top-level claim names to be present
// and non-null.
func WithRequiredClaims(names ...string) VerifierOption {
	return requiredClaimsOption(append([]string(nil), names...))
}
func (o requiredClaimsOption) applyVerifier(config *verifierConfig) error {
	if len(o) == 0 {
		return fmt.Errorf("%w: at least one required claim is needed", ErrInvalidConfig)
	}
	seen := make(map[string]struct{}, len(o))
	claims := make([]string, 0, len(o))
	for _, name := range o {
		if err := validateClaimName(name); err != nil {
			return err
		}
		if _, exists := seen[name]; exists {
			continue
		}
		seen[name] = struct{}{}
		claims = append(claims, name)
	}
	config.requiredClaims = claims
	return nil
}

func validatorOptions(config verifierConfig) []jwtv5.ParserOption {
	options := []jwtv5.ParserOption{jwtv5.WithTimeFunc(config.clock)}
	if config.leeway != 0 {
		options = append(options, jwtv5.WithLeeway(config.leeway))
	}
	if config.requireExp {
		options = append(options, jwtv5.WithExpirationRequired())
	}
	if config.requireNbf {
		options = append(options, jwtv5.WithNotBeforeRequired())
	}
	if config.validateIat {
		options = append(options, jwtv5.WithIssuedAt())
	}
	if config.issuer != "" {
		options = append(options, jwtv5.WithIssuer(config.issuer))
	}
	if len(config.audiences) != 0 {
		if config.requireAllAudiences {
			options = append(options, jwtv5.WithAllAudiences(config.audiences...))
		} else {
			options = append(options, jwtv5.WithAudience(config.audiences...))
		}
	}
	if config.subject != "" {
		options = append(options, jwtv5.WithSubject(config.subject))
	}
	return options
}

func validateClaimString(name, value string) error {
	if value == "" || !utf8.ValidString(value) {
		return fmt.Errorf("%w: %s must be a non-empty UTF-8 string", ErrInvalidConfig, name)
	}
	for _, r := range value {
		if unicode.IsControl(r) {
			return fmt.Errorf("%w: %s must not contain control characters", ErrInvalidConfig, name)
		}
	}
	return nil
}

func validateClaimName(name string) error {
	if len(name) > 256 {
		return fmt.Errorf("%w: claim name exceeds 256 bytes", ErrInvalidConfig)
	}
	return validateClaimString("claim name", name)
}
