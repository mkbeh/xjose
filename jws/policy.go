package jws

import (
	"errors"
	"fmt"
)

// SignaturePolicy decides whether independently verified signatures satisfy
// the application's acceptance requirements.
//
// JWS defines how signatures are represented and verified but leaves the
// required set of successful signatures to the application. MultiVerifier
// always enforces that at least one signature is cryptographically valid,
// even when a custom policy returns nil.
type SignaturePolicy interface {
	Evaluate(results []SignatureResult) error
}

// SignaturePolicyFunc adapts a function to SignaturePolicy.
type SignaturePolicyFunc func(results []SignatureResult) error

// Evaluate calls policy(results).
func (policy SignaturePolicyFunc) Evaluate(results []SignatureResult) error {
	if policy == nil {
		return errors.New("signature policy function is nil")
	}

	return policy(results)
}

func (policy SignaturePolicyFunc) validate() error {
	if policy == nil {
		return errors.New("signature policy function is nil")
	}

	return nil
}

// RequireAnySignature accepts a JWS when at least one provided signature is
// valid with a trusted verification key. This is the default policy and
// matches the acceptance semantics of go-jose VerifyMulti.
func RequireAnySignature() SignaturePolicy {
	return requireAnyPolicy{}
}

// RequireAllProvidedSignatures accepts a JWS only when every signature present
// in the object is valid with a trusted verification key.
//
// This policy does not require any particular signer identity. Use
// RequireKeyIDs or RequireThreshold for identity-based approval rules.
func RequireAllProvidedSignatures() SignaturePolicy {
	return requireAllProvidedPolicy{}
}

// RequireKeyIDs accepts a JWS only when each listed trusted key identity has a
// valid signature. Additional signatures do not affect the decision.
//
// Key identities are taken from ResolvedKey.KeyID, not directly from the JWS
// kid header.
func RequireKeyIDs(keyIDs ...string) SignaturePolicy {
	return &requiredKeyIDsPolicy{
		keyIDs: append([]string(nil), keyIDs...),
	}
}

// RequireThreshold accepts a JWS when at least minimum unique trusted key
// identities from keyIDs have valid signatures.
//
// This is an application-level quorum over independent JWS signatures, not a
// cryptographic threshold-signature scheme.
func RequireThreshold(minimum int, keyIDs ...string) SignaturePolicy {
	return &thresholdPolicy{
		minimum: minimum,
		keyIDs:  append([]string(nil), keyIDs...),
	}
}

// AllOf accepts a JWS only when every nested policy accepts it.
func AllOf(policies ...SignaturePolicy) SignaturePolicy {
	return &allOfPolicy{
		policies: append([]SignaturePolicy(nil), policies...),
	}
}

type policyValidator interface {
	validate() error
}

type requireAnyPolicy struct{}

func (requireAnyPolicy) Evaluate(results []SignatureResult) error {
	for _, result := range results {
		if result.Valid() {
			return nil
		}
	}

	return errors.New("no signature was successfully verified")
}

type requireAllProvidedPolicy struct{}

func (requireAllProvidedPolicy) Evaluate(results []SignatureResult) error {
	if len(results) == 0 {
		return errors.New("JWS contains no signatures")
	}

	for _, result := range results {
		if !result.Valid() {
			return fmt.Errorf(
				"signature %d is not valid: %w",
				result.Index,
				result.Err,
			)
		}
	}

	return nil
}

type requiredKeyIDsPolicy struct {
	keyIDs []string
}

func (policy *requiredKeyIDsPolicy) validate() error {
	return validatePolicyKeyIDs(policy.keyIDs)
}

func (policy *requiredKeyIDsPolicy) Evaluate(results []SignatureResult) error {
	valid := validKeyIDs(results)

	for _, keyID := range policy.keyIDs {
		if _, exists := valid[keyID]; !exists {
			return fmt.Errorf(
				"required key ID %q has no valid signature",
				keyID,
			)
		}
	}

	return nil
}

type thresholdPolicy struct {
	minimum int
	keyIDs  []string
}

func (policy *thresholdPolicy) validate() error {
	if err := validatePolicyKeyIDs(policy.keyIDs); err != nil {
		return err
	}

	if policy.minimum <= 0 {
		return errors.New("threshold must be positive")
	}

	if policy.minimum > len(policy.keyIDs) {
		return fmt.Errorf(
			"threshold %d exceeds key count %d",
			policy.minimum,
			len(policy.keyIDs),
		)
	}

	return nil
}

func (policy *thresholdPolicy) Evaluate(results []SignatureResult) error {
	if err := policy.validate(); err != nil {
		return err
	}

	valid := validKeyIDs(results)
	verified := 0

	for _, keyID := range policy.keyIDs {
		if _, exists := valid[keyID]; !exists {
			continue
		}

		verified++

		if verified == policy.minimum {
			return nil
		}
	}

	return fmt.Errorf(
		"verified %d unique trusted key IDs, require %d",
		verified,
		policy.minimum,
	)
}

type allOfPolicy struct {
	policies []SignaturePolicy
}

func (policy *allOfPolicy) validate() error {
	if len(policy.policies) == 0 {
		return errors.New("AllOf requires at least one policy")
	}

	for index, nested := range policy.policies {
		if nested == nil {
			return fmt.Errorf("AllOf policy %d is nil", index)
		}

		validator, ok := nested.(policyValidator)
		if !ok {
			continue
		}

		if err := validator.validate(); err != nil {
			return fmt.Errorf(
				"AllOf policy %d: %w",
				index,
				err,
			)
		}
	}

	return nil
}

func (policy *allOfPolicy) Evaluate(results []SignatureResult) error {
	if err := policy.validate(); err != nil {
		return err
	}

	for index, nested := range policy.policies {
		if err := nested.Evaluate(results); err != nil {
			return fmt.Errorf(
				"policy %d: %w",
				index,
				err,
			)
		}
	}

	return nil
}

func validatePolicyKeyIDs(keyIDs []string) error {
	if len(keyIDs) == 0 {
		return errors.New("at least one key ID is required")
	}

	seen := make(
		map[string]struct{},
		len(keyIDs),
	)

	for index, keyID := range keyIDs {
		if err := validateHeaderValue(headerKeyID, keyID, maxKeyIDLength); err != nil {
			return fmt.Errorf("key ID %d: %w", index, err)
		}

		if _, exists := seen[keyID]; exists {
			return fmt.Errorf("duplicate key ID %q", keyID)
		}

		seen[keyID] = struct{}{}
	}

	return nil
}

func validKeyIDs(results []SignatureResult) map[string]struct{} {
	valid := make(
		map[string]struct{},
		len(results),
	)

	for _, result := range results {
		if result.Valid() && result.KeyID != "" {
			valid[result.KeyID] = struct{}{}
		}
	}

	return valid
}
