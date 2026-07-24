package jws

import (
	"context"
	"errors"
	"fmt"

	"github.com/go-jose/go-jose/v4"
)

// SignatureResult contains the verification result for one signature in JWS
// JSON Serialization.
type SignatureResult struct {
	Index  int
	KeyID  string
	Header Header
	Err    error
}

// Valid reports whether the signature was successfully verified.
func (result SignatureResult) Valid() bool {
	return result.Err == nil
}

// MultiVerified contains the shared payload and per-signature verification
// results after the configured policy has accepted the JWS.
type MultiVerified struct {
	Payload    []byte
	Signatures []SignatureResult
}

// MultiVerifier verifies Flattened or General JWS JSON Serialization.
//
// A MultiVerifier may be reused concurrently when its resolver and underlying
// verification-key implementations are safe for concurrent use. The zero value
// is invalid; use NewMultiVerifier or NewMultiVerifierWithResolver.
type MultiVerifier struct {
	resolver   KeyResolver
	algorithms []jose.SignatureAlgorithm
	config     config
}

// NewMultiVerifier creates a JWS JSON verifier backed by static key material.
func NewMultiVerifier(
	key any,
	algorithms []jose.SignatureAlgorithm,
	options ...Option,
) (*MultiVerifier, error) {
	resolver, err := newStaticResolver(key)
	if err != nil {
		return nil, err
	}

	return NewMultiVerifierWithResolver(
		resolver,
		algorithms,
		options...,
	)
}

// NewMultiVerifierWithResolver creates a JWS JSON verifier that resolves
// trusted key material independently for each protected signature header.
func NewMultiVerifierWithResolver(
	resolver KeyResolver,
	algorithms []jose.SignatureAlgorithm,
	options ...Option,
) (*MultiVerifier, error) {
	if resolver == nil {
		return nil, fmt.Errorf(
			"%w: key resolver is required",
			ErrInvalidConfig,
		)
	}

	if len(algorithms) == 0 {
		return nil, fmt.Errorf(
			"%w: at least one signature algorithm is required",
			ErrInvalidConfig,
		)
	}

	config, err := makeConfig(options)
	if err != nil {
		return nil, err
	}

	if err := config.validateMultiVerifier(); err != nil {
		return nil, err
	}

	return &MultiVerifier{
		resolver: resolver,
		algorithms: append(
			[]jose.SignatureAlgorithm(nil),
			algorithms...,
		),
		config: config,
	}, nil
}

// Verify verifies JWS JSON Serialization and returns its payload.
func (verifier *MultiVerifier) Verify(
	ctx context.Context,
	raw string,
) ([]byte, error) {
	verified, err := verifier.VerifyMessage(ctx, raw)
	if err != nil {
		return nil, err
	}

	return verified.Payload, nil
}

// VerifyMessage verifies Flattened or General JWS JSON Serialization and
// applies the configured signature policy.
func (verifier *MultiVerifier) VerifyMessage(
	ctx context.Context,
	raw string,
) (MultiVerified, error) {
	if err := validateRaw(raw, verifier.config.maxTokenSize); err != nil {
		return MultiVerified{}, err
	}

	object, err := jose.ParseSignedJSON(raw, verifier.algorithms)
	if err != nil {
		return MultiVerified{}, fmt.Errorf(
			"%w: parse JWS JSON: %w",
			ErrMalformedToken,
			err,
		)
	}

	payload := object.UnsafePayloadWithoutVerification()

	return verifier.verify(ctx, object, payload)
}

func (verifier *MultiVerifier) verify(
	ctx context.Context,
	object *jose.JSONWebSignature,
	payload []byte,
) (MultiVerified, error) {
	if err := validateSignatures(object, verifier.config.maxSignatures); err != nil {
		return MultiVerified{}, err
	}

	if err := validatePayloadSize(payload, verifier.config.maxPayloadSize); err != nil {
		return MultiVerified{}, err
	}

	results := make([]SignatureResult, 0, len(object.Signatures))

	hasValidSignature := false

	_, stopAfterFirstValid := verifier.config.policy.(requireAnyPolicy)

	for index, signature := range object.Signatures {
		if err := ctx.Err(); err != nil {
			return MultiVerified{}, err
		}

		result := SignatureResult{
			Index: index,
		}

		if err := validateUnprotectedHeader(signature.Unprotected); err != nil {
			result.Err = fmt.Errorf("signature %d: %w", index, err)
			results = append(results, result)
			continue
		}

		header, err := parseProtectedHeader(signature.Protected)
		if err != nil {
			result.Err = fmt.Errorf("signature %d: %w", index, err)
			results = append(results, result)
			continue
		}

		result.Header = header

		if err := validateExpectedHeaders(verifier.config, header); err != nil {
			result.Err = fmt.Errorf("signature %d: %w", index, err)
			results = append(results, result)
			continue
		}

		resolved, err := verifier.resolver.Resolve(ctx, header)
		if errors.Is(err, ErrKeyNotFound) {
			result.Err = fmt.Errorf("signature %d: %w", index, err)
			results = append(results, result)
			continue
		}

		if err != nil {
			return MultiVerified{}, fmt.Errorf("resolve key for signature %d: %w", index, err)
		}

		if resolved.Key == nil {
			return MultiVerified{}, fmt.Errorf("%w: resolver returned a nil key for signature %d", ErrVerify, index)
		}

		result.KeyID = resolved.KeyID

		if err := ctx.Err(); err != nil {
			return MultiVerified{}, err
		}

		if err := verifySignature(object, index, resolved.Key); err != nil {
			result.Err = fmt.Errorf("%w: signature %d: %w", ErrVerify, index, err)
			results = append(results, result)
			continue
		}

		hasValidSignature = true
		results = append(results, result)

		if stopAfterFirstValid {
			break
		}
	}

	if !hasValidSignature {
		return MultiVerified{}, fmt.Errorf(
			"%w: no signature was successfully verified",
			ErrVerificationPolicy,
		)
	}

	if err := verifier.config.policy.Evaluate(results); err != nil {
		return MultiVerified{}, fmt.Errorf(
			"%w: evaluate signature policy: %w",
			ErrVerificationPolicy,
			err,
		)
	}

	return MultiVerified{
		Payload:    payload,
		Signatures: results,
	}, nil
}

func verifySignature(
	object *jose.JSONWebSignature,
	index int,
	key any,
) error {
	isolated := *object
	isolated.Signatures = []jose.Signature{object.Signatures[index]}

	_, err := isolated.Verify(key)
	return err
}
