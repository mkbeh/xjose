package jws

import (
	"context"
	"fmt"

	"github.com/go-jose/go-jose/v4"
)

// Verified contains the trusted key identity, protected header, and payload
// produced by successful Compact JWS verification.
type Verified struct {
	KeyID   string
	Header  Header
	Payload []byte
}

// Verifier verifies Compact JWS values with one signature.
//
// The configured signature algorithms form a strict allowlist. A Verifier may
// be reused concurrently when its resolver and underlying verification-key
// implementations are safe for concurrent use. The zero value is invalid; use
// NewVerifier or NewVerifierWithResolver.
type Verifier struct {
	resolver   KeyResolver
	algorithms []jose.SignatureAlgorithm
	config     config
}

// NewVerifier creates a Compact JWS verifier backed by static key material.
//
// key may be any verification key type accepted by go-jose, including a JWK,
// JWKS, HMAC key, or OpaqueVerifier.
func NewVerifier(
	key any,
	algorithms []jose.SignatureAlgorithm,
	options ...Option,
) (*Verifier, error) {
	resolver, err := newStaticResolver(key)
	if err != nil {
		return nil, err
	}

	return NewVerifierWithResolver(
		resolver,
		algorithms,
		options...,
	)
}

// NewVerifierWithResolver creates a Compact JWS verifier that resolves trusted
// key material from each protected header.
func NewVerifierWithResolver(
	resolver KeyResolver,
	algorithms []jose.SignatureAlgorithm,
	options ...Option,
) (*Verifier, error) {
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

	if err := config.validateVerifier(); err != nil {
		return nil, err
	}

	return &Verifier{
		resolver: resolver,
		algorithms: append(
			[]jose.SignatureAlgorithm(nil),
			algorithms...,
		),
		config: config,
	}, nil
}

// Verify verifies a Compact JWS and returns its payload.
//
// On error, Verify returns a nil payload.
func (verifier *Verifier) Verify(
	ctx context.Context,
	raw string,
) ([]byte, error) {
	verified, err := verifier.VerifyMessage(ctx, raw)
	if err != nil {
		return nil, err
	}

	return verified.Payload, nil
}

// VerifyMessage verifies a Compact JWS and returns the trusted key identity,
// protected header, and payload.
func (verifier *Verifier) VerifyMessage(
	ctx context.Context,
	raw string,
) (Verified, error) {
	if err := validateRaw(raw, verifier.config.maxTokenSize); err != nil {
		return Verified{}, err
	}

	object, err := jose.ParseSignedCompact(raw, verifier.algorithms)
	if err != nil {
		return Verified{}, fmt.Errorf(
			"%w: parse compact JWS: %w",
			ErrMalformedToken,
			err,
		)
	}

	return verifier.verify(ctx, object)
}

// VerifyDetached verifies a detached Compact JWS against the exact payload
// supplied by the caller.
func (verifier *Verifier) VerifyDetached(
	ctx context.Context,
	raw string,
	payload []byte,
) (Verified, error) {
	if err := validateRaw(raw, verifier.config.maxTokenSize); err != nil {
		return Verified{}, err
	}

	if err := validatePayload(payload, verifier.config.maxPayloadSize); err != nil {
		return Verified{}, err
	}

	object, err := jose.ParseDetached(raw, payload, verifier.algorithms)
	if err != nil {
		return Verified{}, fmt.Errorf(
			"%w: parse detached compact JWS: %w",
			ErrMalformedToken,
			err,
		)
	}

	return verifier.verify(ctx, object)
}

func (verifier *Verifier) verify(
	ctx context.Context,
	object *jose.JSONWebSignature,
) (Verified, error) {
	if object == nil || len(object.Signatures) != 1 {
		return Verified{}, fmt.Errorf(
			"%w: compact JWS must contain exactly one signature",
			ErrMalformedToken,
		)
	}

	payload := object.UnsafePayloadWithoutVerification()
	if err := validatePayloadSize(payload, verifier.config.maxPayloadSize); err != nil {
		return Verified{}, err
	}

	signature := object.Signatures[0]

	if err := validateUnprotectedHeader(signature.Unprotected); err != nil {
		return Verified{}, err
	}

	header, err := parseProtectedHeader(signature.Protected)
	if err != nil {
		return Verified{}, err
	}

	if err := validateExpectedHeaders(verifier.config, header); err != nil {
		return Verified{}, err
	}

	resolved, err := verifier.resolver.Resolve(ctx, header)
	if err != nil {
		return Verified{}, fmt.Errorf(
			"resolve verification key: %w",
			err,
		)
	}

	if resolved.Key == nil {
		return Verified{}, fmt.Errorf(
			"%w: resolver returned a nil key",
			ErrVerify,
		)
	}

	verifiedPayload, err := object.Verify(resolved.Key)
	if err != nil {
		return Verified{}, fmt.Errorf(
			"%w: verify compact JWS: %w",
			ErrVerify,
			err,
		)
	}

	return Verified{
		KeyID:   resolved.KeyID,
		Header:  header,
		Payload: verifiedPayload,
	}, nil
}
