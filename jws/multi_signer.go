package jws

import (
	"fmt"

	"github.com/go-jose/go-jose/v4"
)

// MultiSigner applies one or more independent signatures to the same payload
// and returns JWS JSON Serialization.
//
// One signing key produces Flattened JWS JSON Serialization. Multiple signing
// keys produce General JWS JSON Serialization. The zero value is invalid; use
// NewMultiSigner.
type MultiSigner struct {
	backend jose.Signer
	config  config
}

// NewMultiSigner creates a JWS JSON signer for one or more signing keys.
func NewMultiSigner(
	keys []SigningKey,
	options ...Option,
) (*MultiSigner, error) {
	if len(keys) == 0 {
		return nil, fmt.Errorf(
			"%w: at least one signing key is required",
			ErrInvalidConfig,
		)
	}

	config, err := makeConfig(options)
	if err != nil {
		return nil, err
	}

	if err := config.validateSigner(); err != nil {
		return nil, err
	}

	if len(keys) > config.maxSignatures {
		return nil, fmt.Errorf(
			"%w: got %d signatures, limit is %d",
			ErrTooManySignatures,
			len(keys),
			config.maxSignatures,
		)
	}

	signingKeys, err := buildSigningKeys(keys)
	if err != nil {
		return nil, err
	}

	backend, err := jose.NewMultiSigner(signingKeys, config.signerOptions())
	if err != nil {
		return nil, fmt.Errorf(
			"%w: create multi-signer: %w",
			ErrInvalidConfig,
			err,
		)
	}

	return &MultiSigner{
		backend: backend,
		config:  config,
	}, nil
}

// Sign signs a payload and returns Flattened or General JWS JSON
// Serialization.
func (signer *MultiSigner) Sign(payload []byte) (string, error) {
	if signer == nil || signer.backend == nil {
		return "", fmt.Errorf("%w: multi-signer is uninitialized", ErrInvalidConfig)
	}

	if err := validatePayload(payload, signer.config.maxPayloadSize); err != nil {
		return "", err
	}

	object, err := signer.backend.Sign(payload)
	if err != nil {
		return "", fmt.Errorf("%w: sign payload: %w", ErrSign, err)
	}

	raw := object.FullSerialize()

	if err := validateRawToken(raw, signer.config.maxTokenSize); err != nil {
		return "", err
	}

	return raw, nil
}
