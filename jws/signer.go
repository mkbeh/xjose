package jws

import (
	"fmt"

	"github.com/go-jose/go-jose/v4"
)

// Signer signs byte payloads using Compact JWS Serialization.
//
// A Signer may be reused concurrently when its key implementation is safe for
// concurrent use. The zero value is invalid; use NewSigner.
type Signer struct {
	backend jose.Signer
	config  config
}

// NewSigner creates a Compact JWS signer for one signing key.
func NewSigner(key SigningKey, options ...Option) (*Signer, error) {
	config, err := makeConfig(options)
	if err != nil {
		return nil, err
	}

	if err := config.validateSigner(); err != nil {
		return nil, err
	}

	signKey, err := key.build()
	if err != nil {
		return nil, err
	}

	backend, err := jose.NewSigner(signKey, config.signerOptions())
	if err != nil {
		return nil, fmt.Errorf(
			"%w: create signer: %w",
			ErrInvalidConfig,
			err,
		)
	}

	return &Signer{
		backend: backend,
		config:  config,
	}, nil
}

// Sign signs a payload and returns Compact JWS Serialization.
//
// A nil payload is rejected. A non-nil empty payload is valid JWS content.
func (signer *Signer) Sign(payload []byte) (string, error) {
	object, err := signer.sign(payload)
	if err != nil {
		return "", err
	}

	raw, err := object.CompactSerialize()
	if err != nil {
		return "", fmt.Errorf(
			"%w: serialize compact JWS: %w",
			ErrSign,
			err,
		)
	}

	if err := validateRaw(raw, signer.config.maxTokenSize); err != nil {
		return "", err
	}

	return raw, nil
}

// SignDetached signs a payload and returns Compact JWS Serialization with an
// empty payload segment.
//
// The caller must retain and provide the exact payload bytes during
// verification.
func (signer *Signer) SignDetached(payload []byte) (string, error) {
	object, err := signer.sign(payload)
	if err != nil {
		return "", err
	}

	raw, err := object.DetachedCompactSerialize()
	if err != nil {
		return "", fmt.Errorf(
			"%w: serialize detached compact JWS: %w",
			ErrSign,
			err,
		)
	}

	if err := validateRaw(raw, signer.config.maxTokenSize); err != nil {
		return "", err
	}

	return raw, nil
}

func (signer *Signer) sign(payload []byte) (*jose.JSONWebSignature, error) {
	if signer == nil || signer.backend == nil {
		return nil, fmt.Errorf(
			"%w: signer is uninitialized",
			ErrInvalidConfig,
		)
	}

	if payload == nil {
		return nil, ErrMissingPayload
	}

	if len(payload) > signer.config.maxPayloadSize {
		return nil, fmt.Errorf(
			"%w: got %d bytes, limit is %d",
			ErrPayloadTooLarge,
			len(payload),
			signer.config.maxPayloadSize,
		)
	}

	object, err := signer.backend.Sign(payload)
	if err != nil {
		return nil, fmt.Errorf(
			"%w: sign payload: %w",
			ErrSign,
			err,
		)
	}

	return object, nil
}
