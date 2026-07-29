package jws

import (
	"bytes"
	"crypto/ed25519"
	"fmt"

	"github.com/go-jose/go-jose/v4"
)

const (
	maxKeyIDLength  = 256
	keyUseSignature = "sig"
)

// SigningKey describes one JWS signature algorithm and its key material.
//
// Byte-backed key material is copied during signer construction. RSA, ECDSA,
// opaque signers, and custom key objects are retained by reference and must not
// be mutated while the resulting Signer or MultiSigner remains in use.
//
// KeyID is copied into the protected kid header. It may be empty when the
// verification key is selected out of band.
type SigningKey struct {
	Algorithm jose.SignatureAlgorithm
	KeyID     string
	Key       any
}

func (key SigningKey) validate() error {
	if key.Algorithm == "" {
		return fmt.Errorf(
			"%w: signature algorithm is required",
			ErrInvalidConfig,
		)
	}

	if key.Key == nil {
		return fmt.Errorf(
			"%w: signing key is required",
			ErrInvalidConfig,
		)
	}

	if key.KeyID != "" {
		if err := validateHeaderValue(headerKeyID, key.KeyID, maxKeyIDLength); err != nil {
			return fmt.Errorf(
				"%w: %w",
				ErrInvalidConfig,
				err,
			)
		}
	}

	return nil
}

func (key SigningKey) build() (jose.SigningKey, error) {
	key.Key = cloneKeyMaterial(key.Key)

	if err := key.validate(); err != nil {
		return jose.SigningKey{}, err
	}

	material, err := key.buildKeyMaterial()
	if err != nil {
		return jose.SigningKey{}, err
	}

	return jose.SigningKey{
		Algorithm: key.Algorithm,
		Key:       material,
	}, nil
}

func buildSigningKeys(keys []SigningKey) ([]jose.SigningKey, error) {
	signingKeys := make([]jose.SigningKey, len(keys))

	for index, key := range keys {
		signingKey, err := key.build()
		if err != nil {
			return nil, fmt.Errorf("signing key %d: %w", index, err)
		}

		signingKeys[index] = signingKey
	}

	return signingKeys, nil
}

func (key SigningKey) buildKeyMaterial() (any, error) {
	switch material := key.Key.(type) {
	case jose.JSONWebKey:
		if _, ok := material.Key.(jose.OpaqueSigner); ok {
			return nil, fmt.Errorf(
				"%w: opaque signer must be supplied directly, not wrapped in JWK",
				ErrInvalidConfig,
			)
		}

		return mergeJWKMetadata(material, key)

	case *jose.JSONWebKey:
		if material == nil {
			return nil, fmt.Errorf(
				"%w: signing JWK is nil",
				ErrInvalidConfig,
			)
		}

		if _, ok := material.Key.(jose.OpaqueSigner); ok {
			return nil, fmt.Errorf(
				"%w: opaque signer must be supplied directly, not wrapped in JWK",
				ErrInvalidConfig,
			)
		}

		return mergeJWKMetadata(*material, key)

	case jose.OpaqueSigner:
		if key.KeyID != "" {
			return nil, fmt.Errorf(
				"%w: opaque signer key ID must be provided by OpaqueSigner.Public",
				ErrInvalidConfig,
			)
		}

		return material, nil

	default:
		if key.KeyID == "" {
			return material, nil
		}

		return jose.JSONWebKey{
			Key:       material,
			KeyID:     key.KeyID,
			Algorithm: string(key.Algorithm),
			Use:       keyUseSignature,
		}, nil
	}
}

func mergeJWKMetadata(jwk jose.JSONWebKey, key SigningKey) (jose.JSONWebKey, error) {
	if jwk.Key == nil {
		return jose.JSONWebKey{}, fmt.Errorf(
			"%w: signing JWK key material is nil",
			ErrInvalidConfig,
		)
	}

	// Reject conflicting key identifiers.
	if key.KeyID != "" && jwk.KeyID != "" && key.KeyID != jwk.KeyID {
		return jose.JSONWebKey{}, fmt.Errorf(
			"%w: signing key ID %q conflicts with JWK key ID %q",
			ErrInvalidConfig,
			key.KeyID,
			jwk.KeyID,
		)
	}

	// Reject an algorithm restriction that conflicts with the signing key.
	if jwk.Algorithm != "" && jwk.Algorithm != string(key.Algorithm) {
		return jose.JSONWebKey{}, fmt.Errorf(
			"%w: JWK algorithm %q conflicts with %q",
			ErrInvalidConfig,
			jwk.Algorithm,
			key.Algorithm,
		)
	}

	// The key must be permitted for signature operations.
	if jwk.Use != "" && jwk.Use != keyUseSignature {
		return jose.JSONWebKey{}, fmt.Errorf(
			"%w: JWK use must be %q",
			ErrInvalidConfig,
			keyUseSignature,
		)
	}

	// Merge trusted SigningKey metadata into the JWK copy.
	if key.KeyID != "" {
		jwk.KeyID = key.KeyID
	}

	jwk.Algorithm = string(key.Algorithm)
	jwk.Use = keyUseSignature

	return jwk, nil
}

func cloneKeyMaterial(key any) any {
	switch key := key.(type) {
	case []byte:
		return bytes.Clone(key)

	case ed25519.PrivateKey:
		return ed25519.PrivateKey(
			bytes.Clone(key),
		)

	case jose.JSONWebKey:
		key.Key = cloneKeyMaterial(key.Key)

		return key

	case *jose.JSONWebKey:
		if key == nil {
			return nil
		}

		cloned := *key
		cloned.Key = cloneKeyMaterial(key.Key)

		return &cloned

	default:
		// RSA, ECDSA, opaque signers, and custom key objects are retained
		// as-is and must be treated as immutable.
		return key
	}
}
