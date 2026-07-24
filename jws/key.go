package jws

import (
	"bytes"
	"crypto/ed25519"
	"crypto/x509"
	"fmt"

	"github.com/go-jose/go-jose/v4"
)

const maxKeyIDLength = 256

// SigningKey describes one JWS signature algorithm and its key material.
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
		return fmt.Errorf("%w: signature algorithm is required", ErrInvalidConfig)
	}

	if key.Key == nil {
		return fmt.Errorf("%w: signing key is required", ErrInvalidConfig)
	}

	if key.KeyID != "" {
		if err := validateHeaderText(headerKeyID, key.KeyID, maxKeyIDLength); err != nil {
			return fmt.Errorf("%w: %w", ErrInvalidConfig, err)
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
			Use:       "sig",
		}, nil
	}
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

func mergeJWKMetadata(jwk jose.JSONWebKey, key SigningKey) (jose.JSONWebKey, error) {
	if jwk.Key == nil {
		return jose.JSONWebKey{}, fmt.Errorf(
			"%w: signing JWK key material is nil",
			ErrInvalidConfig,
		)
	}

	if key.KeyID != "" &&
		jwk.KeyID != "" &&
		key.KeyID != jwk.KeyID {
		return jose.JSONWebKey{}, fmt.Errorf(
			"%w: signing key ID %q conflicts with JWK key ID %q",
			ErrInvalidConfig,
			key.KeyID,
			jwk.KeyID,
		)
	}

	if jwk.Algorithm != "" &&
		jwk.Algorithm != string(key.Algorithm) {
		return jose.JSONWebKey{}, fmt.Errorf(
			"%w: JWK algorithm %q conflicts with %q",
			ErrInvalidConfig,
			jwk.Algorithm,
			key.Algorithm,
		)
	}

	if jwk.Use != "" && jwk.Use != "sig" {
		return jose.JSONWebKey{}, fmt.Errorf(
			"%w: JWK use must be %q",
			ErrInvalidConfig,
			"sig",
		)
	}

	if key.KeyID != "" {
		jwk.KeyID = key.KeyID
	}

	jwk.Algorithm = string(key.Algorithm)
	jwk.Use = "sig"

	return jwk, nil
}

func cloneKeyMaterial(key any) any {
	switch key := key.(type) {
	case jose.JSONWebKey:
		return cloneJWK(key)

	case *jose.JSONWebKey:
		if key == nil {
			return nil
		}

		return new(cloneJWK(*key))

	case jose.JSONWebKeySet:
		return cloneJWKS(key)

	case *jose.JSONWebKeySet:
		if key == nil {
			return nil
		}

		return new(cloneJWKS(*key))

	default:
		return cloneMutableKeyMaterial(key)
	}
}

func cloneMutableKeyMaterial(key any) any {
	switch key := key.(type) {
	case []byte:
		return bytes.Clone(key)

	case ed25519.PrivateKey:
		return ed25519.PrivateKey(
			bytes.Clone(key),
		)

	case ed25519.PublicKey:
		return ed25519.PublicKey(
			bytes.Clone(key),
		)

	default:
		return key
	}
}

func cloneJWK(key jose.JSONWebKey) jose.JSONWebKey {
	key.Key = cloneMutableKeyMaterial(key.Key)

	key.Certificates = append(
		[]*x509.Certificate(nil),
		key.Certificates...,
	)

	key.CertificateThumbprintSHA1 = bytes.Clone(
		key.CertificateThumbprintSHA1,
	)

	key.CertificateThumbprintSHA256 = bytes.Clone(
		key.CertificateThumbprintSHA256,
	)

	if key.CertificatesURL != nil {
		key.CertificatesURL = new(*key.CertificatesURL)
	}

	return key
}

func cloneJWKS(set jose.JSONWebKeySet) jose.JSONWebKeySet {
	cloned := jose.JSONWebKeySet{
		Keys: make([]jose.JSONWebKey, len(set.Keys)),
	}

	for index, key := range set.Keys {
		cloned.Keys[index] = cloneJWK(key)
	}

	return cloned
}
