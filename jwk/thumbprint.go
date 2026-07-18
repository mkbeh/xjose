package jwk

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"

	"github.com/mkbeh/xjwt"
)

// FromVerificationKey creates a public JWK from an xjwt verification key.
// Symmetric HMAC keys cannot be exported as public JWKs.
func FromVerificationKey(key xjwt.VerificationKey) (Key, error) {
	publicKey, err := key.PublicKey()
	if err != nil {
		return Key{}, fmt.Errorf("%w: get public key: %w", ErrPrivateKeyMaterial, err)
	}

	return NewVerificationKey(key.ID(), key.Algorithm(), publicKey)
}

// Thumbprint returns the RFC 7638 JWK thumbprint using hash.
func (k Key) Thumbprint(hash crypto.Hash) ([]byte, error) {
	if !hash.Available() {
		return nil, fmt.Errorf("%w: hash %v is unavailable", ErrInvalid, hash)
	}

	canonical, err := k.thumbprintInput()
	if err != nil {
		return nil, err
	}

	digest := hash.New()
	_, _ = digest.Write(canonical)

	return digest.Sum(nil), nil
}

// ThumbprintID returns the base64url-encoded SHA-256 RFC 7638 thumbprint. It is
// suitable for use as a deterministic kid when an application wants one.
func (k Key) ThumbprintID() (string, error) {
	thumbprint, err := k.Thumbprint(crypto.SHA256)
	if err != nil {
		return "", err
	}

	return base64.RawURLEncoding.EncodeToString(thumbprint), nil
}

func (k Key) thumbprintInput() ([]byte, error) {
	if k.value == nil || k.keyType == "" {
		return nil, fmt.Errorf("%w: JWK is not initialized", ErrInvalid)
	}

	switch value := k.value.(type) {
	case *rsa.PublicKey:
		return json.Marshal(struct {
			Exponent string `json:"e"`
			KeyType  string `json:"kty"`
			Modulus  string `json:"n"`
		}{
			Exponent: encodeUInt(big.NewInt(int64(value.E))),
			KeyType:  KeyTypeRSA,
			Modulus:  encodeUInt(value.N),
		})
	case *ecdsa.PublicKey:
		size := coordinateSize(k.curve)
		if size == 0 {
			return nil, fmt.Errorf("%w: %w: %q", ErrInvalid, ErrUnsupportedCurve, k.curve)
		}
		return json.Marshal(struct {
			Curve   string `json:"crv"`
			KeyType string `json:"kty"`
			X       string `json:"x"`
			Y       string `json:"y"`
		}{
			Curve:   k.curve,
			KeyType: KeyTypeEC,
			X:       encodeFixed(value.X, size),
			Y:       encodeFixed(value.Y, size),
		})
	case ed25519.PublicKey:
		return json.Marshal(struct {
			Curve   string `json:"crv"`
			KeyType string `json:"kty"`
			X       string `json:"x"`
		}{
			Curve:   "Ed25519",
			KeyType: KeyTypeOKP,
			X:       strictBase64URL.EncodeToString(value),
		})
	default:
		return nil, fmt.Errorf("%w: unsupported public key value %T", ErrInvalid, k.value)
	}
}
