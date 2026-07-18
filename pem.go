package xjwt

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
)

const (
	pemTypePrivateKey    = "PRIVATE KEY"
	pemTypePublicKey     = "PUBLIC KEY"
	pemTypeCertificate   = "CERTIFICATE"
	pemTypeEncryptedKey  = "ENCRYPTED PRIVATE KEY"
	pemTypeRSAPrivateKey = "RSA PRIVATE KEY"
	pemTypeRSAPublicKey  = "RSA PUBLIC KEY"
	pemTypeECPrivateKey  = "EC PRIVATE KEY"
)

// ParsePrivateKeyPEM parses one unencrypted PKCS#8, PKCS#1, or SEC1 private key
// PEM block. It accepts RSA, ECDSA, and Ed25519 keys supported by xjwt.
func ParsePrivateKeyPEM(data []byte) (crypto.Signer, error) {
	block, err := decodeSinglePEMBlock(data)
	if err != nil {
		return nil, err
	}
	if block.Type == pemTypeEncryptedKey || block.Headers["Proc-Type"] == "4,ENCRYPTED" || block.Headers["DEK-Info"] != "" {
		return nil, fmt.Errorf("%w: encrypted private keys are not supported", ErrInvalidKey)
	}

	switch block.Type {
	case pemTypePrivateKey, pemTypeRSAPrivateKey, pemTypeECPrivateKey:
		return ParsePrivateKeyDER(block.Bytes)
	default:
		return nil, fmt.Errorf("%w: unsupported private key PEM type %q", ErrInvalidKey, block.Type)
	}
}

// ParsePrivateKeyDER parses an unencrypted PKCS#8, PKCS#1, or SEC1 DER private
// key. It accepts RSA, ECDSA, and Ed25519 keys supported by xjwt.
func ParsePrivateKeyDER(data []byte) (crypto.Signer, error) {
	if len(data) == 0 {
		return nil, fmt.Errorf("%w: private key DER is empty", ErrInvalidKey)
	}

	if value, err := x509.ParsePKCS8PrivateKey(data); err == nil {
		return normalizeParsedPrivateKey(value)
	}
	if value, err := x509.ParsePKCS1PrivateKey(data); err == nil {
		return normalizeParsedPrivateKey(value)
	}
	if value, err := x509.ParseECPrivateKey(data); err == nil {
		return normalizeParsedPrivateKey(value)
	}

	return nil, fmt.Errorf("%w: unsupported or malformed private key DER", ErrInvalidKey)
}

// ParsePublicKeyPEM parses one PKIX, PKCS#1 RSA, or X.509 certificate PEM
// block and returns its RSA, ECDSA, or Ed25519 public key.
func ParsePublicKeyPEM(data []byte) (crypto.PublicKey, error) {
	block, err := decodeSinglePEMBlock(data)
	if err != nil {
		return nil, err
	}

	switch block.Type {
	case pemTypePublicKey, pemTypeRSAPublicKey:
		return ParsePublicKeyDER(block.Bytes)
	case pemTypeCertificate:
		return ParseCertificatePublicKeyDER(block.Bytes)
	default:
		return nil, fmt.Errorf("%w: unsupported public key PEM type %q", ErrInvalidKey, block.Type)
	}
}

// ParsePublicKeyDER parses a PKIX SubjectPublicKeyInfo or PKCS#1 RSA public key
// and returns a supported RSA, ECDSA, or Ed25519 public key.
func ParsePublicKeyDER(data []byte) (crypto.PublicKey, error) {
	if len(data) == 0 {
		return nil, fmt.Errorf("%w: public key DER is empty", ErrInvalidKey)
	}

	if value, err := x509.ParsePKIXPublicKey(data); err == nil {
		return normalizeParsedPublicKey(value)
	}
	if value, err := x509.ParsePKCS1PublicKey(data); err == nil {
		return normalizeParsedPublicKey(value)
	}

	return nil, fmt.Errorf("%w: unsupported or malformed public key DER", ErrInvalidKey)
}

// ParseCertificatePublicKeyPEM parses one X.509 certificate PEM block and
// returns its supported RSA, ECDSA, or Ed25519 public key.
func ParseCertificatePublicKeyPEM(data []byte) (crypto.PublicKey, error) {
	block, err := decodeSinglePEMBlock(data)
	if err != nil {
		return nil, err
	}
	if block.Type != pemTypeCertificate {
		return nil, fmt.Errorf("%w: expected %q PEM block, got %q", ErrInvalidKey, pemTypeCertificate, block.Type)
	}

	return ParseCertificatePublicKeyDER(block.Bytes)
}

// ParseCertificatePublicKeyDER parses an X.509 certificate and returns its
// supported RSA, ECDSA, or Ed25519 public key.
func ParseCertificatePublicKeyDER(data []byte) (crypto.PublicKey, error) {
	if len(data) == 0 {
		return nil, fmt.Errorf("%w: certificate DER is empty", ErrInvalidKey)
	}
	certificate, err := x509.ParseCertificate(data)
	if err != nil {
		return nil, fmt.Errorf("%w: parse X.509 certificate: %w", ErrInvalidKey, err)
	}

	return normalizeParsedPublicKey(certificate.PublicKey)
}

// MarshalPrivateKeyDER serializes a local RSA, ECDSA, or Ed25519 private key as
// unencrypted PKCS#8 DER. Opaque hardware-backed crypto.Signer values are not
// exportable and are rejected by the standard library.
func MarshalPrivateKeyDER(signer crypto.Signer) ([]byte, error) {
	if signer == nil {
		return nil, fmt.Errorf("%w: private key is nil", ErrInvalidKey)
	}
	value, err := normalizeParsedPrivateKey(signer)
	if err != nil {
		return nil, err
	}
	der, err := x509.MarshalPKCS8PrivateKey(value)
	if err != nil {
		return nil, fmt.Errorf("%w: marshal PKCS#8 private key: %w", ErrInvalidKey, err)
	}

	return der, nil
}

// MarshalPrivateKeyPEM serializes a local private key as unencrypted PKCS#8
// PEM. Applications are responsible for protecting the returned private-key
// material.
func MarshalPrivateKeyPEM(signer crypto.Signer) ([]byte, error) {
	der, err := MarshalPrivateKeyDER(signer)
	if err != nil {
		return nil, err
	}

	return pem.EncodeToMemory(&pem.Block{Type: pemTypePrivateKey, Bytes: der}), nil
}

// MarshalPublicKeyDER serializes a supported RSA, ECDSA, or Ed25519 public key
// as PKIX SubjectPublicKeyInfo DER.
func MarshalPublicKeyDER(publicKey crypto.PublicKey) ([]byte, error) {
	value, err := normalizeParsedPublicKey(publicKey)
	if err != nil {
		return nil, err
	}
	der, err := x509.MarshalPKIXPublicKey(value)
	if err != nil {
		return nil, fmt.Errorf("%w: marshal public key: %w", ErrInvalidKey, err)
	}

	return der, nil
}

// MarshalPublicKeyPEM serializes a supported public key as PKIX
// SubjectPublicKeyInfo PEM.
func MarshalPublicKeyPEM(publicKey crypto.PublicKey) ([]byte, error) {
	der, err := MarshalPublicKeyDER(publicKey)
	if err != nil {
		return nil, err
	}

	return pem.EncodeToMemory(&pem.Block{Type: pemTypePublicKey, Bytes: der}), nil
}

func decodeSinglePEMBlock(data []byte) (*pem.Block, error) {
	if len(bytes.TrimSpace(data)) == 0 {
		return nil, fmt.Errorf("%w: PEM data is empty", ErrInvalidKey)
	}
	block, rest := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("%w: malformed PEM data", ErrInvalidKey)
	}
	if len(bytes.TrimSpace(rest)) != 0 {
		return nil, fmt.Errorf("%w: PEM data must contain exactly one block", ErrInvalidKey)
	}

	return block, nil
}

func normalizeParsedPrivateKey(value any) (crypto.Signer, error) {
	switch key := value.(type) {
	case *rsa.PrivateKey:
		if key == nil || key.N == nil || key.N.BitLen() < minimumRSAKeyBits {
			return nil, fmt.Errorf("%w: RSA private key must contain at least %d bits", ErrInvalidKey, minimumRSAKeyBits)
		}
		if err := key.Validate(); err != nil {
			return nil, fmt.Errorf("%w: validate RSA private key: %w", ErrInvalidKey, err)
		}

		return key, nil
	case *ecdsa.PrivateKey:
		if !validSupportedECDSAPrivateKey(key) {
			return nil, fmt.Errorf("%w: unsupported or invalid ECDSA private key", ErrInvalidKey)
		}

		return key, nil
	case ed25519.PrivateKey:
		if len(key) != ed25519.PrivateKeySize {
			return nil, fmt.Errorf("%w: Ed25519 requires a %d-byte private key", ErrInvalidKey, ed25519.PrivateKeySize)
		}
		copyKey := ed25519.PrivateKey(bytes.Clone(key))
		if !bytes.Equal(copyKey, ed25519.NewKeyFromSeed(copyKey.Seed())) {
			return nil, fmt.Errorf("%w: Ed25519 private key is inconsistent with its seed", ErrInvalidKey)
		}

		return copyKey, nil
	default:
		return nil, fmt.Errorf("%w: unsupported private key type %T", ErrInvalidKey, value)
	}
}

func normalizeParsedPublicKey(value any) (crypto.PublicKey, error) {
	switch key := value.(type) {
	case *rsa.PublicKey:
		if !validRSAPublicKey(key) {
			return nil, fmt.Errorf(
				"%w: RSA public key must contain at least %d bits",
				ErrInvalidKey,
				minimumRSAKeyBits,
			)
		}

		return cloneRSAPublicKey(key), nil
	case *ecdsa.PublicKey:
		if !validSupportedECDSAPublicKey(key) {
			return nil, fmt.Errorf("%w: unsupported or invalid ECDSA public key", ErrInvalidKey)
		}

		return cloneECDSAPublicKey(key), nil
	case ed25519.PublicKey:
		if len(key) != ed25519.PublicKeySize {
			return nil, fmt.Errorf("%w: Ed25519 requires a %d-byte public key", ErrInvalidKey, ed25519.PublicKeySize)
		}

		return ed25519.PublicKey(bytes.Clone(key)), nil
	default:
		return nil, fmt.Errorf("%w: unsupported public key type %T", ErrInvalidKey, value)
	}
}

func validSupportedECDSAPrivateKey(key *ecdsa.PrivateKey) bool {
	if key == nil || key.Curve == nil || key.D == nil || !validSupportedECDSAPublicKey(&key.PublicKey) {
		return false
	}
	params := key.Curve.Params()
	if key.D.Sign() <= 0 || key.D.Cmp(params.N) >= 0 {
		return false
	}
	x, y := key.Curve.ScalarBaseMult(key.D.Bytes())

	return x.Cmp(key.X) == 0 && y.Cmp(key.Y) == 0
}

func validSupportedECDSAPublicKey(key *ecdsa.PublicKey) bool {
	if key == nil || key.Curve == nil || key.X == nil || key.Y == nil {
		return false
	}
	switch key.Curve {
	case elliptic.P256(), elliptic.P384(), elliptic.P521():
		return key.Curve.IsOnCurve(key.X, key.Y)
	default:
		return false
	}
}
