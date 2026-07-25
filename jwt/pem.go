package jwt

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
)

// ParsePrivateKeyPEM parses an unencrypted RSA, ECDSA, or Ed25519 private key
// from a PEM block containing PKCS#8, PKCS#1, or SEC1 DER.
func ParsePrivateKeyPEM(data []byte) (crypto.PrivateKey, error) {
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("%w: invalid private key PEM", ErrInvalidKey)
	}

	return ParsePrivateKeyDER(block.Bytes)
}

// ParsePrivateKeyDER parses an unencrypted RSA, ECDSA, or Ed25519 private key
// from PKCS#8, PKCS#1, or SEC1 DER.
func ParsePrivateKeyDER(data []byte) (crypto.PrivateKey, error) {
	if key, err := x509.ParsePKCS8PrivateKey(data); err == nil {
		return supportedPrivateKey(key)
	}
	if key, err := x509.ParsePKCS1PrivateKey(data); err == nil {
		return key, nil
	}
	if key, err := x509.ParseECPrivateKey(data); err == nil {
		return key, nil
	}

	return nil, fmt.Errorf(
		"%w: unsupported private key DER",
		ErrInvalidKey,
	)
}

// ParsePublicKeyPEM parses an RSA, ECDSA, or Ed25519 public key from a PEM
// block containing PKIX, PKCS#1, or X.509 certificate DER.
func ParsePublicKeyPEM(data []byte) (crypto.PublicKey, error) {
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("%w: invalid public key PEM", ErrInvalidKey)
	}

	return ParsePublicKeyDER(block.Bytes)
}

// ParsePublicKeyDER parses an RSA, ECDSA, or Ed25519 public key from PKIX,
// PKCS#1, or X.509 certificate DER.
func ParsePublicKeyDER(data []byte) (crypto.PublicKey, error) {
	if key, err := x509.ParsePKIXPublicKey(data); err == nil {
		return supportedPublicKey(key)
	}
	if key, err := x509.ParsePKCS1PublicKey(data); err == nil {
		return key, nil
	}
	certificate, err := x509.ParseCertificate(data)
	if err == nil {
		return supportedPublicKey(certificate.PublicKey)
	}

	return nil, fmt.Errorf(
		"%w: unsupported public key DER",
		ErrInvalidKey,
	)
}

func supportedPrivateKey(k any) (crypto.PrivateKey, error) {
	switch k.(type) {
	case *rsa.PrivateKey, *ecdsa.PrivateKey, ed25519.PrivateKey:
		return k, nil
	default:
		return nil, fmt.Errorf("%w: unsupported private key type %T", ErrInvalidKey, k)
	}
}

func supportedPublicKey(k any) (crypto.PublicKey, error) {
	switch k.(type) {
	case *rsa.PublicKey, *ecdsa.PublicKey, ed25519.PublicKey:
		return k, nil
	default:
		return nil, fmt.Errorf("%w: unsupported public key type %T", ErrInvalidKey, k)
	}
}
