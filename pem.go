package xjwt

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
)

func ParsePrivateKeyPEM(data []byte) (crypto.PrivateKey, error) {
	b, _ := pem.Decode(data)
	if b == nil {
		return nil, fmt.Errorf("%w: invalid PEM", ErrInvalidKey)
	}
	return ParsePrivateKeyDER(b.Bytes)
}
func ParsePrivateKeyDER(data []byte) (crypto.PrivateKey, error) {
	if k, e := x509.ParsePKCS8PrivateKey(data); e == nil {
		return supportedPrivate(k)
	}
	if k, e := x509.ParsePKCS1PrivateKey(data); e == nil {
		return supportedPrivate(k)
	}
	if k, e := x509.ParseECPrivateKey(data); e == nil {
		return supportedPrivate(k)
	}
	return nil, fmt.Errorf("%w: unsupported private key DER", ErrInvalidKey)
}
func ParsePublicKeyPEM(data []byte) (crypto.PublicKey, error) {
	b, _ := pem.Decode(data)
	if b == nil {
		return nil, fmt.Errorf("%w: invalid PEM", ErrInvalidKey)
	}
	if b.Type == "CERTIFICATE" {
		return ParseCertificatePublicKeyDER(b.Bytes)
	}
	return ParsePublicKeyDER(b.Bytes)
}
func ParsePublicKeyDER(data []byte) (crypto.PublicKey, error) {
	if k, e := x509.ParsePKIXPublicKey(data); e == nil {
		return supportedPublic(k)
	}
	if k, e := x509.ParsePKCS1PublicKey(data); e == nil {
		return supportedPublic(k)
	}
	return nil, fmt.Errorf("%w: unsupported public key DER", ErrInvalidKey)
}
func ParseCertificatePublicKeyPEM(data []byte) (crypto.PublicKey, error) {
	b, _ := pem.Decode(data)
	if b == nil {
		return nil, fmt.Errorf("%w: invalid certificate PEM", ErrInvalidKey)
	}
	return ParseCertificatePublicKeyDER(b.Bytes)
}
func ParseCertificatePublicKeyDER(data []byte) (crypto.PublicKey, error) {
	c, e := x509.ParseCertificate(data)
	if e != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidKey, e)
	}
	return supportedPublic(c.PublicKey)
}
func MarshalPrivateKeyDER(key crypto.PrivateKey) ([]byte, error) {
	if _, e := supportedPrivate(key); e != nil {
		return nil, e
	}
	b, e := x509.MarshalPKCS8PrivateKey(key)
	if e != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidKey, e)
	}
	return b, nil
}
func MarshalPrivateKeyPEM(key crypto.PrivateKey) ([]byte, error) {
	b, e := MarshalPrivateKeyDER(key)
	if e != nil {
		return nil, e
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: b}), nil
}
func MarshalPublicKeyDER(key crypto.PublicKey) ([]byte, error) {
	if _, e := supportedPublic(key); e != nil {
		return nil, e
	}
	b, e := x509.MarshalPKIXPublicKey(key)
	if e != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidKey, e)
	}
	return b, nil
}
func MarshalPublicKeyPEM(key crypto.PublicKey) ([]byte, error) {
	b, e := MarshalPublicKeyDER(key)
	if e != nil {
		return nil, e
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: b}), nil
}
func supportedPrivate(k any) (crypto.PrivateKey, error) {
	switch k.(type) {
	case *rsa.PrivateKey, *ecdsa.PrivateKey, ed25519.PrivateKey:
		return k, nil
	default:
		return nil, fmt.Errorf("%w: unsupported private key type %T", ErrInvalidKey, k)
	}
}
func supportedPublic(k any) (crypto.PublicKey, error) {
	switch k.(type) {
	case *rsa.PublicKey, *ecdsa.PublicKey, ed25519.PublicKey:
		return k, nil
	default:
		return nil, fmt.Errorf("%w: unsupported public key type %T", ErrInvalidKey, k)
	}
}
