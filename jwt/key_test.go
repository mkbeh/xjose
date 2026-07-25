package jwt

import (
	"crypto/elliptic"
	"strings"
	"testing"

	"github.com/golang-jwt/jwt/v5"
)

func TestNewSigningKeySupportsStandardMethods(t *testing.T) {
	rsaKey := generateRSAKey(t, 2048)
	ecdsaKey := generateECDSAKey(t, elliptic.P256())
	_, ed25519Key := generateEd25519Key(t)

	tests := []struct {
		name   string
		method jwt.SigningMethod
		key    any
	}{
		{name: "HMAC", method: jwt.SigningMethodHS256, key: testHMACSecret()},
		{name: "RSA", method: jwt.SigningMethodRS256, key: rsaKey},
		{name: "RSA-PSS", method: jwt.SigningMethodPS256, key: rsaKey},
		{name: "ECDSA", method: jwt.SigningMethodES256, key: ecdsaKey},
		{name: "Ed25519", method: jwt.SigningMethodEdDSA, key: ed25519Key},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			key, err := NewSigningKey("key-1", test.method, test.key)
			requireNoError(t, err)

			if key.ID() != "key-1" {
				t.Fatalf("ID() = %q, want %q", key.ID(), "key-1")
			}
			if key.Method().Alg() != test.method.Alg() {
				t.Fatalf("Method().Alg() = %q, want %q", key.Method().Alg(), test.method.Alg())
			}

			verification := key.VerificationKey()
			if verification.ID() != key.ID() {
				t.Fatalf("verification ID = %q, want %q", verification.ID(), key.ID())
			}
			if verification.Method().Alg() != test.method.Alg() {
				t.Fatalf("verification algorithm = %q, want %q", verification.Method().Alg(), test.method.Alg())
			}
			if verification.Key() == nil {
				t.Fatal("verification key is nil")
			}
		})
	}
}

func TestKeyConstructorsRejectInvalidInput(t *testing.T) {
	shortRSA := generateRSAKey(t, 1024)
	wrongCurve := generateECDSAKey(t, elliptic.P384())

	tests := []struct {
		name   string
		create func() error
		target error
	}{
		{
			name: "invalid key id",
			create: func() error {
				_, err := NewSigningKey("key\n1", jwt.SigningMethodHS256, testHMACSecret())
				return err
			},
			target: ErrInvalidKeyID,
		},
		{
			name: "key id too long",
			create: func() error {
				_, err := NewVerificationKey(strings.Repeat("a", maxKeyIDLength+1), jwt.SigningMethodHS256, testHMACSecret())
				return err
			},
			target: ErrInvalidKeyID,
		},
		{
			name: "nil method",
			create: func() error {
				_, err := NewSigningKey("", nil, testHMACSecret())
				return err
			},
			target: ErrInvalidKey,
		},
		{
			name: "short HMAC secret",
			create: func() error {
				_, err := NewSigningKey("", jwt.SigningMethodHS256, []byte("short"))
				return err
			},
			target: ErrInvalidKey,
		},
		{
			name: "small RSA key",
			create: func() error {
				_, err := NewSigningKey("", jwt.SigningMethodRS256, shortRSA)
				return err
			},
			target: ErrInvalidKey,
		},
		{
			name: "wrong ECDSA curve",
			create: func() error {
				_, err := NewSigningKey("", jwt.SigningMethodES256, wrongCurve)
				return err
			},
			target: ErrInvalidKey,
		},
		{
			name: "invalid Ed25519 private key",
			create: func() error {
				_, err := NewSigningKey("", jwt.SigningMethodEdDSA, make([]byte, 32))
				return err
			},
			target: ErrInvalidKey,
		},
		{
			name: "wrong verification key type",
			create: func() error {
				_, err := NewVerificationKey("", jwt.SigningMethodRS256, testHMACSecret())
				return err
			},
			target: ErrInvalidKey,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			requireErrorIs(t, test.create(), test.target)
		})
	}
}

func TestHMACKeyMaterialIsCopied(t *testing.T) {
	secret := testHMACSecret()
	originalFirstByte := secret[0]

	key, err := NewSigningKey("key-1", jwt.SigningMethodHS256, secret)
	requireNoError(t, err)

	secret[0] ^= 0xff

	verification := key.VerificationKey()

	firstValue := verification.Key()
	first, ok := firstValue.([]byte)
	if !ok {
		t.Fatalf(
			"VerificationKey.Key() type = %T, want []byte",
			firstValue,
		)
	}

	if first[0] != originalFirstByte {
		t.Fatal("constructor retained caller-owned HMAC bytes")
	}

	first[0] ^= 0xff

	secondValue := verification.Key()
	second, ok := secondValue.([]byte)
	if !ok {
		t.Fatalf(
			"VerificationKey.Key() type = %T, want []byte",
			secondValue,
		)
	}

	if second[0] != originalFirstByte {
		t.Fatal("Key() exposed internal HMAC bytes")
	}
}
