package jwt

import (
	"context"
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
	sign := func(
		context.Context,
		[]byte,
	) ([]byte, error) {
		return nil, nil
	}

	tests := []struct {
		name   string
		create func() error
		target error
	}{
		{
			name: "key id too long",
			create: func() error {
				_, err := NewVerificationKey(
					strings.Repeat("a", maxKeyIDLength+1),
					jwt.SigningMethodHS256,
					testHMACSecret(),
				)

				return err
			},
			target: ErrInvalidKeyID,
		},
		{
			name: "nil signing method",
			create: func() error {
				_, err := NewSigningKey(
					"",
					nil,
					testHMACSecret(),
				)

				return err
			},
			target: ErrInvalidKey,
		},
		{
			name: "nil signing key",
			create: func() error {
				_, err := NewSigningKey(
					"",
					jwt.SigningMethodHS256,
					nil,
				)

				return err
			},
			target: ErrInvalidKey,
		},
		{
			name: "nil verification method",
			create: func() error {
				_, err := NewVerificationKey(
					"",
					nil,
					testHMACSecret(),
				)

				return err
			},
			target: ErrInvalidKey,
		},
		{
			name: "nil verification key",
			create: func() error {
				_, err := NewVerificationKey(
					"",
					jwt.SigningMethodHS256,
					nil,
				)

				return err
			},
			target: ErrInvalidKey,
		},
		{
			name: "nil external public key",
			create: func() error {
				_, err := NewExternalSigningKey(
					"",
					jwt.SigningMethodEdDSA,
					nil,
					sign,
				)

				return err
			},
			target: ErrInvalidKey,
		},
		{
			name: "nil external sign function",
			create: func() error {
				publicKey, _ := generateEd25519Key(t)

				_, err := NewExternalSigningKey(
					"",
					jwt.SigningMethodEdDSA,
					publicKey,
					nil,
				)

				return err
			},
			target: ErrInvalidKey,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			requireErrorIs(
				t,
				test.create(),
				test.target,
			)
		})
	}
}
