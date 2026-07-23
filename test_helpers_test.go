package xjwt

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

const (
	testIssuer   = "https://auth.example.com"
	testAudience = "orders-api"
	testSubject  = "user-123"
)

var testNow = time.Date(2026, 7, 22, 20, 0, 0, 0, time.UTC)

type testClaims struct {
	jwt.RegisteredClaims
	Role string `json:"role"`
}

func validTestClaims() *testClaims {
	return &testClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    testIssuer,
			Subject:   testSubject,
			Audience:  jwt.ClaimStrings{testAudience},
			ExpiresAt: jwt.NewNumericDate(testNow.Add(5 * time.Minute)),
			NotBefore: jwt.NewNumericDate(testNow.Add(-time.Minute)),
			IssuedAt:  jwt.NewNumericDate(testNow),
			ID:        "token-123",
		},
		Role: "reader",
	}
}

func testHMACSecret() []byte {
	secret := make([]byte, 64)
	for index := range secret {
		secret[index] = byte(index + 1)
	}
	return secret
}

func generateRSAKey(t testing.TB, bits int) *rsa.PrivateKey {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		t.Fatalf("rsa.GenerateKey() error = %v", err)
	}
	return key
}

func generateECDSAKey(t testing.TB, curve elliptic.Curve) *ecdsa.PrivateKey {
	t.Helper()
	key, err := ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		t.Fatalf("ecdsa.GenerateKey() error = %v", err)
	}
	return key
}

func generateEd25519Key(t testing.TB) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ed25519.GenerateKey() error = %v", err)
	}
	return publicKey, privateKey
}

func requireNoError(t testing.TB, err error) {
	t.Helper()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func requireErrorIs(t testing.TB, err, target error) {
	t.Helper()
	if !errors.Is(err, target) {
		t.Fatalf("error = %v, want errors.Is(_, %v)", err, target)
	}
}

func signJWT(
	t testing.TB,
	method jwt.SigningMethod,
	key any,
	claims jwt.Claims,
	headers map[string]any,
) string {
	t.Helper()
	token := jwt.NewWithClaims(method, claims)
	for name, value := range headers {
		token.Header[name] = value
	}
	raw, err := token.SignedString(key)
	if err != nil {
		t.Fatalf("SignedString() error = %v", err)
	}
	return raw
}

func newHMACSigner(t testing.TB, keyID string, options ...SignerOption) *Signer {
	t.Helper()
	key, err := NewSigningKey(keyID, jwt.SigningMethodHS256, testHMACSecret())
	requireNoError(t, err)
	signer, err := NewSigner(key, options...)
	requireNoError(t, err)
	return signer
}

func newHMACVerifier(t testing.TB, keyID string, options ...VerifierOption) *Verifier {
	t.Helper()
	key, err := NewVerificationKey(keyID, jwt.SigningMethodHS256, testHMACSecret())
	requireNoError(t, err)
	keySet, err := NewStaticKeySet(key)
	requireNoError(t, err)
	allOptions := append([]VerifierOption{
		WithMethods(jwt.SigningMethodHS256),
		WithClock(func() time.Time { return testNow }),
	}, options...)
	verifier, err := NewVerifier(keySet, allOptions...)
	requireNoError(t, err)
	return verifier
}

func testContext() context.Context {
	return context.Background()
}
