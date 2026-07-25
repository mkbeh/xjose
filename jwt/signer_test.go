package jwt

import (
	"context"
	"crypto/ed25519"
	"errors"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

func TestSignerSignAppliesHeadersAndClaims(t *testing.T) {
	signer := newHMACSigner(t, "signing-key", WithType("access+jwt"))

	raw, err := signer.Sign(testContext(), validTestClaims())
	requireNoError(t, err)

	claims := new(testClaims)
	token, _, err := jwt.NewParser().ParseUnverified(raw, claims)
	requireNoError(t, err)

	if token.Header[headerParamAlgorithm] != jwt.SigningMethodHS256.Alg() {
		t.Fatalf("alg = %v, want %q", token.Header[headerParamAlgorithm], jwt.SigningMethodHS256.Alg())
	}
	if token.Header[headerParamKeyID] != "signing-key" {
		t.Fatalf("kid = %v, want %q", token.Header[headerParamKeyID], "signing-key")
	}
	if token.Header[headerParamType] != "access+jwt" {
		t.Fatalf("typ = %v, want %q", token.Header[headerParamType], "access+jwt")
	}
	if claims.Subject != testSubject || claims.Role != "reader" {
		t.Fatalf("claims = %+v", claims)
	}
}

func TestSignerWithoutType(t *testing.T) {
	signer := newHMACSigner(t, "", WithoutType())

	raw, err := signer.Sign(testContext(), validTestClaims())
	requireNoError(t, err)

	token, _, err := jwt.NewParser().ParseUnverified(raw, new(testClaims))
	requireNoError(t, err)
	if _, exists := token.Header[headerParamType]; exists {
		t.Fatal("typ header is present")
	}
}

func TestSignerRejectsInvalidInput(t *testing.T) {
	signer := newHMACSigner(t, "")

	var nilSigner *Signer
	_, err := nilSigner.Sign(testContext(), validTestClaims())
	requireErrorIs(t, err, ErrInvalidConfig)

	_, err = signer.Sign(nil, validTestClaims())
	requireErrorIs(t, err, ErrInvalidConfig)

	_, err = signer.Sign(testContext(), nil)
	requireErrorIs(t, err, ErrInvalidClaims)

	limited := newHMACSigner(t, "", WithMaxTokenSize(32))
	_, err = limited.Sign(testContext(), validTestClaims())
	requireErrorIs(t, err, ErrTokenTooLarge)
}

func TestExternalSignerUsesContext(t *testing.T) {
	publicKey, privateKey := generateEd25519Key(t)
	type contextKey string
	const requestIDKey contextKey = "request-id"

	key, err := NewExternalSigningKey(
		"external-key",
		jwt.SigningMethodEdDSA,
		publicKey,
		func(ctx context.Context, input []byte) ([]byte, error) {
			if ctx.Value(requestIDKey) != "request-123" {
				return nil, errors.New("missing request context")
			}
			return ed25519.Sign(privateKey, input), nil
		},
	)
	requireNoError(t, err)

	signer, err := NewSigner(key)
	requireNoError(t, err)

	verificationKey := key.VerificationKey()
	verifier, err := NewVerifier(
		verificationKey,
		WithMethods(jwt.SigningMethodEdDSA),
		WithClock(func() time.Time { return testNow }),
	)
	requireNoError(t, err)

	ctx := context.WithValue(testContext(), requestIDKey, "request-123")
	raw, err := signer.Sign(ctx, validTestClaims())
	requireNoError(t, err)

	claims := new(testClaims)
	err = verifier.Verify(testContext(), raw, claims)
	requireNoError(t, err)
	if claims.Subject != testSubject {
		t.Fatalf("subject = %q, want %q", claims.Subject, testSubject)
	}
}

func TestExternalSignerErrors(t *testing.T) {
	publicKey, _ := generateEd25519Key(t)
	signError := errors.New("sign backend unavailable")

	tests := []struct {
		name   string
		sign   SignFunc
		target error
	}{
		{
			name: "backend error",
			sign: func(context.Context, []byte) ([]byte, error) {
				return nil, signError
			},
			target: signError,
		},
		{
			name: "empty signature",
			sign: func(context.Context, []byte) ([]byte, error) {
				return nil, nil
			},
			target: ErrInvalidSignature,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			key, err := NewExternalSigningKey("", jwt.SigningMethodEdDSA, publicKey, test.sign)
			requireNoError(t, err)
			signer, err := NewSigner(key)
			requireNoError(t, err)

			_, err = signer.Sign(testContext(), validTestClaims())
			requireErrorIs(t, err, ErrSign)
			requireErrorIs(t, err, test.target)
		})
	}
}
