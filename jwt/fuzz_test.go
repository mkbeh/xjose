package jwt

import (
	"bytes"
	"context"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

var rootFuzzNow = time.Date(2026, 7, 23, 12, 0, 0, 0, time.UTC)

type rootFuzzClaims struct {
	jwt.RegisteredClaims

	Data     []byte `json:"data,omitempty"`
	Sequence uint64 `json:"sequence,omitempty"`
}

func FuzzVerifierVerifyToken(f *testing.F) {
	signer, verifier := newRootFuzzStack(f)

	valid, err := signer.Sign(context.Background(), newRootFuzzClaims(nil, 0))
	if err != nil {
		f.Fatalf("Sign() seed error = %v", err)
	}

	f.Add(valid)
	f.Add("")
	f.Add("not-a-jwt")
	f.Add("a.b.c")
	f.Add(valid + ".")

	f.Fuzz(func(t *testing.T, raw string) {
		claims := new(rootFuzzClaims)
		header, err := verifier.VerifyToken(
			context.Background(),
			raw,
			claims,
		)
		if err != nil {
			if header != (Header{}) {
				t.Fatalf("VerifyToken() header = %+v on error %v", header, err)
			}

			return
		}

		if header.Algorithm != jwt.SigningMethodHS256.Alg() {
			t.Fatalf("algorithm = %q, want %q", header.Algorithm, jwt.SigningMethodHS256.Alg())
		}
		if header.KeyID != "fuzz-key" {
			t.Fatalf("key ID = %q, want %q", header.KeyID, "fuzz-key")
		}
		if header.Type != "JWT" {
			t.Fatalf("type = %q, want %q", header.Type, "JWT")
		}
		if claims.Issuer != "https://fuzz.example.com" {
			t.Fatalf("issuer = %q", claims.Issuer)
		}
		if claims.ExpiresAt == nil || !claims.ExpiresAt.After(rootFuzzNow) {
			t.Fatalf("expiration = %v", claims.ExpiresAt)
		}
	})
}

func FuzzSignVerifyRoundTrip(f *testing.F) {
	signer, verifier := newRootFuzzStack(f)

	f.Add([]byte(nil), uint64(0))
	f.Add([]byte("payload"), uint64(1))
	f.Add([]byte{0x00, 0xff, 0x80, 0x7f}, ^uint64(0))

	f.Fuzz(func(t *testing.T, data []byte, sequence uint64) {
		if len(data) > 16<<10 {
			return
		}

		raw, err := signer.Sign(
			context.Background(),
			newRootFuzzClaims(data, sequence),
		)
		if err != nil {
			t.Fatalf("Sign() error = %v", err)
		}

		claims := new(rootFuzzClaims)
		header, err := verifier.VerifyToken(
			context.Background(),
			raw,
			claims,
		)
		if err != nil {
			t.Fatalf("VerifyToken() error = %v", err)
		}

		if header.Algorithm != jwt.SigningMethodHS256.Alg() ||
			header.KeyID != "fuzz-key" ||
			header.Type != "JWT" {
			t.Fatalf("header = %+v", header)
		}
		if !bytes.Equal(claims.Data, data) {
			t.Fatalf("data = %x, want %x", claims.Data, data)
		}
		if claims.Sequence != sequence {
			t.Fatalf("sequence = %d, want %d", claims.Sequence, sequence)
		}
	})
}

func newRootFuzzStack(t testing.TB) (*Signer, *Verifier) {
	t.Helper()

	secret := make([]byte, 64)
	for index := range secret {
		secret[index] = byte(index + 1)
	}

	signingKey, err := NewSigningKey(
		"fuzz-key",
		jwt.SigningMethodHS256,
		secret,
	)
	if err != nil {
		t.Fatalf("NewSigningKey() error = %v", err)
	}

	signer, err := NewSigner(
		signingKey,
		WithMaxTokenSize(64<<10),
	)
	if err != nil {
		t.Fatalf("NewSigner() error = %v", err)
	}

	keySet, err := NewStaticKeySet(signingKey.VerificationKey())
	if err != nil {
		t.Fatalf("NewStaticKeySet() error = %v", err)
	}

	verifier, err := NewVerifier(
		keySet,
		WithMethods(jwt.SigningMethodHS256),
		WithClock(func() time.Time { return rootFuzzNow }),
		WithType("JWT"),
		WithIssuer("https://fuzz.example.com"),
		WithAudience("fuzz-api"),
		RequireIssuedAt(),
		WithMaxLifetime(10*time.Minute),
		WithMaxTokenSize(64<<10),
	)
	if err != nil {
		t.Fatalf("NewVerifier() error = %v", err)
	}

	return signer, verifier
}

func newRootFuzzClaims(data []byte, sequence uint64) *rootFuzzClaims {
	return &rootFuzzClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    "https://fuzz.example.com",
			Subject:   "fuzz-subject",
			Audience:  jwt.ClaimStrings{"fuzz-api"},
			ExpiresAt: jwt.NewNumericDate(rootFuzzNow.Add(5 * time.Minute)),
			NotBefore: jwt.NewNumericDate(rootFuzzNow.Add(-time.Minute)),
			IssuedAt:  jwt.NewNumericDate(rootFuzzNow),
			ID:        "fuzz-token",
		},
		Data:     bytes.Clone(data),
		Sequence: sequence,
	}
}
