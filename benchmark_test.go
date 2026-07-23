package xjwt

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

const (
	benchmarkIssuer   = "https://auth.example.com"
	benchmarkAudience = "orders-api"
	benchmarkSubject  = "user-123"
	benchmarkKeyID    = "benchmark-key"
	benchmarkMaxSize  = 128 << 10
)

var (
	benchmarkNow = time.Date(2026, 7, 23, 12, 0, 0, 0, time.UTC)

	benchmarkTokenSink  string
	benchmarkHeaderSink Header
	benchmarkStringSink string
)

type benchmarkClaims struct {
	jwt.RegisteredClaims
	Payload string `json:"payload"`
}

type benchmarkSigningKey struct {
	name string
	key  SigningKey
}

func BenchmarkSignerSign(b *testing.B) {
	ctx := context.Background()

	for _, algorithm := range newBenchmarkSigningKeys(b) {
		signer, err := NewSigner(
			algorithm.key,
			WithMaxTokenSize(benchmarkMaxSize),
		)
		if err != nil {
			b.Fatalf("NewSigner() error = %v", err)
		}

		for _, size := range benchmarkPayloadSizes() {
			b.Run(
				fmt.Sprintf("%s/%s", algorithm.name, size.name),
				func(b *testing.B) {
					claims := newBenchmarkClaims(size.bytes)

					b.ReportAllocs()
					b.SetBytes(int64(size.bytes))
					b.ResetTimer()

					var raw string
					var err error

					for i := 0; i < b.N; i++ {
						raw, err = signer.Sign(ctx, claims)
						if err != nil {
							b.Fatalf("Sign() error = %v", err)
						}
					}

					benchmarkTokenSink = raw
				},
			)
		}
	}
}

func BenchmarkVerifierVerifyToken(b *testing.B) {
	ctx := context.Background()

	for _, algorithm := range newBenchmarkSigningKeys(b) {
		signer, err := NewSigner(
			algorithm.key,
			WithMaxTokenSize(benchmarkMaxSize),
		)
		if err != nil {
			b.Fatalf("NewSigner() error = %v", err)
		}

		keySet, err := NewStaticKeySet(
			algorithm.key.VerificationKey(),
		)
		if err != nil {
			b.Fatalf("NewStaticKeySet() error = %v", err)
		}

		verifier, err := NewVerifier(
			keySet,
			WithMethods(algorithm.key.Method()),
			WithType("JWT"),
			WithIssuer(benchmarkIssuer),
			WithAudience(benchmarkAudience),
			WithSubject(benchmarkSubject),
			WithClock(func() time.Time { return benchmarkNow }),
			RequireIssuedAt(),
			WithMaxLifetime(time.Hour),
			WithMaxTokenSize(benchmarkMaxSize),
		)
		if err != nil {
			b.Fatalf("NewVerifier() error = %v", err)
		}

		for _, size := range benchmarkPayloadSizes() {
			b.Run(
				fmt.Sprintf("%s/%s", algorithm.name, size.name),
				func(b *testing.B) {
					raw, err := signer.Sign(
						ctx,
						newBenchmarkClaims(size.bytes),
					)
					if err != nil {
						b.Fatalf("Sign() setup error = %v", err)
					}

					claims := new(benchmarkClaims)

					b.ReportAllocs()
					b.SetBytes(int64(size.bytes))
					b.ResetTimer()

					var header Header

					for i := 0; i < b.N; i++ {
						header, err = verifier.VerifyToken(
							ctx,
							raw,
							claims,
						)
						if err != nil {
							b.Fatalf("VerifyToken() error = %v", err)
						}
					}

					benchmarkHeaderSink = header
					benchmarkStringSink = claims.Payload
				},
			)
		}
	}
}

func newBenchmarkSigningKeys(b testing.TB) []benchmarkSigningKey {
	b.Helper()

	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		b.Fatalf("rsa.GenerateKey() error = %v", err)
	}

	ecdsaKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		b.Fatalf("ecdsa.GenerateKey() error = %v", err)
	}

	_, ed25519Key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		b.Fatalf("ed25519.GenerateKey() error = %v", err)
	}

	secret := make([]byte, 64)
	for index := range secret {
		secret[index] = byte(index + 1)
	}

	return []benchmarkSigningKey{
		{
			name: "HS256",
			key: newBenchmarkSigningKey(
				b,
				jwt.SigningMethodHS256,
				secret,
			),
		},
		{
			name: "PS256",
			key: newBenchmarkSigningKey(
				b,
				jwt.SigningMethodPS256,
				rsaKey,
			),
		},
		{
			name: "ES256",
			key: newBenchmarkSigningKey(
				b,
				jwt.SigningMethodES256,
				ecdsaKey,
			),
		},
		{
			name: "EdDSA",
			key: newBenchmarkSigningKey(
				b,
				jwt.SigningMethodEdDSA,
				ed25519Key,
			),
		},
	}
}

func newBenchmarkSigningKey(
	b testing.TB,
	method jwt.SigningMethod,
	key any,
) SigningKey {
	b.Helper()

	signingKey, err := NewSigningKey(
		benchmarkKeyID,
		method,
		key,
	)
	if err != nil {
		b.Fatalf("NewSigningKey(%s) error = %v", method.Alg(), err)
	}

	return signingKey
}

func newBenchmarkClaims(payloadSize int) *benchmarkClaims {
	return &benchmarkClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    benchmarkIssuer,
			Subject:   benchmarkSubject,
			Audience:  jwt.ClaimStrings{benchmarkAudience},
			ExpiresAt: jwt.NewNumericDate(benchmarkNow.Add(30 * time.Minute)),
			NotBefore: jwt.NewNumericDate(benchmarkNow.Add(-time.Minute)),
			IssuedAt:  jwt.NewNumericDate(benchmarkNow),
			ID:        "benchmark-token",
		},
		Payload: strings.Repeat("x", payloadSize),
	}
}

func benchmarkPayloadSizes() []struct {
	name  string
	bytes int
} {
	return []struct {
		name  string
		bytes int
	}{
		{name: "128B", bytes: 128},
		{name: "1KiB", bytes: 1 << 10},
		{name: "16KiB", bytes: 16 << 10},
	}
}
