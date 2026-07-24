package jws

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"testing"

	"github.com/go-jose/go-jose/v4"
)

const (
	benchmarkKeyID          = "benchmark-key"
	benchmarkType           = "benchmark+jws"
	benchmarkContentType    = "application/octet-stream"
	benchmarkMaxTokenSize   = 256 << 10
	benchmarkMaxPayloadSize = 64 << 10
)

var (
	benchmarkStringSink        string
	benchmarkBytesSink         []byte
	benchmarkVerifiedSink      Verified
	benchmarkMultiVerifiedSink MultiVerified
)

type benchmarkSigningFixture struct {
	name            string
	algorithm       jose.SignatureAlgorithm
	signingKey      any
	verificationKey any
}

func BenchmarkSignerSign(b *testing.B) {
	for _, fixture := range benchmarkSigningFixtures(b) {
		fixture := fixture
		signer := benchmarkSigner(b, fixture)

		for _, size := range benchmarkPayloadSizes() {
			size := size

			b.Run(fmt.Sprintf("%s/%s", fixture.name, size.name), func(b *testing.B) {
				payload := benchmarkBytes(size.bytes, 0x21)

				b.ReportAllocs()
				b.SetBytes(int64(len(payload)))
				b.ResetTimer()

				var raw string
				var err error

				for b.Loop() {
					raw, err = signer.Sign(payload)
					if err != nil {
						b.Fatalf("Sign() error = %v", err)
					}
				}

				benchmarkStringSink = raw
			})
		}
	}
}

func BenchmarkSignerSignDetached(b *testing.B) {
	payload := benchmarkBytes(1<<10, 0x31)

	for _, fixture := range benchmarkSigningFixtures(b) {
		fixture := fixture
		signer := benchmarkSigner(b, fixture)

		b.Run(fixture.name, func(b *testing.B) {
			b.ReportAllocs()
			b.SetBytes(int64(len(payload)))
			b.ResetTimer()

			var raw string
			var err error

			for b.Loop() {
				raw, err = signer.SignDetached(payload)
				if err != nil {
					b.Fatalf("SignDetached() error = %v", err)
				}
			}

			benchmarkStringSink = raw
		})
	}
}

func BenchmarkVerifierVerifyMessage(b *testing.B) {
	ctx := context.Background()

	for _, fixture := range benchmarkSigningFixtures(b) {
		fixture := fixture
		signer := benchmarkSigner(b, fixture)
		verifier := benchmarkVerifier(b, fixture)

		for _, size := range benchmarkPayloadSizes() {
			size := size

			b.Run(fmt.Sprintf("%s/%s", fixture.name, size.name), func(b *testing.B) {
				payload := benchmarkBytes(size.bytes, 0x41)
				raw, err := signer.Sign(payload)
				if err != nil {
					b.Fatalf("Sign() setup error = %v", err)
				}

				b.ReportAllocs()
				b.SetBytes(int64(len(payload)))
				b.ResetTimer()

				var verified Verified

				for b.Loop() {
					verified, err = verifier.VerifyMessage(ctx, raw)
					if err != nil {
						b.Fatalf("VerifyMessage() error = %v", err)
					}
				}

				benchmarkVerifiedSink = verified
				benchmarkBytesSink = verified.Payload
			})
		}
	}
}

func BenchmarkVerifierVerifyDetached(b *testing.B) {
	ctx := context.Background()
	payload := benchmarkBytes(1<<10, 0x61)

	for _, fixture := range benchmarkSigningFixtures(b) {
		fixture := fixture
		signer := benchmarkSigner(b, fixture)
		verifier := benchmarkVerifier(b, fixture)

		raw, err := signer.SignDetached(payload)
		if err != nil {
			b.Fatalf("SignDetached() setup error = %v", err)
		}

		b.Run(fixture.name, func(b *testing.B) {
			b.ReportAllocs()
			b.SetBytes(int64(len(payload)))
			b.ResetTimer()

			var verified Verified

			for b.Loop() {
				verified, err = verifier.VerifyDetached(ctx, raw, payload)
				if err != nil {
					b.Fatalf("VerifyDetached() error = %v", err)
				}
			}

			benchmarkVerifiedSink = verified
			benchmarkBytesSink = verified.Payload
		})
	}
}

func BenchmarkMultiSignerSign(b *testing.B) {
	payload := benchmarkBytes(1<<10, 0x71)

	for _, signatureCount := range []int{1, 2, 4, 8} {
		signatureCount := signatureCount

		b.Run(fmt.Sprintf("Signatures=%d", signatureCount), func(b *testing.B) {
			keys, _ := benchmarkMultiSigningKeys(signatureCount)

			signer, err := NewMultiSigner(keys, benchmarkOptions()...)
			if err != nil {
				b.Fatalf("NewMultiSigner() error = %v", err)
			}

			b.ReportAllocs()
			b.SetBytes(int64(len(payload)))
			b.ResetTimer()

			var raw string

			for b.Loop() {
				raw, err = signer.Sign(payload)
				if err != nil {
					b.Fatalf("Sign() error = %v", err)
				}
			}

			benchmarkStringSink = raw
		})
	}
}

func BenchmarkMultiVerifierVerifyMessage(b *testing.B) {
	ctx := context.Background()
	payload := benchmarkBytes(1<<10, 0x81)

	policies := []struct {
		name   string
		policy SignaturePolicy
	}{
		{
			name:   "RequireAny",
			policy: RequireAnySignature(),
		},
		{
			name:   "RequireAll",
			policy: RequireAllProvidedSignatures(),
		},
	}

	for _, policy := range policies {
		policy := policy

		b.Run(policy.name, func(b *testing.B) {
			for _, signatureCount := range []int{1, 2, 4, 8} {
				signatureCount := signatureCount

				b.Run(fmt.Sprintf("Signatures=%d", signatureCount), func(b *testing.B) {
					keys, secret := benchmarkMultiSigningKeys(signatureCount)

					signer, err := NewMultiSigner(keys, benchmarkOptions()...)
					if err != nil {
						b.Fatalf("NewMultiSigner() error = %v", err)
					}

					raw, err := signer.Sign(payload)
					if err != nil {
						b.Fatalf("Sign() setup error = %v", err)
					}

					options := append(
						benchmarkOptions(),
						WithSignaturePolicy(policy.policy),
					)

					verifier, err := NewMultiVerifier(
						secret,
						benchmarkMultiAlgorithms(),
						options...,
					)
					if err != nil {
						b.Fatalf("NewMultiVerifier() error = %v", err)
					}

					b.ReportAllocs()
					b.SetBytes(int64(len(payload)))
					b.ResetTimer()

					var verified MultiVerified

					for b.Loop() {
						verified, err = verifier.VerifyMessage(ctx, raw)
						if err != nil {
							b.Fatalf("VerifyMessage() error = %v", err)
						}
					}

					benchmarkMultiVerifiedSink = verified
					benchmarkBytesSink = verified.Payload
				})
			}
		})
	}
}

func benchmarkSigningFixtures(b testing.TB) []benchmarkSigningFixture {
	b.Helper()

	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		b.Fatalf("rsa.GenerateKey() error = %v", err)
	}

	ecdsaKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		b.Fatalf("ecdsa.GenerateKey() error = %v", err)
	}

	ed25519PublicKey, ed25519PrivateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		b.Fatalf("ed25519.GenerateKey() error = %v", err)
	}

	secret := benchmarkBytes(64, 0x11)

	return []benchmarkSigningFixture{
		{
			name:            "HS256",
			algorithm:       jose.HS256,
			signingKey:      secret,
			verificationKey: secret,
		},
		{
			name:            "PS256",
			algorithm:       jose.PS256,
			signingKey:      rsaKey,
			verificationKey: &rsaKey.PublicKey,
		},
		{
			name:            "ES256",
			algorithm:       jose.ES256,
			signingKey:      ecdsaKey,
			verificationKey: &ecdsaKey.PublicKey,
		},
		{
			name:            "EdDSA",
			algorithm:       jose.EdDSA,
			signingKey:      ed25519PrivateKey,
			verificationKey: ed25519PublicKey,
		},
	}
}

func benchmarkSigner(
	b testing.TB,
	fixture benchmarkSigningFixture,
) *Signer {
	b.Helper()

	signer, err := NewSigner(
		SigningKey{
			Algorithm: fixture.algorithm,
			KeyID:     benchmarkKeyID,
			Key:       fixture.signingKey,
		},
		benchmarkOptions()...,
	)
	if err != nil {
		b.Fatalf("NewSigner(%s) error = %v", fixture.name, err)
	}

	return signer
}

func benchmarkVerifier(
	b testing.TB,
	fixture benchmarkSigningFixture,
) *Verifier {
	b.Helper()

	verifier, err := NewVerifier(
		jose.JSONWebKey{
			Key:       fixture.verificationKey,
			KeyID:     benchmarkKeyID,
			Algorithm: string(fixture.algorithm),
			Use:       "sig",
		},
		[]jose.SignatureAlgorithm{fixture.algorithm},
		benchmarkOptions()...,
	)
	if err != nil {
		b.Fatalf("NewVerifier(%s) error = %v", fixture.name, err)
	}

	return verifier
}

func benchmarkMultiSigningKeys(count int) ([]SigningKey, []byte) {
	secret := benchmarkBytes(64, 0x51)
	algorithms := []jose.SignatureAlgorithm{
		jose.HS256,
		jose.HS384,
		jose.HS512,
	}

	keys := make([]SigningKey, count)
	for index := range keys {
		keys[index] = SigningKey{
			Algorithm: algorithms[index%len(algorithms)],
			Key:       secret,
		}
	}

	return keys, secret
}

func benchmarkMultiAlgorithms() []jose.SignatureAlgorithm {
	return []jose.SignatureAlgorithm{
		jose.HS256,
		jose.HS384,
		jose.HS512,
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

func benchmarkOptions() []Option {
	return []Option{
		WithType(benchmarkType),
		WithContentType(benchmarkContentType),
		WithMaxTokenSize(benchmarkMaxTokenSize),
		WithMaxPayloadSize(benchmarkMaxPayloadSize),
	}
}

func benchmarkBytes(size int, seed byte) []byte {
	value := make([]byte, size)
	for index := range value {
		value[index] = seed + byte(index%17)
	}

	return value
}
