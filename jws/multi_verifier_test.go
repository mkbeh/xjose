package jws

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"testing"

	jose "github.com/go-jose/go-jose/v4"
)

func TestMultiVerifierPolicies(t *testing.T) {
	fixture := newMultiFixture(t)
	payload := []byte(`{"document_id":"document-123","operation":"approve"}`)
	raw := signMultiFixture(t, fixture, payload)

	tests := []struct {
		name       string
		resolver   KeyResolver
		policy     SignaturePolicy
		wantValid  int
		wantResult int
	}{
		{
			name:       "default any stops after first valid",
			resolver:   fixture.resolver,
			wantValid:  1,
			wantResult: 1,
		},
		{
			name: "any skips unknown signature",
			resolver: newMapResolver(map[string]trustedKey{
				"approval": {
					algorithm: jose.EdDSA,
					key: fixture.keys[1].Key.(ed25519.PrivateKey).
						Public().(ed25519.PublicKey),
				},
			}),
			wantValid:  1,
			wantResult: 2,
		},
		{
			name:       "all provided",
			resolver:   fixture.resolver,
			policy:     RequireAllProvidedSignatures(),
			wantValid:  2,
			wantResult: 2,
		},
		{
			name:       "required identities",
			resolver:   fixture.resolver,
			policy:     RequireKeyIDs("issuer", "approval"),
			wantValid:  2,
			wantResult: 2,
		},
		{
			name: "threshold",
			resolver: newMapResolver(map[string]trustedKey{
				"approval": {
					algorithm: jose.EdDSA,
					key: fixture.keys[1].Key.(ed25519.PrivateKey).
						Public().(ed25519.PublicKey),
				},
			}),
			policy:     RequireThreshold(1, "issuer", "approval"),
			wantValid:  1,
			wantResult: 2,
		},
		{
			name:     "composed",
			resolver: fixture.resolver,
			policy: AllOf(
				RequireKeyIDs("issuer"),
				RequireThreshold(1, "approval", "compliance"),
			),
			wantValid:  2,
			wantResult: 2,
		},
	}

	for _, test := range tests {
		test := test

		t.Run(test.name, func(t *testing.T) {
			options := []Option{
				WithType(testType),
				WithContentType(testContentType),
			}
			if test.policy != nil {
				options = append(options, WithSignaturePolicy(test.policy))
			}

			verifier, err := NewMultiVerifierWithResolver(
				test.resolver,
				fixture.algorithms,
				options...,
			)
			requireNoError(t, err)

			verified, err := verifier.VerifyMessage(context.Background(), raw)
			requireNoError(t, err)
			requireBytesEqual(t, verified.Payload, payload)

			if len(verified.Signatures) != test.wantResult {
				t.Fatalf(
					"result count = %d, want %d",
					len(verified.Signatures),
					test.wantResult,
				)
			}

			valid := 0
			for _, result := range verified.Signatures {
				if result.Valid() {
					valid++
				}
			}
			if valid != test.wantValid {
				t.Fatalf("valid count = %d, want %d", valid, test.wantValid)
			}
		})
	}
}
func TestMultiVerifierContinuesAfterInvalidSignature(t *testing.T) {
	fixture := newMultiFixture(t)
	raw := signMultiFixture(t, fixture, []byte("payload"))
	raw = corruptFirstJSONSignature(t, raw)

	verifier, err := NewMultiVerifierWithResolver(
		fixture.resolver,
		fixture.algorithms,
	)
	requireNoError(t, err)

	verified, err := verifier.VerifyMessage(context.Background(), raw)
	requireNoError(t, err)

	if len(verified.Signatures) != 2 {
		t.Fatalf("result count = %d, want 2", len(verified.Signatures))
	}
	if verified.Signatures[0].Valid() {
		t.Fatal("first signature unexpectedly valid")
	}
	requireErrorIs(t, verified.Signatures[0].Err, ErrVerify)
	if !verified.Signatures[1].Valid() {
		t.Fatalf("second signature error: %v", verified.Signatures[1].Err)
	}

	allVerifier, err := NewMultiVerifierWithResolver(
		fixture.resolver,
		fixture.algorithms,
		WithSignaturePolicy(RequireAllProvidedSignatures()),
	)
	requireNoError(t, err)

	_, err = allVerifier.VerifyMessage(context.Background(), raw)
	requireErrorIs(t, err, ErrVerificationPolicy)
	requireErrorIs(t, err, ErrVerify)
}
func TestMultiVerifierDistinguishesMissingKeysAndResolverFailures(t *testing.T) {
	fixture := newMultiFixture(t)
	raw := signMultiFixture(t, fixture, []byte("payload"))

	missingKeyResolver := newMapResolver(map[string]trustedKey{})
	verifier, err := NewMultiVerifierWithResolver(
		missingKeyResolver,
		fixture.algorithms,
	)
	requireNoError(t, err)

	_, err = verifier.VerifyMessage(context.Background(), raw)
	requireErrorIs(t, err, ErrVerificationPolicy)

	resolverFailure := errors.New("key store unavailable")
	failingResolver := KeyResolverFunc(func(
		context.Context,
		Header,
	) (ResolvedKey, error) {
		return ResolvedKey{}, resolverFailure
	})

	verifier, err = NewMultiVerifierWithResolver(
		failingResolver,
		fixture.algorithms,
	)
	requireNoError(t, err)

	_, err = verifier.VerifyMessage(context.Background(), raw)
	if !errors.Is(err, resolverFailure) {
		t.Fatalf("error = %v, want resolver failure", err)
	}

	nilKeyResolver := KeyResolverFunc(func(
		context.Context,
		Header,
	) (ResolvedKey, error) {
		return ResolvedKey{KeyID: "issuer"}, nil
	})

	verifier, err = NewMultiVerifierWithResolver(
		nilKeyResolver,
		fixture.algorithms,
	)
	requireNoError(t, err)

	_, err = verifier.VerifyMessage(context.Background(), raw)
	requireErrorIs(t, err, ErrVerify)
}
func TestMultiVerifierValidatesInput(t *testing.T) {
	secret := bytes.Repeat([]byte{0x84}, 32)

	_, err := NewMultiVerifierWithResolver(
		nil,
		[]jose.SignatureAlgorithm{jose.HS256},
	)
	requireErrorIs(t, err, ErrInvalidConfig)

	_, err = NewMultiVerifier(
		secret,
		nil,
	)
	requireErrorIs(t, err, ErrInvalidConfig)

	signer, err := NewMultiSigner([]SigningKey{
		{Algorithm: jose.HS256, Key: secret},
	})
	requireNoError(t, err)

	raw, err := signer.Sign([]byte("payload"))
	requireNoError(t, err)

	verifier, err := NewMultiVerifier(
		secret,
		[]jose.SignatureAlgorithm{jose.HS256},
	)
	requireNoError(t, err)

	_, err = verifier.VerifyMessage(context.Background(), "")
	requireErrorIs(t, err, ErrMissingToken)

	fixture := newMultiFixture(t)
	limited, err := NewMultiVerifierWithResolver(
		fixture.resolver,
		fixture.algorithms,
		WithMaxSignatures(1),
	)
	requireNoError(t, err)

	general := signMultiFixture(t, fixture, []byte("payload"))
	_, err = limited.VerifyMessage(context.Background(), general)
	requireErrorIs(t, err, ErrTooManySignatures)

	tokenLimited, err := NewMultiVerifier(
		secret,
		[]jose.SignatureAlgorithm{jose.HS256},
		WithMaxTokenSize(1),
	)
	requireNoError(t, err)
	_, err = tokenLimited.VerifyMessage(context.Background(), raw)
	requireErrorIs(t, err, ErrTokenTooLarge)
}
