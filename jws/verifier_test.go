package jws

import (
	"bytes"
	"context"
	"testing"

	jose "github.com/go-jose/go-jose/v4"
)

func TestVerifierRejectsInvalidSignatureAndReturnsNilPayload(t *testing.T) {
	secret := bytes.Repeat([]byte{0x71}, 32)
	signer := newHMACSigner(t, secret, "verify-key")
	verifier := newHMACVerifier(t, secret, "verify-key")

	raw, err := signer.Sign([]byte("payload"))
	requireNoError(t, err)

	payload, err := verifier.Verify(
		context.Background(),
		corruptCompactSignature(raw),
	)
	requireErrorIs(t, err, ErrVerify)
	if payload != nil {
		t.Fatalf("payload = %q, want nil", payload)
	}
}

func TestVerifierValidatesInputLimits(t *testing.T) {
	secret := bytes.Repeat([]byte{0x72}, 32)
	signer := newHMACSigner(t, secret, "")
	raw, err := signer.Sign([]byte("payload"))
	requireNoError(t, err)

	verifier := newHMACVerifier(t, secret, "")

	_, err = verifier.VerifyMessage(context.Background(), "")
	requireErrorIs(t, err, ErrMissingToken)

	limited := newHMACVerifier(t, secret, "", WithMaxTokenSize(1))
	_, err = limited.VerifyMessage(context.Background(), raw)
	requireErrorIs(t, err, ErrTokenTooLarge)

	payloadLimited := newHMACVerifier(t, secret, "", WithMaxPayloadSize(3))
	_, err = payloadLimited.VerifyMessage(context.Background(), raw)
	requireErrorIs(t, err, ErrPayloadTooLarge)
}

func TestVerifierValidatesExpectedHeaders(t *testing.T) {
	secret := bytes.Repeat([]byte{0x73}, 32)
	signer := newHMACSigner(
		t,
		secret,
		"headers",
		WithType("actual+jws"),
		WithContentType("application/json"),
	)

	raw, err := signer.Sign([]byte("payload"))
	requireNoError(t, err)

	wrongType := newHMACVerifier(
		t,
		secret,
		"headers",
		WithType("expected+jws"),
	)
	_, err = wrongType.VerifyMessage(context.Background(), raw)
	requireErrorIs(t, err, ErrUnexpectedType)

	wrongContentType := newHMACVerifier(
		t,
		secret,
		"headers",
		WithContentType("application/cbor"),
	)
	_, err = wrongContentType.VerifyMessage(context.Background(), raw)
	requireErrorIs(t, err, ErrUnexpectedContentType)
}

func TestVerifierUsesResolver(t *testing.T) {
	secret := bytes.Repeat([]byte{0x74}, 32)
	signer := newHMACSigner(
		t,
		secret,
		"",
		WithHeader(headerKeyID, "header-key"),
	)

	raw, err := signer.Sign([]byte("payload"))
	requireNoError(t, err)

	resolver := KeyResolverFunc(func(
		_ context.Context,
		header Header,
	) (ResolvedKey, error) {
		if header.KeyID != "header-key" {
			return ResolvedKey{}, ErrKeyNotFound
		}

		return ResolvedKey{
			KeyID: "trusted-key",
			Key:   secret,
		}, nil
	})

	verifier, err := NewVerifierWithResolver(
		resolver,
		[]jose.SignatureAlgorithm{jose.HS256},
	)
	requireNoError(t, err)

	verified, err := verifier.VerifyMessage(context.Background(), raw)
	requireNoError(t, err)
	if verified.KeyID != "trusted-key" {
		t.Fatalf("KeyID = %q, want %q", verified.KeyID, "trusted-key")
	}
}

func TestVerifierRejectsNilResolvedKey(t *testing.T) {
	secret := bytes.Repeat([]byte{0x75}, 32)
	signer := newHMACSigner(t, secret, "nil-key")
	raw, err := signer.Sign([]byte("payload"))
	requireNoError(t, err)

	verifier, err := NewVerifierWithResolver(
		KeyResolverFunc(func(
			context.Context,
			Header,
		) (ResolvedKey, error) {
			return ResolvedKey{KeyID: "nil-key"}, nil
		}),
		[]jose.SignatureAlgorithm{jose.HS256},
	)
	requireNoError(t, err)

	_, err = verifier.VerifyMessage(context.Background(), raw)
	requireErrorIs(t, err, ErrVerify)
}

func TestVerifierClonesStaticVerificationKey(t *testing.T) {
	secret := bytes.Repeat([]byte{0x76}, 32)
	verificationSecret := bytes.Clone(secret)

	signer := newHMACSigner(t, secret, "")
	verifier := newHMACVerifier(t, verificationSecret, "")

	for index := range verificationSecret {
		verificationSecret[index] ^= 0xff
	}

	raw, err := signer.Sign([]byte("payload"))
	requireNoError(t, err)

	verified, err := verifier.VerifyMessage(context.Background(), raw)
	requireNoError(t, err)
	requireBytesEqual(t, verified.Payload, []byte("payload"))
}

func TestVerifierEnforcesAlgorithmAllowlist(t *testing.T) {
	secret := bytes.Repeat([]byte{0xb2}, 64)
	signer := newHMACSigner(t, secret, "")
	raw, err := signer.Sign([]byte("payload"))
	requireNoError(t, err)

	verifier, err := NewVerifier(
		secret,
		[]jose.SignatureAlgorithm{jose.HS512},
	)
	requireNoError(t, err)

	_, err = verifier.VerifyMessage(context.Background(), raw)
	requireErrorIs(t, err, ErrMalformedToken)
}
