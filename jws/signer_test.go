package jws

import (
	"bytes"
	"context"
	"errors"
	"sync"
	"testing"

	jose "github.com/go-jose/go-jose/v4"
)

func TestSignerRoundTrip(t *testing.T) {
	payload := []byte(`{"document_id":"document-123","status":"approved"}`)

	for _, fixture := range testSigningFixtures(t) {
		fixture := fixture

		t.Run(fixture.name, func(t *testing.T) {
			signer, err := NewSigner(
				SigningKey{
					Algorithm: fixture.algorithm,
					KeyID:     fixture.keyID,
					Key:       fixture.signingKey,
				},
				WithType(testType),
				WithContentType(testContentType),
				WithHeader("tenant", "acme"),
			)
			requireNoError(t, err)

			raw, err := signer.Sign(payload)
			requireNoError(t, err)

			verifier, err := NewVerifier(
				fixture.verificationKey,
				[]jose.SignatureAlgorithm{fixture.algorithm},
				WithType(testType),
				WithContentType(testContentType),
			)
			requireNoError(t, err)

			verified, err := verifier.VerifyMessage(context.Background(), raw)
			requireNoError(t, err)

			requireBytesEqual(t, verified.Payload, payload)
			if verified.KeyID != fixture.keyID {
				t.Fatalf("KeyID = %q, want %q", verified.KeyID, fixture.keyID)
			}
			if verified.Header.Algorithm != fixture.algorithm {
				t.Fatalf("algorithm = %q, want %q", verified.Header.Algorithm, fixture.algorithm)
			}
			if verified.Header.Type != testType {
				t.Fatalf("type = %q, want %q", verified.Header.Type, testType)
			}
			if verified.Header.ContentType != testContentType {
				t.Fatalf("content type = %q, want %q", verified.Header.ContentType, testContentType)
			}
			if got := verified.Header.ExtraHeaders["tenant"]; got != "acme" {
				t.Fatalf("tenant header = %#v, want %q", got, "acme")
			}
		})
	}
}
func TestSignerDetachedRoundTrip(t *testing.T) {
	secret := bytes.Repeat([]byte{0x21}, 32)
	payload := []byte("exact document bytes\n")

	signer := newHMACSigner(
		t,
		secret,
		"detached-hmac",
		WithType(testType),
	)
	verifier := newHMACVerifier(
		t,
		secret,
		"detached-hmac",
		WithType(testType),
	)

	raw, err := signer.SignDetached(payload)
	requireNoError(t, err)

	parts := bytes.Split([]byte(raw), []byte("."))
	if len(parts) != 3 || len(parts[1]) != 0 {
		t.Fatalf("detached compact JWS = %q, want empty payload segment", raw)
	}

	verified, err := verifier.VerifyDetached(context.Background(), raw, payload)
	requireNoError(t, err)
	requireBytesEqual(t, verified.Payload, payload)

	_, err = verifier.VerifyDetached(
		context.Background(),
		raw,
		[]byte("different document bytes\n"),
	)
	requireErrorIs(t, err, ErrVerify)
}
func TestSignerValidatesReceiverAndPayload(t *testing.T) {
	secret := bytes.Repeat([]byte{0x33}, 32)

	var nilSigner *Signer
	_, err := nilSigner.Sign([]byte("payload"))
	requireErrorIs(t, err, ErrInvalidConfig)

	var zeroSigner Signer
	_, err = zeroSigner.Sign([]byte("payload"))
	requireErrorIs(t, err, ErrInvalidConfig)

	signer := newHMACSigner(t, secret, "", WithMaxPayloadSize(3))

	_, err = signer.Sign(nil)
	requireErrorIs(t, err, ErrMissingPayload)

	_, err = signer.Sign([]byte("four"))
	requireErrorIs(t, err, ErrPayloadTooLarge)

	smallTokenSigner := newHMACSigner(
		t,
		secret,
		"",
		WithMaxTokenSize(1),
	)
	_, err = smallTokenSigner.Sign([]byte("a"))
	requireErrorIs(t, err, ErrTokenTooLarge)
}
func TestSignerUsesKeySnapshot(t *testing.T) {
	secret := bytes.Repeat([]byte{0x44}, 32)
	original := bytes.Clone(secret)

	signer := newHMACSigner(t, secret, "snapshot")
	for index := range secret {
		secret[index] ^= 0xff
	}

	raw, err := signer.Sign([]byte("payload"))
	requireNoError(t, err)

	verifier := newHMACVerifier(t, original, "snapshot")
	_, err = verifier.VerifyMessage(context.Background(), raw)
	requireNoError(t, err)

	wrongVerifier := newHMACVerifier(t, secret, "snapshot")
	_, err = wrongVerifier.VerifyMessage(context.Background(), raw)
	requireErrorIs(t, err, ErrVerify)
}
func TestSignerWithHeaderSetsProtectedKeyID(t *testing.T) {
	secret := bytes.Repeat([]byte{0x55}, 32)

	signer := newHMACSigner(
		t,
		secret,
		"",
		WithHeader(headerKeyID, "signing-key"),
	)

	raw, err := signer.Sign([]byte("payload"))
	requireNoError(t, err)

	object := parseCompact(t, raw, jose.HS256)
	if got := object.Signatures[0].Protected.KeyID; got != "signing-key" {
		t.Fatalf("protected kid = %q, want %q", got, "signing-key")
	}
}
func TestSignerOpaqueSigner(t *testing.T) {
	opaque := newOpaqueEdSigner(t, "opaque-1")

	signer, err := NewSigner(SigningKey{
		Algorithm: jose.EdDSA,
		Key:       opaque,
	})
	requireNoError(t, err)

	raw, err := signer.Sign([]byte("first"))
	requireNoError(t, err)

	verifier, err := NewVerifier(
		opaque.publicKey,
		[]jose.SignatureAlgorithm{jose.EdDSA},
	)
	requireNoError(t, err)

	verified, err := verifier.VerifyMessage(context.Background(), raw)
	requireNoError(t, err)
	if verified.Header.KeyID != "opaque-1" {
		t.Fatalf("first kid = %q, want %q", verified.Header.KeyID, "opaque-1")
	}

	opaque.setKeyID("opaque-2")
	raw, err = signer.Sign([]byte("second"))
	requireNoError(t, err)

	verified, err = verifier.VerifyMessage(context.Background(), raw)
	requireNoError(t, err)
	if verified.Header.KeyID != "opaque-2" {
		t.Fatalf("second kid = %q, want %q", verified.Header.KeyID, "opaque-2")
	}

}
func TestSignerConcurrentUse(t *testing.T) {
	secret := bytes.Repeat([]byte{0x66}, 32)
	signer := newHMACSigner(t, secret, "concurrent")
	verifier := newHMACVerifier(t, secret, "concurrent")

	const workers = 32

	var wait sync.WaitGroup
	errorsChannel := make(chan error, workers)

	for worker := 0; worker < workers; worker++ {
		worker := worker
		wait.Add(1)

		go func() {
			defer wait.Done()

			payload := []byte{byte(worker), 0x01, 0x02, 0x03}
			raw, err := signer.Sign(payload)
			if err != nil {
				errorsChannel <- err
				return
			}

			verified, err := verifier.VerifyMessage(context.Background(), raw)
			if err != nil {
				errorsChannel <- err
				return
			}

			if !bytes.Equal(verified.Payload, payload) {
				errorsChannel <- errors.New("verified payload mismatch")
			}
		}()
	}

	wait.Wait()
	close(errorsChannel)

	for err := range errorsChannel {
		t.Errorf("concurrent sign/verify: %v", err)
	}
}
func TestSignerInteroperatesWithGoJose(t *testing.T) {
	secret := bytes.Repeat([]byte{0xb1}, 32)
	payload := []byte("interoperability payload")

	signer := newHMACSigner(t, secret, "interoperability")
	raw, err := signer.Sign(payload)
	requireNoError(t, err)

	object, err := jose.ParseSignedCompact(
		raw,
		[]jose.SignatureAlgorithm{jose.HS256},
	)
	requireNoError(t, err)

	verifiedPayload, err := object.Verify(secret)
	requireNoError(t, err)
	requireBytesEqual(t, verifiedPayload, payload)

	upstreamSigner, err := jose.NewSigner(
		jose.SigningKey{
			Algorithm: jose.HS256,
			Key:       secret,
		},
		(&jose.SignerOptions{}).WithHeader(
			headerKeyID,
			"interoperability",
		),
	)
	requireNoError(t, err)

	upstreamObject, err := upstreamSigner.Sign(payload)
	requireNoError(t, err)
	upstreamRaw, err := upstreamObject.CompactSerialize()
	requireNoError(t, err)

	verifier := newHMACVerifier(t, secret, "interoperability")
	verified, err := verifier.VerifyMessage(context.Background(), upstreamRaw)
	requireNoError(t, err)
	requireBytesEqual(t, verified.Payload, payload)
}
