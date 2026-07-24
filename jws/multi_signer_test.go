package jws

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"testing"

	jose "github.com/go-jose/go-jose/v4"
)

func TestMultiSignerProducesFlattenedAndGeneralSerialization(t *testing.T) {
	secret := bytes.Repeat([]byte{0x81}, 32)

	flattenedSigner, err := NewMultiSigner([]SigningKey{
		{
			Algorithm: jose.HS256,
			KeyID:     "flattened",
			Key:       secret,
		},
	})
	requireNoError(t, err)

	flattened, err := flattenedSigner.Sign([]byte("payload"))
	requireNoError(t, err)

	var flattenedObject map[string]json.RawMessage
	requireNoError(t, json.Unmarshal([]byte(flattened), &flattenedObject))
	if _, exists := flattenedObject["signature"]; !exists {
		t.Fatal("flattened JWS has no signature member")
	}
	if _, exists := flattenedObject["signatures"]; exists {
		t.Fatal("flattened JWS unexpectedly has signatures member")
	}

	flattenedVerifier, err := NewMultiVerifier(
		jose.JSONWebKey{
			Key:       secret,
			KeyID:     "flattened",
			Algorithm: string(jose.HS256),
			Use:       "sig",
		},
		[]jose.SignatureAlgorithm{jose.HS256},
	)
	requireNoError(t, err)

	verified, err := flattenedVerifier.VerifyMessage(
		context.Background(),
		flattened,
	)
	requireNoError(t, err)
	requireBytesEqual(t, verified.Payload, []byte("payload"))

	fixture := newMultiFixture(t)
	general := signMultiFixture(t, fixture, []byte("payload"))

	var generalObject struct {
		Signatures []json.RawMessage `json:"signatures"`
	}
	requireNoError(t, json.Unmarshal([]byte(general), &generalObject))
	if len(generalObject.Signatures) != 2 {
		t.Fatalf("signature count = %d, want 2", len(generalObject.Signatures))
	}
}
func TestMultiSignerValidatesInput(t *testing.T) {
	secret := bytes.Repeat([]byte{0x82}, 32)

	_, err := NewMultiSigner(nil)
	requireErrorIs(t, err, ErrInvalidConfig)

	_, err = NewMultiSigner(
		[]SigningKey{
			{Algorithm: jose.HS256, Key: secret},
			{Algorithm: jose.HS512, Key: secret},
		},
		WithMaxSignatures(1),
	)
	requireErrorIs(t, err, ErrTooManySignatures)

	signer, err := NewMultiSigner([]SigningKey{
		{Algorithm: jose.HS256, Key: secret},
	})
	requireNoError(t, err)

	_, err = signer.Sign(nil)
	requireErrorIs(t, err, ErrMissingPayload)

	var nilSigner *MultiSigner
	_, err = nilSigner.Sign([]byte("payload"))
	requireErrorIs(t, err, ErrInvalidConfig)
}
func TestMultiSignerSupportsOpaqueSigners(t *testing.T) {
	issuer := newOpaqueEdSigner(t, "issuer-opaque")
	approval := newOpaqueEdSigner(t, "approval-opaque")

	signer, err := NewMultiSigner([]SigningKey{
		{Algorithm: jose.EdDSA, Key: issuer},
		{Algorithm: jose.EdDSA, Key: approval},
	})
	requireNoError(t, err)

	raw, err := signer.Sign([]byte("payload"))
	requireNoError(t, err)

	resolver := newMapResolver(map[string]trustedKey{
		"issuer-opaque": {
			algorithm: jose.EdDSA,
			key:       issuer.publicKey,
		},
		"approval-opaque": {
			algorithm: jose.EdDSA,
			key:       approval.publicKey,
		},
	})

	verifier, err := NewMultiVerifierWithResolver(
		resolver,
		[]jose.SignatureAlgorithm{jose.EdDSA},
		WithSignaturePolicy(
			RequireKeyIDs("issuer-opaque", "approval-opaque"),
		),
	)
	requireNoError(t, err)

	verified, err := verifier.VerifyMessage(context.Background(), raw)
	requireNoError(t, err)
	if len(verified.Signatures) != 2 {
		t.Fatalf("signature count = %d, want 2", len(verified.Signatures))
	}
}
func TestMultiSignerConcurrentUse(t *testing.T) {
	secret := bytes.Repeat([]byte{0x83}, 64)

	signer, err := NewMultiSigner([]SigningKey{
		{Algorithm: jose.HS256, Key: secret},
		{Algorithm: jose.HS512, Key: secret},
	})
	requireNoError(t, err)

	verifier, err := NewMultiVerifier(
		secret,
		[]jose.SignatureAlgorithm{jose.HS256, jose.HS512},
		WithSignaturePolicy(RequireAllProvidedSignatures()),
	)
	requireNoError(t, err)

	const workers = 24
	var wait sync.WaitGroup
	errorsChannel := make(chan error, workers)

	for worker := 0; worker < workers; worker++ {
		worker := worker
		wait.Add(1)

		go func() {
			defer wait.Done()

			payload := []byte(fmt.Sprintf("payload-%d", worker))
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
		t.Errorf("concurrent multi sign/verify: %v", err)
	}
}
