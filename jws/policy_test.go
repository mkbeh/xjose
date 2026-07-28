package jws

import (
	"bytes"
	"errors"
	"testing"

	"github.com/go-jose/go-jose/v4"
)

func TestSignaturePolicies(t *testing.T) {
	validA := SignatureResult{Index: 0, KeyID: "a"}
	validB := SignatureResult{Index: 1, KeyID: "b"}
	invalid := SignatureResult{
		Index: 2,
		KeyID: "c",
		Err:   ErrKeyNotFound,
	}

	requireNoError(t, RequireAnySignature().Evaluate([]SignatureResult{invalid, validA}))
	if err := RequireAnySignature().Evaluate([]SignatureResult{invalid}); err == nil {
		t.Fatal("RequireAnySignature unexpectedly accepted invalid results")
	}

	requireNoError(t, RequireAllProvidedSignatures().Evaluate([]SignatureResult{validA, validB}))
	err := RequireAllProvidedSignatures().Evaluate([]SignatureResult{validA, invalid})
	if !errors.Is(err, ErrKeyNotFound) {
		t.Fatalf("error = %v, want ErrKeyNotFound in chain", err)
	}

	requireNoError(t, RequireKeyIDs("a", "b").Evaluate([]SignatureResult{validA, validB}))
	if err := RequireKeyIDs("a", "b").Evaluate([]SignatureResult{validA}); err == nil {
		t.Fatal("RequireKeyIDs unexpectedly accepted a missing identity")
	}

	requireNoError(t, RequireThreshold(2, "a", "b", "c").Evaluate(
		[]SignatureResult{validA, validA, validB},
	))
	if err := RequireThreshold(2, "a", "b", "c").Evaluate(
		[]SignatureResult{validA, validA},
	); err == nil {
		t.Fatal("RequireThreshold counted a duplicate identity")
	}

	requireNoError(t, AllOf(
		RequireKeyIDs("a"),
		RequireThreshold(1, "b", "c"),
	).Evaluate([]SignatureResult{validA, validB}))
}

func TestSignaturePolicyValidation(t *testing.T) {
	secret := bytes.Repeat([]byte{0xa3}, 32)

	policies := []SignaturePolicy{
		RequireKeyIDs(),
		RequireKeyIDs("duplicate", "duplicate"),
		RequireThreshold(0, "a"),
		RequireThreshold(2, "a"),
		AllOf(),
		AllOf(RequireAnySignature(), nil),
	}

	for index, policy := range policies {
		_, err := NewMultiVerifier(
			secret,
			[]jose.SignatureAlgorithm{jose.HS256},
			WithSignaturePolicy(policy),
		)
		if !errors.Is(err, ErrInvalidConfig) {
			t.Errorf("policy %d error = %v, want ErrInvalidConfig", index, err)
		}
	}
}
