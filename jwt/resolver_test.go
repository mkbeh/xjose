package jwt

import (
	"context"
	"testing"

	"github.com/golang-jwt/jwt/v5"
)

func TestKeyResolverFunc(t *testing.T) {
	var nilResolver KeyResolverFunc
	_, err := nilResolver.Resolve(testContext(), Header{})
	requireErrorIs(t, err, ErrInvalidConfig)

	key, err := NewVerificationKey("key-1", jwt.SigningMethodHS256, testHMACSecret())
	requireNoError(t, err)

	resolver := KeyResolverFunc(func(_ context.Context, header Header) (VerificationKey, error) {
		if header.KeyID != "key-1" {
			t.Fatalf("header key ID = %q", header.KeyID)
		}
		return key, nil
	})

	resolved, err := resolver.Resolve(testContext(), Header{KeyID: "key-1"})
	requireNoError(t, err)
	if resolved.ID() != "key-1" {
		t.Fatalf("resolved ID = %q", resolved.ID())
	}
}
