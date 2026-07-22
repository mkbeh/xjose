package jwe

import (
	"context"
	"testing"
)

func TestKeyResolverFunc(t *testing.T) {
	var nilResolver KeyResolverFunc
	_, err := nilResolver.Resolve(context.Background(), Header{})
	requireErrorIs(t, err, ErrInvalidConfig)

	want := []byte("key")
	resolver := KeyResolverFunc(func(ctx context.Context, header Header) (any, error) {
		if ctx == nil {
			t.Fatal("context is nil")
		}
		if header.KeyID != "kid" {
			t.Fatalf("key ID = %q, want kid", header.KeyID)
		}
		return want, nil
	})

	got, err := resolver.Resolve(context.Background(), Header{KeyID: "kid"})
	requireNoError(t, err)
	requireBytesEqual(t, got.([]byte), want)
}

func TestStaticResolver(t *testing.T) {
	key := []byte("key")
	got, err := (staticResolver{key: key}).Resolve(context.Background(), Header{})
	requireNoError(t, err)
	requireBytesEqual(t, got.([]byte), key)
}
