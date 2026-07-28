package jws

import (
	"bytes"
	"context"
	"testing"

	"github.com/go-jose/go-jose/v4"
)

func TestStaticResolverJWKAndJWKS(t *testing.T) {
	secret := bytes.Repeat([]byte{0x93}, 32)
	jwk := jose.JSONWebKey{
		Key:       secret,
		KeyID:     "key-1",
		Algorithm: string(jose.HS256),
		Use:       "sig",
	}

	resolver, err := newStaticResolver(jwk)
	requireNoError(t, err)

	resolved, err := resolver.Resolve(context.Background(), Header{
		Algorithm: jose.HS256,
		KeyID:     "key-1",
	})
	requireNoError(t, err)
	if resolved.KeyID != "key-1" {
		t.Fatalf("KeyID = %q, want %q", resolved.KeyID, "key-1")
	}

	_, err = resolver.Resolve(context.Background(), Header{
		Algorithm: jose.HS256,
		KeyID:     "missing",
	})
	requireErrorIs(t, err, ErrKeyNotFound)

	_, err = resolver.Resolve(context.Background(), Header{
		Algorithm: jose.HS512,
		KeyID:     "key-1",
	})
	requireErrorIs(t, err, ErrKeyNotFound)

	setResolver, err := newStaticResolver(jose.JSONWebKeySet{
		Keys: []jose.JSONWebKey{jwk},
	})
	requireNoError(t, err)

	_, err = setResolver.Resolve(context.Background(), Header{
		Algorithm: jose.HS256,
	})
	requireErrorIs(t, err, ErrKeyNotFound)

	resolved, err = setResolver.Resolve(context.Background(), Header{
		Algorithm: jose.HS256,
		KeyID:     "key-1",
	})
	requireNoError(t, err)
	if resolved.KeyID != "key-1" {
		t.Fatalf("KeyID = %q, want %q", resolved.KeyID, "key-1")
	}
}

func TestStaticResolverRejectsAmbiguousJWKS(t *testing.T) {
	secret := bytes.Repeat([]byte{0x94}, 32)
	set := jose.JSONWebKeySet{
		Keys: []jose.JSONWebKey{
			{
				Key:       bytes.Clone(secret),
				KeyID:     "duplicate",
				Algorithm: string(jose.HS256),
				Use:       "sig",
			},
			{
				Key:       bytes.Clone(secret),
				KeyID:     "duplicate",
				Algorithm: string(jose.HS256),
				Use:       "sig",
			},
		},
	}

	resolver, err := newStaticResolver(set)
	requireNoError(t, err)

	_, err = resolver.Resolve(context.Background(), Header{
		Algorithm: jose.HS256,
		KeyID:     "duplicate",
	})
	requireErrorIs(t, err, ErrInvalidConfig)
}

func TestStaticResolverUsesKeySnapshot(t *testing.T) {
	secret := bytes.Repeat([]byte{0x95}, 32)
	original := bytes.Clone(secret)

	resolver, err := newStaticResolver(secret)
	requireNoError(t, err)

	for index := range secret {
		secret[index] ^= 0xff
	}

	resolved, err := resolver.Resolve(context.Background(), Header{
		Algorithm: jose.HS256,
	})
	requireNoError(t, err)

	resolvedSecret, ok := resolved.Key.([]byte)
	if !ok {
		t.Fatalf("resolved key type = %T, want []byte", resolved.Key)
	}
	requireBytesEqual(t, resolvedSecret, original)
}

func TestResolversRejectNilValues(t *testing.T) {
	_, err := newStaticResolver(nil)
	requireErrorIs(t, err, ErrInvalidConfig)

	var nilJWK *jose.JSONWebKey
	_, err = newStaticResolver(nilJWK)
	requireErrorIs(t, err, ErrInvalidConfig)

	var resolver KeyResolverFunc
	_, err = resolver.Resolve(context.Background(), Header{})
	requireErrorIs(t, err, ErrInvalidConfig)
}
