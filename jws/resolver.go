package jws

import (
	"context"
	"fmt"

	jose "github.com/go-jose/go-jose/v4"
)

// ResolvedKey contains trusted verification key material and its canonical
// identity.
//
// KeyID is supplied by the trusted resolver and is used by identity-based
// signature policies. It must not be copied from an unverified JWS header
// unless the resolver has first mapped that value to application-controlled
// key material.
type ResolvedKey struct {
	KeyID string
	Key   any
}

// KeyResolver resolves trusted verification key material for a protected JWS
// header.
//
// Header values are authenticated only after the returned key successfully
// verifies the corresponding signature. Implementations must therefore treat
// them only as untrusted key-selection hints.
type KeyResolver interface {
	Resolve(ctx context.Context, header Header) (ResolvedKey, error)
}

// KeyResolverFunc adapts a function to KeyResolver.
type KeyResolverFunc func(ctx context.Context, header Header) (ResolvedKey, error)

// Resolve calls resolver(ctx, header).
func (resolver KeyResolverFunc) Resolve(ctx context.Context, header Header) (ResolvedKey, error) {
	if resolver == nil {
		return ResolvedKey{}, fmt.Errorf(
			"%w: key resolver function is nil",
			ErrInvalidConfig,
		)
	}

	return resolver(ctx, header)
}

type staticResolver struct {
	key any
}

func newStaticResolver(key any) (KeyResolver, error) {
	if key == nil {
		return nil, fmt.Errorf(
			"%w: verification key is required",
			ErrInvalidConfig,
		)
	}

	key = cloneKeyMaterial(key)
	if key == nil {
		return nil, fmt.Errorf(
			"%w: verification key is nil",
			ErrInvalidConfig,
		)
	}

	return staticResolver{
		key: key,
	}, nil
}

func (resolver staticResolver) Resolve(_ context.Context, header Header) (ResolvedKey, error) {
	switch key := resolver.key.(type) {
	case jose.JSONWebKey:
		return resolveJWK(key, header)

	case *jose.JSONWebKey:
		if key == nil {
			return ResolvedKey{}, fmt.Errorf(
				"%w: verification JWK is nil",
				ErrInvalidConfig,
			)
		}

		return resolveJWK(*key, header)

	case jose.JSONWebKeySet:
		return resolveJWKS(&key, header)

	case *jose.JSONWebKeySet:
		if key == nil {
			return ResolvedKey{}, fmt.Errorf(
				"%w: verification JWKS is nil",
				ErrInvalidConfig,
			)
		}

		return resolveJWKS(key, header)

	default:
		return ResolvedKey{
			Key: key,
		}, nil
	}
}

func resolveJWK(key jose.JSONWebKey, header Header) (ResolvedKey, error) {
	if key.Key == nil {
		return ResolvedKey{}, fmt.Errorf(
			"%w: verification JWK key material is nil",
			ErrInvalidConfig,
		)
	}

	if header.KeyID != "" &&
		key.KeyID != "" &&
		header.KeyID != key.KeyID {
		return ResolvedKey{}, fmt.Errorf(
			"%w: key ID %q not found",
			ErrKeyNotFound,
			header.KeyID,
		)
	}

	if key.Algorithm != "" &&
		key.Algorithm != string(header.Algorithm) {
		return ResolvedKey{}, fmt.Errorf(
			"%w: key %q does not allow algorithm %q",
			ErrKeyNotFound,
			key.KeyID,
			header.Algorithm,
		)
	}

	if key.Use != "" && key.Use != "sig" {
		return ResolvedKey{}, fmt.Errorf(
			"%w: key %q is not a signature key",
			ErrKeyNotFound,
			key.KeyID,
		)
	}

	return ResolvedKey{
		KeyID: key.KeyID,
		Key:   key,
	}, nil
}

func resolveJWKS(set *jose.JSONWebKeySet, header Header) (ResolvedKey, error) {
	if header.KeyID == "" {
		return ResolvedKey{}, fmt.Errorf(
			"%w: protected kid header is required for JWKS",
			ErrKeyNotFound,
		)
	}

	var matched *jose.JSONWebKey

	for index := range set.Keys {
		key := &set.Keys[index]

		if key.KeyID != header.KeyID {
			continue
		}

		if key.Key == nil {
			continue
		}

		if key.Algorithm != "" &&
			key.Algorithm != string(header.Algorithm) {
			continue
		}

		if key.Use != "" && key.Use != "sig" {
			continue
		}

		if matched != nil {
			return ResolvedKey{}, fmt.Errorf(
				"%w: key ID %q matches multiple signature keys for algorithm %q",
				ErrInvalidConfig,
				header.KeyID,
				header.Algorithm,
			)
		}

		matched = key
	}

	if matched == nil {
		return ResolvedKey{}, fmt.Errorf(
			"%w: key ID %q has no matching signature key",
			ErrKeyNotFound,
			header.KeyID,
		)
	}

	return ResolvedKey{
		KeyID: matched.KeyID,
		Key:   *matched,
	}, nil
}
