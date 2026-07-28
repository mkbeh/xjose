package jws

import (
	"context"
	"fmt"

	"github.com/go-jose/go-jose/v4"
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

type jwkResolver struct {
	key jose.JSONWebKey
}

type jwksResolver struct {
	keysByID map[string][]jose.JSONWebKey
}

func newStaticResolver(key any) (KeyResolver, error) {
	if key == nil {
		return nil, fmt.Errorf(
			"%w: verification key is required",
			ErrInvalidConfig,
		)
	}

	switch key := key.(type) {
	case jose.JSONWebKey:
		return newJWKResolver(key)

	case *jose.JSONWebKey:
		if key == nil {
			return nil, fmt.Errorf(
				"%w: verification JWK is nil",
				ErrInvalidConfig,
			)
		}

		return newJWKResolver(*key)

	case jose.JSONWebKeySet:
		return newJWKSResolver(key), nil

	case *jose.JSONWebKeySet:
		if key == nil {
			return nil, fmt.Errorf(
				"%w: verification JWKS is nil",
				ErrInvalidConfig,
			)
		}

		return newJWKSResolver(*key), nil

	default:
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
}

func newJWKResolver(key jose.JSONWebKey) (KeyResolver, error) {
	key.Key = cloneKeyMaterial(key.Key)

	if key.Key == nil {
		return nil, fmt.Errorf(
			"%w: verification JWK key material is nil",
			ErrInvalidConfig,
		)
	}

	return jwkResolver{
		key: key,
	}, nil
}

func newJWKSResolver(set jose.JSONWebKeySet) KeyResolver {
	keysByID := make(
		map[string][]jose.JSONWebKey,
		len(set.Keys),
	)

	for _, key := range set.Keys {
		// Keys without an identity cannot participate in kid-based lookup.
		if key.KeyID == "" || key.Key == nil {
			continue
		}

		// A JWKS may contain both signature and encryption keys.
		if key.Use != "" && key.Use != keyUseSignature {
			continue
		}

		key.Key = cloneKeyMaterial(key.Key)

		keysByID[key.KeyID] = append(keysByID[key.KeyID], key)
	}

	return jwksResolver{
		keysByID: keysByID,
	}
}

func (resolver staticResolver) Resolve(_ context.Context, _ Header) (ResolvedKey, error) {
	return ResolvedKey{
		Key: resolver.key,
	}, nil
}

func (resolver jwkResolver) Resolve(_ context.Context, header Header) (ResolvedKey, error) {
	key := resolver.key

	if header.KeyID != "" && key.KeyID != "" && header.KeyID != key.KeyID {
		return ResolvedKey{}, fmt.Errorf(
			"%w: key ID %q not found",
			ErrKeyNotFound,
			header.KeyID,
		)
	}

	if key.Algorithm != "" && key.Algorithm != string(header.Algorithm) {
		return ResolvedKey{}, fmt.Errorf(
			"%w: key %q does not allow algorithm %q",
			ErrKeyNotFound,
			key.KeyID,
			header.Algorithm,
		)
	}

	if key.Use != "" && key.Use != keyUseSignature {
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

func (resolver jwksResolver) Resolve(_ context.Context, header Header) (ResolvedKey, error) {
	if header.KeyID == "" {
		return ResolvedKey{}, fmt.Errorf(
			"%w: protected kid header is required for JWKS",
			ErrKeyNotFound,
		)
	}

	candidates := resolver.keysByID[header.KeyID]

	var matchedKey *jose.JSONWebKey

	for index := range candidates {
		key := &candidates[index]

		// Ignore keys restricted to a different signature algorithm.
		if key.Algorithm != "" && key.Algorithm != string(header.Algorithm) {
			continue
		}

		// More than one applicable key makes resolution ambiguous.
		if matchedKey != nil {
			return ResolvedKey{}, fmt.Errorf(
				"%w: key ID %q matches multiple signature keys for algorithm %q",
				ErrInvalidConfig,
				header.KeyID,
				header.Algorithm,
			)
		}

		matchedKey = key
	}

	if matchedKey == nil {
		return ResolvedKey{}, fmt.Errorf(
			"%w: key ID %q has no matching signature key",
			ErrKeyNotFound,
			header.KeyID,
		)
	}

	return ResolvedKey{
		KeyID: matchedKey.KeyID,
		Key:   *matchedKey,
	}, nil
}
