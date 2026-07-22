package jwe

import (
	"context"
	"fmt"
)

// KeyResolver resolves a JWE decryption key using protected header
// parameters.
//
// The header has not been authenticated when Resolve is called and must be
// treated only as an untrusted key-selection input.
//
// Slice-backed keys returned by Resolve must not be mutated while they may be
// used by the decrypter. RSA, ECDSA and custom key objects must be immutable.
type KeyResolver interface {
	Resolve(context.Context, Header) (any, error)
}

// KeyResolverFunc adapts a function to KeyResolver.
type KeyResolverFunc func(context.Context, Header) (any, error)

// Resolve implements KeyResolver.
func (resolver KeyResolverFunc) Resolve(ctx context.Context, header Header) (any, error) {
	if resolver == nil {
		return nil, fmt.Errorf(
			"%w: key resolver function is nil",
			ErrInvalidConfig,
		)
	}

	return resolver(ctx, header)
}

type staticResolver struct {
	key any
}

func (resolver staticResolver) Resolve(context.Context, Header) (any, error) {
	return resolver.key, nil
}
