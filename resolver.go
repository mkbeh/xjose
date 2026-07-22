package xjwt

import (
	"context"
	"fmt"
)

// KeyResolver resolves a verification key using the protected JWT header.
type KeyResolver interface {
	Resolve(context.Context, Header) (VerificationKey, error)
}

// KeyResolverFunc adapts a function to KeyResolver.
type KeyResolverFunc func(context.Context, Header) (VerificationKey, error)

// Resolve implements KeyResolver.
func (f KeyResolverFunc) Resolve(ctx context.Context, header Header) (VerificationKey, error) {
	if f == nil {
		return VerificationKey{}, fmt.Errorf(
			"%w: key resolver function is nil",
			ErrInvalidConfig,
		)
	}

	return f(ctx, header)
}
