package xjwt

import (
	"context"
	"fmt"
)

// KeyResolver selects a verification key from an untrusted JOSE header.
// Implementations may use local state, files, application-managed caches, or
// remote services. xjwt itself performs no I/O.
type KeyResolver interface {
	Resolve(ctx context.Context, header Header) (VerificationKey, error)
}

// KeyResolverFunc adapts a function to KeyResolver.
type KeyResolverFunc func(ctx context.Context, header Header) (VerificationKey, error)

// Resolve calls f with ctx and header.
func (f KeyResolverFunc) Resolve(ctx context.Context, header Header) (VerificationKey, error) {
	if f == nil {
		return VerificationKey{}, ErrInvalidConfig
	}
	return f(ctx, header)
}

// Resolve allows a single VerificationKey to be used directly as a resolver.
// The token alg and kid must match the key binding exactly.
func (k VerificationKey) Resolve(ctx context.Context, header Header) (VerificationKey, error) {
	if err := ctx.Err(); err != nil {
		return VerificationKey{}, err
	}
	if k.value == nil {
		return VerificationKey{}, fmt.Errorf("%w: verification key is not initialized", ErrInvalidKey)
	}
	if k.algorithm != header.Algorithm {
		return VerificationKey{}, fmt.Errorf(
			"%w: key uses %s, token uses %s",
			ErrUnexpectedAlgorithm,
			k.algorithm,
			header.Algorithm,
		)
	}
	switch {
	case k.id == "" && header.KeyID != "":
		return VerificationKey{}, fmt.Errorf("%w: anonymous key does not accept kid %q", ErrUnknownKey, header.KeyID)
	case k.id != "" && header.KeyID == "":
		return VerificationKey{}, ErrMissingKeyID
	case k.id != header.KeyID:
		return VerificationKey{}, fmt.Errorf("%w: %q", ErrUnknownKey, header.KeyID)
	default:
		return k.clone(), nil
	}
}
