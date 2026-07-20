package xjwt

import "context"

type KeyResolver interface {
	Resolve(context.Context, Header) (VerificationKey, error)
}
type KeyResolverFunc func(context.Context, Header) (VerificationKey, error)

func (f KeyResolverFunc) Resolve(ctx context.Context, h Header) (VerificationKey, error) {
	return f(ctx, h)
}
