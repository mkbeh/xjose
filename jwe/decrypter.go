package jwe

import (
	"context"
	"fmt"
	"strings"

	"github.com/go-jose/go-jose/v4"
)

type Header struct {
	Algorithm   string
	KeyID       string
	Type        string
	ContentType string
}
type Decrypted struct {
	Header    Header
	Plaintext []byte
}
type KeyResolver interface {
	Resolve(context.Context, Header) (any, error)
}
type KeyResolverFunc func(context.Context, Header) (any, error)

func (f KeyResolverFunc) Resolve(ctx context.Context, h Header) (any, error) { return f(ctx, h) }

type staticResolver struct{ key any }

func (s staticResolver) Resolve(context.Context, Header) (any, error) { return s.key, nil }

type Decrypter struct {
	resolver    KeyResolver
	algorithms  []jose.KeyAlgorithm
	encryptions []jose.ContentEncryption
	config      config
}

func NewDecrypter(key any, algorithms []jose.KeyAlgorithm, encryptions []jose.ContentEncryption, options ...Option) (*Decrypter, error) {
	return NewDecrypterWithResolver(staticResolver{key}, algorithms, encryptions, options...)
}
func NewDecrypterWithResolver(resolver KeyResolver, algorithms []jose.KeyAlgorithm, encryptions []jose.ContentEncryption, options ...Option) (*Decrypter, error) {
	if resolver == nil || len(algorithms) == 0 || len(encryptions) == 0 {
		return nil, fmt.Errorf("%w: resolver and algorithm allowlists are required", ErrInvalidConfig)
	}
	c, err := makeConfig(options)
	if err != nil {
		return nil, err
	}
	return &Decrypter{resolver: resolver, algorithms: append([]jose.KeyAlgorithm(nil), algorithms...), encryptions: append([]jose.ContentEncryption(nil), encryptions...), config: c}, nil
}
func (d *Decrypter) Decrypt(ctx context.Context, raw string) ([]byte, error) {
	v, err := d.DecryptToken(ctx, raw)
	return v.Plaintext, err
}
func (d *Decrypter) DecryptToken(ctx context.Context, raw string) (Decrypted, error) {
	var zero Decrypted
	if d == nil {
		return zero, fmt.Errorf("%w: decrypter is nil", ErrInvalidConfig)
	}
	if err := ctx.Err(); err != nil {
		return zero, err
	}
	if raw == "" {
		return zero, ErrMissingToken
	}
	if len(raw) > d.config.maxToken {
		return zero, ErrTokenTooLarge
	}
	if strings.Count(raw, ".") != 4 {
		return zero, ErrMalformedToken
	}
	obj, err := jose.ParseEncryptedCompact(raw, d.algorithms, d.encryptions)
	if err != nil {
		return zero, fmt.Errorf("%w: %w", ErrMalformedToken, err)
	}
	h := Header{Algorithm: obj.Header.Algorithm, KeyID: obj.Header.KeyID}
	if v, ok := obj.Header.ExtraHeaders[jose.HeaderType].(string); ok {
		h.Type = v
	}
	if v, ok := obj.Header.ExtraHeaders[jose.HeaderContentType].(string); ok {
		h.ContentType = v
	}
	if d.config.typ != "" && h.Type != d.config.typ {
		return zero, ErrUnexpectedType
	}
	if d.config.cty != "" && h.ContentType != d.config.cty {
		return zero, ErrUnexpectedContentType
	}
	key, err := d.resolver.Resolve(ctx, h)
	if err != nil {
		return zero, err
	}
	plaintext, err := obj.Decrypt(key)
	if err != nil {
		return zero, fmt.Errorf("%w: %w", ErrDecrypt, err)
	}
	if len(plaintext) > d.config.maxPlain {
		return zero, ErrPlaintextTooLarge
	}
	return Decrypted{Header: h, Plaintext: plaintext}, nil
}
