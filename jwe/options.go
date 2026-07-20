package jwe

import (
	"fmt"

	"github.com/go-jose/go-jose/v4"
)

const (
	DefaultMaxTokenSize     = 32 << 10
	DefaultMaxPlaintextSize = 16 << 10
)

type Option interface{ apply(*config) error }
type config struct {
	typ, cty           string
	maxToken, maxPlain int
	headers            map[jose.HeaderKey]any
}
type typOption string

func WithType(v string) Option { return typOption(v) }
func (o typOption) apply(c *config) error {
	if o == "" {
		return fmt.Errorf("%w: typ is empty", ErrInvalidConfig)
	}
	c.typ = string(o)
	return nil
}

type ctyOption string

func WithContentType(v string) Option { return ctyOption(v) }
func (o ctyOption) apply(c *config) error {
	if o == "" {
		return fmt.Errorf("%w: cty is empty", ErrInvalidConfig)
	}
	c.cty = string(o)
	return nil
}

type sizeOption struct{ token, plain int }

func WithMaxTokenSize(v int) Option     { return sizeOption{token: v} }
func WithMaxPlaintextSize(v int) Option { return sizeOption{plain: v} }
func (o sizeOption) apply(c *config) error {
	if o.token < 0 || o.plain < 0 {
		return fmt.Errorf("%w: sizes must not be negative", ErrInvalidConfig)
	}
	if o.token > 0 {
		c.maxToken = o.token
	}
	if o.plain > 0 {
		c.maxPlain = o.plain
	}
	return nil
}

type headerOption struct {
	k jose.HeaderKey
	v any
}

func WithProtectedHeader(k jose.HeaderKey, v any) Option { return headerOption{k, v} }
func (o headerOption) apply(c *config) error {
	switch string(o.k) {
	case "alg", "enc", "kid", "typ", "cty", "crit", "zip":
		return fmt.Errorf("%w: protected header %q is reserved", ErrInvalidConfig, o.k)
	}
	if c.headers == nil {
		c.headers = map[jose.HeaderKey]any{}
	}
	c.headers[o.k] = o.v
	return nil
}
func makeConfig(opts []Option) (config, error) {
	c := config{maxToken: DefaultMaxTokenSize, maxPlain: DefaultMaxPlaintextSize}
	for _, o := range opts {
		if o == nil {
			return c, fmt.Errorf("%w: nil option", ErrInvalidConfig)
		}
		if err := o.apply(&c); err != nil {
			return c, err
		}
	}
	return c, nil
}
