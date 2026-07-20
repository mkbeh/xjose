package xjwt

import (
	"context"
	"fmt"

	"github.com/golang-jwt/jwt/v5"
)

type Signer struct {
	key    SigningKey
	config signerConfig
}

func NewSigner(key SigningKey, options ...SignerOption) (*Signer, error) {
	if key.method == nil || key.key == nil {
		return nil, fmt.Errorf("%w: signing key is uninitialized", ErrInvalidKey)
	}
	c := signerConfig{typ: "JWT", includeTyp: true, maxSize: DefaultMaxTokenSize}
	for _, o := range options {
		if o == nil {
			return nil, fmt.Errorf("%w: nil signer option", ErrInvalidConfig)
		}
		if err := o.applySigner(&c); err != nil {
			return nil, err
		}
	}
	return &Signer{key: key, config: c}, nil
}
func (s *Signer) Sign(ctx context.Context, claims jwt.Claims) (string, error) {
	if s == nil {
		return "", fmt.Errorf("%w: signer is nil", ErrInvalidConfig)
	}
	if err := ctx.Err(); err != nil {
		return "", err
	}
	if claims == nil {
		return "", fmt.Errorf("%w: claims are nil", ErrInvalidClaims)
	}
	token := jwt.NewWithClaims(s.key.method, claims)
	if s.config.includeTyp {
		token.Header["typ"] = s.config.typ
	} else {
		delete(token.Header, "typ")
	}
	if s.config.cty != "" {
		token.Header["cty"] = s.config.cty
	}
	if s.key.id != "" {
		token.Header["kid"] = s.key.id
	}
	var raw string
	var err error
	if ext, ok := s.key.method.(*externalMethod); ok {
		input, signErr := token.SigningString()
		if signErr != nil {
			return "", fmt.Errorf("%w: %v", ErrSign, signErr)
		}
		sig, signErr := ext.signWithContext(ctx, input)
		if signErr != nil {
			return "", fmt.Errorf("%w: %v", ErrSign, signErr)
		}
		raw = input + "." + token.EncodeSegment(sig)
	} else {
		raw, err = token.SignedString(s.key.key)
		if err != nil {
			return "", fmt.Errorf("%w: %w", ErrSign, err)
		}
	}
	if len(raw) > s.config.maxSize {
		return "", ErrTokenTooLarge
	}
	return raw, nil
}
