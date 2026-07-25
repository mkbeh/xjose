package jwt

import (
	"context"
	"fmt"

	"github.com/golang-jwt/jwt/v5"
)

// DefaultMaxTokenSize is the default maximum compact JWT size accepted.
const DefaultMaxTokenSize = 16 << 10

type Signer struct {
	key    SigningKey
	config signerConfig
}

func NewSigner(key SigningKey, options ...SignerOption) (*Signer, error) {
	if err := key.validate(); err != nil {
		return nil, err
	}

	c := signerConfig{
		typ:        "JWT",
		includeTyp: true,
		maxSize:    DefaultMaxTokenSize,
	}

	for _, option := range options {
		if option == nil {
			return nil, fmt.Errorf("%w: nil signer option", ErrInvalidConfig)
		}
		if err := option.applySigner(&c); err != nil {
			return nil, err
		}
	}

	return &Signer{
		key:    key,
		config: c,
	}, nil
}

func (s *Signer) Sign(ctx context.Context, claims jwt.Claims) (string, error) {
	if s == nil {
		return "", fmt.Errorf("%w: signer is nil", ErrInvalidConfig)
	}
	if ctx == nil {
		return "", fmt.Errorf("%w: context is nil", ErrInvalidConfig)
	}
	if claims == nil {
		return "", fmt.Errorf("%w: claims are nil", ErrInvalidClaims)
	}

	token := jwt.NewWithClaims(s.key.method, claims)
	s.applyHeaders(token)

	input, err := token.SigningString()
	if err != nil {
		return "", fmt.Errorf("%w: %w", ErrSign, err)
	}

	signature, err := s.key.signInput(ctx, input)
	if err != nil {
		return "", fmt.Errorf("%w: %w", ErrSign, err)
	}

	if len(signature) == 0 {
		return "", fmt.Errorf(
			"%w: %w: signing method returned an empty signature",
			ErrSign,
			ErrInvalidSignature,
		)
	}

	encodedSignature := token.EncodeSegment(signature)

	if len(input)+1+len(encodedSignature) > s.config.maxSize {
		return "", ErrTokenTooLarge
	}

	return input + "." + encodedSignature, nil
}

func (s *Signer) applyHeaders(token *jwt.Token) {
	if s.config.includeTyp {
		token.Header[headerParamType] = s.config.typ
	} else {
		delete(token.Header, headerParamType)
	}

	if s.key.id != "" {
		token.Header[headerParamKeyID] = s.key.id
	}
}
