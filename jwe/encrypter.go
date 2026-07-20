package jwe

import (
	"context"
	"fmt"

	"github.com/go-jose/go-jose/v4"
)

type Encrypter struct {
	recipient  jose.Recipient
	encryption jose.ContentEncryption
	config     config
}

func NewEncrypter(recipient jose.Recipient, encryption jose.ContentEncryption, options ...Option) (*Encrypter, error) {
	if recipient.Algorithm == "" || recipient.Key == nil || encryption == "" {
		return nil, fmt.Errorf("%w: recipient and encryption are required", ErrInvalidConfig)
	}
	c, err := makeConfig(options)
	if err != nil {
		return nil, err
	}
	e := &Encrypter{recipient: recipient, encryption: encryption, config: c}
	if _, err = e.backend(""); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalidConfig, err)
	}
	return e, nil
}
func (e *Encrypter) backend(contentType string) (jose.Encrypter, error) {
	opts := &jose.EncrypterOptions{ExtraHeaders: map[jose.HeaderKey]any{}}
	for k, v := range e.config.headers {
		opts.ExtraHeaders[k] = v
	}
	if e.config.typ != "" {
		opts.WithType(jose.ContentType(e.config.typ))
	}
	cty := e.config.cty
	if contentType != "" {
		cty = contentType
	}
	if cty != "" {
		opts.WithContentType(jose.ContentType(cty))
	}
	return jose.NewEncrypter(e.encryption, e.recipient, opts)
}
func (e *Encrypter) Encrypt(ctx context.Context, plaintext []byte) (string, error) {
	return e.encrypt(ctx, plaintext, "")
}
func (e *Encrypter) encrypt(ctx context.Context, plaintext []byte, cty string) (string, error) {
	if e == nil {
		return "", fmt.Errorf("%w: encrypter is nil", ErrInvalidConfig)
	}
	if err := ctx.Err(); err != nil {
		return "", err
	}
	if len(plaintext) == 0 {
		return "", ErrMissingPlaintext
	}
	if len(plaintext) > e.config.maxPlain {
		return "", ErrPlaintextTooLarge
	}
	backend, err := e.backend(cty)
	if err != nil {
		return "", fmt.Errorf("%w: %w", ErrEncrypt, err)
	}
	obj, err := backend.Encrypt(plaintext)
	if err != nil {
		return "", fmt.Errorf("%w: %w", ErrEncrypt, err)
	}
	raw, err := obj.CompactSerialize()
	if err != nil {
		return "", fmt.Errorf("%w: %w", ErrEncrypt, err)
	}
	if len(raw) > e.config.maxToken {
		return "", ErrTokenTooLarge
	}
	return raw, nil
}
