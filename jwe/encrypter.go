package jwe

import (
	"bytes"
	"fmt"

	"github.com/go-jose/go-jose/v4"
)

type Encrypter struct {
	recipient  jose.Recipient
	encryption jose.ContentEncryption
	config     config
}

func NewEncrypter(
	recipient jose.Recipient,
	encryption jose.ContentEncryption,
	options ...Option,
) (*Encrypter, error) {
	if recipient.Algorithm == "" {
		return nil, fmt.Errorf(
			"%w: key management algorithm is required",
			ErrInvalidConfig,
		)
	}

	if recipient.Key == nil {
		return nil, fmt.Errorf(
			"%w: recipient key is required",
			ErrInvalidConfig,
		)
	}

	if encryption == "" {
		return nil, fmt.Errorf(
			"%w: content encryption algorithm is required",
			ErrInvalidConfig,
		)
	}

	recipient.Key = cloneKeyMaterial(recipient.Key)
	recipient.PBES2Salt = bytes.Clone(recipient.PBES2Salt)

	config, err := makeConfig(options)
	if err != nil {
		return nil, err
	}

	// Validate the complete JOSE configuration at construction time. A fresh
	// backend is created for each Encrypt call because some go-jose encrypters
	// contain mutable per-message state.
	if _, err := newEncrypter(recipient, encryption, config); err != nil {
		return nil, fmt.Errorf(
			"%w: create encrypter: %w",
			ErrInvalidConfig,
			err,
		)
	}

	return &Encrypter{
		recipient:  recipient,
		encryption: encryption,
		config:     config,
	}, nil
}

func newEncrypter(
	recipient jose.Recipient,
	encryption jose.ContentEncryption,
	config config,
) (jose.Encrypter, error) {
	options := &jose.EncrypterOptions{
		Compression: config.compression,
	}

	if config.typ != "" {
		options.WithType(
			jose.ContentType(config.typ),
		)
	}

	if config.cty != "" {
		options.WithContentType(
			jose.ContentType(config.cty),
		)
	}

	for name, value := range config.extraHeaders {
		options.WithHeader(name, value)
	}

	return jose.NewEncrypter(encryption, recipient, options)
}

func (encrypter *Encrypter) Encrypt(plaintext []byte) (string, error) {
	if encrypter == nil {
		return "", fmt.Errorf(
			"%w: encrypter is uninitialized",
			ErrInvalidConfig,
		)
	}

	if len(plaintext) == 0 {
		return "", ErrMissingPlaintext
	}

	if len(plaintext) > encrypter.config.maxPlaintextSize {
		return "", fmt.Errorf(
			"%w: got %d bytes, limit is %d",
			ErrPlaintextTooLarge,
			len(plaintext),
			encrypter.config.maxPlaintextSize,
		)
	}

	backend, err := newEncrypter(encrypter.recipient, encrypter.encryption, encrypter.config)
	if err != nil {
		return "", fmt.Errorf(
			"%w: create encrypter: %w",
			ErrEncrypt,
			err,
		)
	}

	object, err := backend.Encrypt(plaintext)
	if err != nil {
		return "", fmt.Errorf(
			"%w: encrypt plaintext: %w",
			ErrEncrypt,
			err,
		)
	}

	raw, err := object.CompactSerialize()
	if err != nil {
		return "", fmt.Errorf(
			"%w: serialize compact JWE: %w",
			ErrEncrypt,
			err,
		)
	}

	if len(raw) > encrypter.config.maxTokenSize {
		return "", fmt.Errorf(
			"%w: got %d bytes, limit is %d",
			ErrTokenTooLarge,
			len(raw),
			encrypter.config.maxTokenSize,
		)
	}

	return raw, nil
}
