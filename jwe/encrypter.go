package jwe

import (
	"bytes"
	"fmt"

	"github.com/go-jose/go-jose/v4"
)

// Encrypter encrypts plaintext as compact, single-recipient JWE.
//
// The recipient, content encryption algorithm, protected header options, and
// size limits are fixed when the Encrypter is created. A fresh go-jose backend
// is created for each encryption operation.
type Encrypter struct {
	recipient  jose.Recipient
	encryption jose.ContentEncryption
	config     config
}

// NewEncrypter creates an Encrypter for compact, single-recipient JWE.
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

	// Validate key and algorithm compatibility at construction time. The
	// backend is discarded because Encrypt creates a fresh instance for every
	// message.
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

// Encrypt encrypts non-empty plaintext and returns compact JWE serialization.
func (encrypter *Encrypter) Encrypt(plaintext []byte) (string, error) {
	if encrypter == nil {
		return "", fmt.Errorf(
			"%w: encrypter is uninitialized",
			ErrInvalidConfig,
		)
	}

	if err := validatePlaintext(plaintext, encrypter.config.maxPlaintextSize); err != nil {
		return "", err
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

	if err := validateRawTokenSize(raw, encrypter.config.maxTokenSize); err != nil {
		return "", err
	}

	return raw, nil
}
