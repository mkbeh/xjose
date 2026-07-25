package jwe

import (
	"fmt"

	"github.com/go-jose/go-jose/v4"
)

// MultiEncrypter encrypts one plaintext for one or more recipients using JWE
// JSON Serialization.
//
// One recipient produces Flattened JWE JSON Serialization. Multiple recipients
// produce General JWE JSON Serialization.
type MultiEncrypter struct {
	recipients []jose.Recipient
	encryption jose.ContentEncryption
	config     config
}

// NewMultiEncrypter creates a JWE JSON encrypter for one or more recipients.
func NewMultiEncrypter(
	recipients []jose.Recipient,
	encryption jose.ContentEncryption,
	options ...Option,
) (*MultiEncrypter, error) {
	if len(recipients) == 0 {
		return nil, fmt.Errorf(
			"%w: at least one recipient is required",
			ErrInvalidConfig,
		)
	}
	if encryption == "" {
		return nil, fmt.Errorf(
			"%w: content encryption algorithm is empty",
			ErrInvalidConfig,
		)
	}

	for index, recipient := range recipients {
		if recipient.Algorithm == "" || recipient.Key == nil {
			return nil, fmt.Errorf(
				"%w: recipient %d algorithm and key are required",
				ErrInvalidConfig,
				index,
			)
		}
	}

	config, err := makeConfig(options)
	if err != nil {
		return nil, err
	}

	encrypter := &MultiEncrypter{
		recipients: cloneRecipients(recipients),
		encryption: encryption,
		config:     config,
	}

	// Validate algorithms, keys, and options at construction time.
	//
	// go-jose also rejects dir and direct ECDH-ES because they cannot be
	// used in multi-recipient mode.
	if _, err := encrypter.createEncrypter(); err != nil {
		return nil, fmt.Errorf(
			"%w: create multi-encrypter: %w",
			ErrInvalidConfig,
			err,
		)
	}

	return encrypter, nil
}

// Encrypt encrypts plaintext and returns JWE JSON Serialization.
func (encrypter *MultiEncrypter) Encrypt(plaintext []byte) (string, error) {
	return encrypter.encrypt(plaintext, nil)
}

// EncryptWithAuthData encrypts plaintext with additional authenticated data
// and returns JWE JSON Serialization.
//
// Empty auth data is treated as absent. Auth data is authenticated but remains
// publicly visible in the serialized JWE object.
func (encrypter *MultiEncrypter) EncryptWithAuthData(plaintext, authData []byte) (string, error) {
	return encrypter.encrypt(plaintext, authData)
}

func (encrypter *MultiEncrypter) encrypt(plaintext, authData []byte) (string, error) {
	if encrypter == nil {
		return "", fmt.Errorf(
			"%w: multi-encrypter is uninitialized",
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

	if len(authData) > encrypter.config.maxTokenSize {
		return "", fmt.Errorf(
			"%w: authenticated data is %d bytes, token limit is %d",
			ErrTokenTooLarge,
			len(authData),
			encrypter.config.maxTokenSize,
		)
	}

	// go-jose distinguishes nil AAD from an empty non-nil slice.
	// Normalize empty AAD so it is omitted from JWE JSON Serialization.
	if len(authData) == 0 {
		authData = nil
	}

	backend, err := encrypter.createEncrypter()
	if err != nil {
		return "", fmt.Errorf(
			"%w: create multi-encrypter: %w",
			ErrEncrypt,
			err,
		)
	}

	object, err := backend.EncryptWithAuthData(plaintext, authData)
	if err != nil {
		return "", fmt.Errorf(
			"%w: encrypt JWE JSON: %w",
			ErrEncrypt,
			err,
		)
	}

	raw := object.FullSerialize()

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

func (encrypter *MultiEncrypter) createEncrypter() (jose.Encrypter, error) {
	options := &jose.EncrypterOptions{
		Compression: encrypter.config.compression,
	}

	for name, value := range encrypter.config.extraHeaders {
		options.WithHeader(name, value)
	}

	if encrypter.config.typ != "" {
		options.WithType(
			jose.ContentType(encrypter.config.typ),
		)
	}

	if encrypter.config.cty != "" {
		options.WithContentType(
			jose.ContentType(encrypter.config.cty),
		)
	}

	return jose.NewMultiEncrypter(
		encrypter.encryption,
		encrypter.recipients,
		options,
	)
}

func cloneRecipients(recipients []jose.Recipient) []jose.Recipient {
	cloned := make([]jose.Recipient, len(recipients))

	for index, recipient := range recipients {
		cloned[index] = recipient
		cloned[index].Key = cloneKeyMaterial(recipient.Key)
		cloned[index].PBES2Salt = append([]byte(nil), recipient.PBES2Salt...)
	}

	return cloned
}
