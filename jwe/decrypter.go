package jwe

import (
	"context"
	"fmt"

	"github.com/go-jose/go-jose/v4"
)

// Decrypted contains authenticated JWE header parameters and plaintext.
type Decrypted struct {
	Header    Header
	Plaintext []byte
}

type Decrypter struct {
	resolver           KeyResolver
	keyAlgorithms      []jose.KeyAlgorithm
	contentEncryptions []jose.ContentEncryption
	config             config
}

// NewDecrypter creates a decrypter using one static decryption key.
func NewDecrypter(
	key any,
	keyAlgorithms []jose.KeyAlgorithm,
	contentEncryptions []jose.ContentEncryption,
	options ...Option,
) (*Decrypter, error) {
	if key == nil {
		return nil, fmt.Errorf(
			"%w: decryption key is nil",
			ErrInvalidConfig,
		)
	}

	return NewDecrypterWithResolver(
		staticResolver{
			key: cloneKeyMaterial(key),
		},
		keyAlgorithms,
		contentEncryptions,
		options...,
	)
}

// NewDecrypterWithResolver creates a decrypter using a dynamic key resolver.
func NewDecrypterWithResolver(
	resolver KeyResolver,
	keyAlgorithms []jose.KeyAlgorithm,
	contentEncryptions []jose.ContentEncryption,
	options ...Option,
) (*Decrypter, error) {
	if resolver == nil {
		return nil, fmt.Errorf(
			"%w: key resolver is required",
			ErrInvalidConfig,
		)
	}

	if len(keyAlgorithms) == 0 {
		return nil, fmt.Errorf(
			"%w: at least one key management algorithm is required",
			ErrInvalidConfig,
		)
	}

	if len(contentEncryptions) == 0 {
		return nil, fmt.Errorf(
			"%w: at least one content encryption algorithm is required",
			ErrInvalidConfig,
		)
	}

	for _, algorithm := range keyAlgorithms {
		if algorithm == "" {
			return nil, fmt.Errorf(
				"%w: key management algorithm is empty",
				ErrInvalidConfig,
			)
		}
	}

	for _, encryption := range contentEncryptions {
		if encryption == "" {
			return nil, fmt.Errorf(
				"%w: content encryption algorithm is empty",
				ErrInvalidConfig,
			)
		}
	}

	config, err := makeConfig(options)
	if err != nil {
		return nil, err
	}

	return &Decrypter{
		resolver: resolver,
		keyAlgorithms: append(
			[]jose.KeyAlgorithm(nil),
			keyAlgorithms...,
		),
		contentEncryptions: append(
			[]jose.ContentEncryption(nil),
			contentEncryptions...,
		),
		config: config,
	}, nil
}

// Decrypt decrypts a compact JWE and returns its plaintext.
func (decrypter *Decrypter) Decrypt(ctx context.Context, raw string) ([]byte, error) {
	decrypted, err := decrypter.DecryptToken(ctx, raw)
	if err != nil {
		return nil, err
	}

	return decrypted.Plaintext, nil
}

// DecryptToken decrypts a compact JWE and returns its authenticated header and plaintext.
func (decrypter *Decrypter) DecryptToken(ctx context.Context, raw string) (Decrypted, error) {
	if decrypter == nil ||
		decrypter.resolver == nil ||
		len(decrypter.keyAlgorithms) == 0 ||
		len(decrypter.contentEncryptions) == 0 {
		return Decrypted{}, fmt.Errorf(
			"%w: decrypter is uninitialized",
			ErrInvalidConfig,
		)
	}

	if raw == "" {
		return Decrypted{}, ErrMissingToken
	}

	if len(raw) > decrypter.config.maxTokenSize {
		return Decrypted{}, fmt.Errorf(
			"%w: got %d bytes, limit is %d",
			ErrTokenTooLarge,
			len(raw),
			decrypter.config.maxTokenSize,
		)
	}

	object, err := jose.ParseEncryptedCompact(
		raw,
		decrypter.keyAlgorithms,
		decrypter.contentEncryptions,
	)
	if err != nil {
		return Decrypted{}, fmt.Errorf(
			"%w: parse compact JWE: %w",
			ErrMalformedToken,
			err,
		)
	}

	header, err := parseHeader(object.Header)
	if err != nil {
		return Decrypted{}, err
	}

	// Reject unsupported typ, cty, or zip before resolving the key.
	if err := decrypter.validatePolicy(header); err != nil {
		return Decrypted{}, err
	}

	key, err := decrypter.resolver.Resolve(ctx, header)
	if err != nil {
		return Decrypted{}, err
	}

	plaintext, err := object.Decrypt(key)
	if err != nil {
		return Decrypted{}, fmt.Errorf(
			"%w: decrypt JWE: %w",
			ErrDecrypt,
			err,
		)
	}

	if len(plaintext) > decrypter.config.maxPlaintextSize {
		return Decrypted{}, fmt.Errorf(
			"%w: got %d bytes, limit is %d",
			ErrPlaintextTooLarge,
			len(plaintext),
			decrypter.config.maxPlaintextSize,
		)
	}

	return Decrypted{
		Header:    header,
		Plaintext: plaintext,
	}, nil
}

func (decrypter *Decrypter) validatePolicy(header Header) error {
	if decrypter.config.typ != "" &&
		header.Type != decrypter.config.typ {
		return ErrUnexpectedType
	}

	if decrypter.config.cty != "" &&
		header.ContentType != decrypter.config.cty {
		return ErrUnexpectedContentType
	}

	if header.Compression != jose.NONE &&
		header.Compression != decrypter.config.compression {
		return fmt.Errorf(
			"%w: expected %q, got %q",
			ErrUnexpectedCompression,
			decrypter.config.compression,
			header.Compression,
		)
	}

	return nil
}
