package jwe

import (
	"context"
	"fmt"

	"github.com/go-jose/go-jose/v4"
)

// MultiDecrypted contains the result of JWE JSON decryption.
//
// Header is the merged header for the selected recipient. It can include
// protected and unprotected parameters, so the header as a whole must not be
// treated as integrity-protected. Plaintext and AuthData are authenticated by
// successful JWE decryption.
type MultiDecrypted struct {
	RecipientIndex int
	Header         Header
	Plaintext      []byte
	AuthData       []byte
}

// MultiDecrypter decrypts Flattened or General JWE JSON Serialization.
type MultiDecrypter struct {
	resolver           KeyResolver
	keyAlgorithms      []jose.KeyAlgorithm
	contentEncryptions []jose.ContentEncryption
	config             config
}

// NewMultiDecrypter creates a decrypter using one static key.
//
// The key is tried against every recipient until one recipient successfully
// decrypts and authenticates the shared ciphertext.
func NewMultiDecrypter(
	key any,
	keyAlgorithms []jose.KeyAlgorithm,
	contentEncryptions []jose.ContentEncryption,
	options ...Option,
) (*MultiDecrypter, error) {
	if key == nil {
		return nil, fmt.Errorf("%w: decryption key is nil", ErrInvalidConfig)
	}

	return NewMultiDecrypterWithResolver(
		staticResolver{key: cloneKeyMaterial(key)},
		keyAlgorithms,
		contentEncryptions,
		options...,
	)
}

// NewMultiDecrypterWithResolver creates a decrypter using a dynamic key
// resolver.
//
// The resolver receives the shared JWE header available before recipient
// selection: protected plus shared unprotected parameters. Per-recipient alg
// and kid values are normally absent. A protected extension such as "keyset"
// can be used as a local routing hint. The resolver should return one concrete
// private or symmetric key; DecryptMulti tries that key against all recipients.
// The header is untrusted until decryption succeeds.
func NewMultiDecrypterWithResolver(
	resolver KeyResolver,
	keyAlgorithms []jose.KeyAlgorithm,
	contentEncryptions []jose.ContentEncryption,
	options ...Option,
) (*MultiDecrypter, error) {
	if resolver == nil {
		return nil, fmt.Errorf(
			"%w: key resolver is required",
			ErrInvalidConfig,
		)
	}
	if len(keyAlgorithms) == 0 || len(contentEncryptions) == 0 {
		return nil, fmt.Errorf(
			"%w: key and content encryption allowlists are required",
			ErrInvalidConfig,
		)
	}
	for _, algorithm := range keyAlgorithms {
		if algorithm == "" {
			return nil, fmt.Errorf("%w: key algorithm is empty", ErrInvalidConfig)
		}
	}
	for _, encryption := range contentEncryptions {
		if encryption == "" {
			return nil, fmt.Errorf("%w: content encryption is empty", ErrInvalidConfig)
		}
	}

	config, err := makeConfig(options)
	if err != nil {
		return nil, err
	}

	return &MultiDecrypter{
		resolver:           resolver,
		keyAlgorithms:      append([]jose.KeyAlgorithm(nil), keyAlgorithms...),
		contentEncryptions: append([]jose.ContentEncryption(nil), contentEncryptions...),
		config:             config,
	}, nil
}

// Decrypt decrypts JWE JSON Serialization and returns its plaintext.
func (decrypter *MultiDecrypter) Decrypt(ctx context.Context, raw string) ([]byte, error) {
	decrypted, err := decrypter.DecryptToken(ctx, raw)
	if err != nil {
		return nil, err
	}

	return decrypted.Plaintext, nil
}

// DecryptToken decrypts JWE JSON Serialization and returns the selected
// recipient, merged header, plaintext, and additional authenticated data.
func (decrypter *MultiDecrypter) DecryptToken(ctx context.Context, raw string) (MultiDecrypted, error) {
	var zero MultiDecrypted

	if decrypter == nil || decrypter.resolver == nil {
		return zero, fmt.Errorf(
			"%w: multi-decrypter is uninitialized",
			ErrInvalidConfig,
		)
	}

	if err := validateRawToken(raw, decrypter.config.maxTokenSize); err != nil {
		return zero, err
	}

	object, err := jose.ParseEncryptedJSON(
		raw,
		decrypter.keyAlgorithms,
		decrypter.contentEncryptions,
	)
	if err != nil {
		return zero, fmt.Errorf(
			"%w: parse JWE JSON serialization: %w",
			ErrMalformedToken,
			err,
		)
	}

	sharedHeader, err := parseMultiSharedHeader(object.Header)
	if err != nil {
		return zero, err
	}
	if err := decrypter.validatePolicy(sharedHeader, true); err != nil {
		return zero, err
	}

	key, err := decrypter.resolver.Resolve(ctx, sharedHeader)
	if err != nil {
		return zero, err
	}
	if key == nil {
		return zero, fmt.Errorf("%w: resolver returned a nil key", ErrDecrypt)
	}

	recipientIndex, joseHeader, plaintext, err := object.DecryptMulti(key)
	if err != nil {
		return zero, fmt.Errorf("%w: decrypt JWE JSON: %w", ErrDecrypt, err)
	}

	header, err := parseHeader(joseHeader)
	if err != nil {
		return zero, err
	}

	if err := decrypter.validatePolicy(header, false); err != nil {
		return zero, err
	}

	if err := validatePlaintextSize(plaintext, decrypter.config.maxPlaintextSize); err != nil {
		return zero, err
	}

	return MultiDecrypted{
		RecipientIndex: recipientIndex,
		Header:         header,
		Plaintext:      plaintext,
		AuthData:       object.GetAuthData(),
	}, nil
}

func (decrypter *MultiDecrypter) validatePolicy(
	header Header,
	allowMissingHeaders bool,
) error {
	if decrypter.config.typ != "" {
		if header.Type == "" && !allowMissingHeaders {
			return ErrUnexpectedType
		}
		if header.Type != "" && header.Type != decrypter.config.typ {
			return ErrUnexpectedType
		}
	}

	if decrypter.config.cty != "" {
		if header.ContentType == "" && !allowMissingHeaders {
			return ErrUnexpectedContentType
		}
		if header.ContentType != "" && header.ContentType != decrypter.config.cty {
			return ErrUnexpectedContentType
		}
	}

	if header.Compression != jose.NONE && header.Compression != decrypter.config.compression {
		return fmt.Errorf(
			"%w: expected %q, got %q",
			ErrUnexpectedCompression,
			decrypter.config.compression,
			header.Compression,
		)
	}

	return nil
}
