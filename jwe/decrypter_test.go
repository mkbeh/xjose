package jwe

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/go-jose/go-jose/v4"
)

func TestNewDecrypterRejectsInvalidConfiguration(t *testing.T) {
	key := testBytes(32, 21)

	tests := []struct {
		name        string
		key         any
		algorithms  []jose.KeyAlgorithm
		encryptions []jose.ContentEncryption
		options     []Option
	}{
		{
			name:        "nil key",
			key:         nil,
			algorithms:  []jose.KeyAlgorithm{jose.DIRECT},
			encryptions: []jose.ContentEncryption{jose.A256GCM},
		},
		{
			name:        "missing key algorithms",
			key:         key,
			encryptions: []jose.ContentEncryption{jose.A256GCM},
		},
		{
			name:       "missing content encryptions",
			key:        key,
			algorithms: []jose.KeyAlgorithm{jose.DIRECT},
		},
		{
			name:        "empty key algorithm",
			key:         key,
			algorithms:  []jose.KeyAlgorithm{""},
			encryptions: []jose.ContentEncryption{jose.A256GCM},
		},
		{
			name:        "empty content encryption",
			key:         key,
			algorithms:  []jose.KeyAlgorithm{jose.DIRECT},
			encryptions: []jose.ContentEncryption{""},
		},
		{
			name:        "nil option",
			key:         key,
			algorithms:  []jose.KeyAlgorithm{jose.DIRECT},
			encryptions: []jose.ContentEncryption{jose.A256GCM},
			options:     []Option{nil},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := NewDecrypter(
				test.key,
				test.algorithms,
				test.encryptions,
				test.options...,
			)
			requireErrorIs(t, err, ErrInvalidConfig)
		})
	}
}

func TestNewDecrypterWithResolverRejectsInvalidConfiguration(t *testing.T) {
	resolver := KeyResolverFunc(func(context.Context, Header) (any, error) {
		return testBytes(32, 22), nil
	})

	tests := []struct {
		name        string
		resolver    KeyResolver
		algorithms  []jose.KeyAlgorithm
		encryptions []jose.ContentEncryption
	}{
		{
			name:        "nil resolver",
			algorithms:  []jose.KeyAlgorithm{jose.DIRECT},
			encryptions: []jose.ContentEncryption{jose.A256GCM},
		},
		{
			name:        "missing algorithms",
			resolver:    resolver,
			encryptions: []jose.ContentEncryption{jose.A256GCM},
		},
		{
			name:       "missing encryptions",
			resolver:   resolver,
			algorithms: []jose.KeyAlgorithm{jose.DIRECT},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := NewDecrypterWithResolver(
				test.resolver,
				test.algorithms,
				test.encryptions,
			)
			requireErrorIs(t, err, ErrInvalidConfig)
		})
	}
}

func TestDecrypterValidatesReceiverContextAndInput(t *testing.T) {
	key := testBytes(32, 23)
	encrypter := newDirectEncrypter(t, key)
	raw, err := encrypter.Encrypt([]byte("payload"))
	requireNoError(t, err)
	decrypter := newDirectDecrypter(t, key)

	var nilDecrypter *Decrypter
	_, err = nilDecrypter.DecryptToken(testContext(), raw)
	requireErrorIs(t, err, ErrInvalidConfig)

	_, err = decrypter.DecryptToken(testContext(), "")
	requireErrorIs(t, err, ErrMissingToken)

	limited, err := NewDecrypter(
		key,
		[]jose.KeyAlgorithm{jose.DIRECT},
		[]jose.ContentEncryption{jose.A256GCM},
		WithMaxTokenSize(len(raw)-1),
	)
	requireNoError(t, err)
	_, err = limited.DecryptToken(testContext(), raw)
	requireErrorIs(t, err, ErrTokenTooLarge)
}

func TestDecrypterResolverReceivesProtectedHeader(t *testing.T) {
	key := testBytes(32, 24)
	encrypter := newDirectEncrypter(
		t,
		key,
		WithType("JWE"),
		WithContentType("application/json"),
		WithHeader(jose.HeaderKey("keyset"), "2026-07"),
	)
	raw, err := encrypter.Encrypt([]byte("payload"))
	requireNoError(t, err)

	called := 0
	resolver := KeyResolverFunc(func(ctx context.Context, header Header) (any, error) {
		called++
		if ctx == nil {
			t.Fatal("resolver context is nil")
		}
		if header.Algorithm != jose.DIRECT || header.Encryption != jose.A256GCM {
			t.Fatalf("resolver header algorithms = %#v", header)
		}
		if header.KeyID != "encryption-key" {
			t.Fatalf("resolver key ID = %q, want encryption-key", header.KeyID)
		}
		if header.Type != "JWE" || header.ContentType != "application/json" {
			t.Fatalf("resolver policy header = %#v", header)
		}
		if header.ExtraHeaders[jose.HeaderKey("keyset")] != "2026-07" {
			t.Fatalf("resolver keyset = %#v", header.ExtraHeaders[jose.HeaderKey("keyset")])
		}

		return key, nil
	})

	decrypter, err := NewDecrypterWithResolver(
		resolver,
		[]jose.KeyAlgorithm{jose.DIRECT},
		[]jose.ContentEncryption{jose.A256GCM},
		WithType("JWE"),
		WithContentType("application/json"),
	)
	requireNoError(t, err)

	decrypted, err := decrypter.DecryptToken(testContext(), raw)
	requireNoError(t, err)
	if called != 1 {
		t.Fatalf("resolver calls = %d, want 1", called)
	}
	requireBytesEqual(t, decrypted.Plaintext, []byte("payload"))
}

func TestDecrypterRejectsPolicyBeforeResolver(t *testing.T) {
	key := testBytes(32, 25)

	tests := []struct {
		name             string
		encrypterOptions []Option
		decrypterOptions []Option
		want             error
	}{
		{
			name:             "type",
			encrypterOptions: []Option{WithType("wrong")},
			decrypterOptions: []Option{WithType("JWE")},
			want:             ErrUnexpectedType,
		},
		{
			name:             "content type",
			encrypterOptions: []Option{WithContentType("text/plain")},
			decrypterOptions: []Option{WithContentType("application/json")},
			want:             ErrUnexpectedContentType,
		},
		{
			name:             "compression",
			encrypterOptions: []Option{WithCompression(jose.DEFLATE)},
			want:             ErrUnexpectedCompression,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			encrypter := newDirectEncrypter(t, key, test.encrypterOptions...)
			raw, err := encrypter.Encrypt(bytes.Repeat([]byte("payload"), 20))
			requireNoError(t, err)

			called := false
			decrypter, err := NewDecrypterWithResolver(
				KeyResolverFunc(func(context.Context, Header) (any, error) {
					called = true
					return key, nil
				}),
				[]jose.KeyAlgorithm{jose.DIRECT},
				[]jose.ContentEncryption{jose.A256GCM},
				test.decrypterOptions...,
			)
			requireNoError(t, err)

			_, err = decrypter.DecryptToken(testContext(), raw)
			requireErrorIs(t, err, test.want)
			if called {
				t.Fatal("resolver was called after policy rejection")
			}
		})
	}
}

func TestDecrypterResolverFailures(t *testing.T) {
	key := testBytes(32, 26)
	raw, err := newDirectEncrypter(t, key).Encrypt([]byte("payload"))
	requireNoError(t, err)
	resolverError := errors.New("resolver unavailable")

	t.Run("resolver error", func(t *testing.T) {
		decrypter, err := NewDecrypterWithResolver(
			KeyResolverFunc(func(context.Context, Header) (any, error) {
				return nil, resolverError
			}),
			[]jose.KeyAlgorithm{jose.DIRECT},
			[]jose.ContentEncryption{jose.A256GCM},
		)
		requireNoError(t, err)

		_, err = decrypter.DecryptToken(testContext(), raw)
		requireErrorIs(t, err, resolverError)
	})

	t.Run("nil key", func(t *testing.T) {
		decrypter, err := NewDecrypterWithResolver(
			KeyResolverFunc(func(context.Context, Header) (any, error) {
				return nil, nil
			}),
			[]jose.KeyAlgorithm{jose.DIRECT},
			[]jose.ContentEncryption{jose.A256GCM},
		)
		requireNoError(t, err)

		_, err = decrypter.DecryptToken(testContext(), raw)
		requireErrorIs(t, err, ErrDecrypt)
	})
}

func TestDecrypterRejectsMalformedAndTamperedTokens(t *testing.T) {
	key := testBytes(32, 27)
	raw, err := newDirectEncrypter(t, key).Encrypt([]byte("payload"))
	requireNoError(t, err)
	decrypter := newDirectDecrypter(t, key)

	for _, malformed := range []string{
		"not-a-jwe",
		"....extra.part",
		"%%%....",
	} {
		_, err := decrypter.DecryptToken(testContext(), malformed)
		requireErrorIs(t, err, ErrMalformedToken)
	}

	for _, part := range []int{2, 3, 4} {
		t.Run(fmt.Sprintf("tampered part %d", part), func(t *testing.T) {
			tampered := tamperCompactPart(t, raw, part)
			plaintext, err := decrypter.Decrypt(testContext(), tampered)
			requireErrorIs(t, err, ErrDecrypt)
			if plaintext != nil {
				t.Fatalf("plaintext = %q, want nil", plaintext)
			}
		})
	}

	rsaEncrypter, err := NewEncrypter(
		jose.Recipient{Algorithm: jose.RSA_OAEP_256, Key: &testRSAKey.PublicKey},
		jose.A256GCM,
	)
	requireNoError(t, err)
	rsaRaw, err := rsaEncrypter.Encrypt([]byte("payload"))
	requireNoError(t, err)
	rsaDecrypter, err := NewDecrypter(
		testRSAKey,
		[]jose.KeyAlgorithm{jose.RSA_OAEP_256},
		[]jose.ContentEncryption{jose.A256GCM},
	)
	requireNoError(t, err)
	plaintext, err := rsaDecrypter.Decrypt(testContext(), tamperCompactPart(t, rsaRaw, 1))
	requireErrorIs(t, err, ErrDecrypt)
	if plaintext != nil {
		t.Fatalf("plaintext = %q, want nil", plaintext)
	}

	wrongKey := newDirectDecrypter(t, testBytes(32, 28))
	plaintext, err = wrongKey.Decrypt(testContext(), raw)
	requireErrorIs(t, err, ErrDecrypt)
	if plaintext != nil {
		t.Fatalf("plaintext = %q, want nil", plaintext)
	}
}

func TestDecrypterEnforcesAlgorithmAllowlists(t *testing.T) {
	key := testBytes(32, 29)
	raw, err := newDirectEncrypter(t, key).Encrypt([]byte("payload"))
	requireNoError(t, err)

	wrongAlgorithm, err := NewDecrypter(
		key,
		[]jose.KeyAlgorithm{jose.A256KW},
		[]jose.ContentEncryption{jose.A256GCM},
	)
	requireNoError(t, err)
	_, err = wrongAlgorithm.DecryptToken(testContext(), raw)
	requireErrorIs(t, err, ErrMalformedToken)

	wrongEncryption, err := NewDecrypter(
		key,
		[]jose.KeyAlgorithm{jose.DIRECT},
		[]jose.ContentEncryption{jose.A128GCM},
	)
	requireNoError(t, err)
	_, err = wrongEncryption.DecryptToken(testContext(), raw)
	requireErrorIs(t, err, ErrMalformedToken)
}

func TestDecrypterRejectsCriticalHeaders(t *testing.T) {
	key := testBytes(32, 30)
	encrypter := newDirectEncrypter(
		t,
		key,
		WithHeader(headerCritical, []string{"tenant"}),
		WithHeader(jose.HeaderKey("tenant"), "acme"),
	)
	raw, err := encrypter.Encrypt([]byte("payload"))
	requireNoError(t, err)

	called := false
	decrypter, err := NewDecrypterWithResolver(
		KeyResolverFunc(func(context.Context, Header) (any, error) {
			called = true
			return key, nil
		}),
		[]jose.KeyAlgorithm{jose.DIRECT},
		[]jose.ContentEncryption{jose.A256GCM},
	)
	requireNoError(t, err)

	_, err = decrypter.DecryptToken(testContext(), raw)
	requireErrorIs(t, err, ErrMalformedToken)
	if called {
		t.Fatal("resolver called for critical header")
	}
}

func TestDecrypterEnforcesPlaintextLimitAfterDecryption(t *testing.T) {
	key := testBytes(32, 31)
	plaintext := bytes.Repeat([]byte("a"), 64)
	raw, err := newDirectEncrypter(t, key).Encrypt(plaintext)
	requireNoError(t, err)

	decrypter, err := NewDecrypter(
		key,
		[]jose.KeyAlgorithm{jose.DIRECT},
		[]jose.ContentEncryption{jose.A256GCM},
		WithMaxPlaintextSize(len(plaintext)-1),
	)
	requireNoError(t, err)

	got, err := decrypter.Decrypt(testContext(), raw)
	requireErrorIs(t, err, ErrPlaintextTooLarge)
	if got != nil {
		t.Fatalf("plaintext = %q, want nil", got)
	}
}

func TestDecrypterClonesStaticKeyAndAllowlists(t *testing.T) {
	key := testBytes(32, 32)
	expectedKey := bytes.Clone(key)
	algorithms := []jose.KeyAlgorithm{jose.DIRECT}
	encryptions := []jose.ContentEncryption{jose.A256GCM}

	decrypter, err := NewDecrypter(key, algorithms, encryptions)
	requireNoError(t, err)

	for index := range key {
		key[index] ^= 0xff
	}
	algorithms[0] = jose.A256KW
	encryptions[0] = jose.A128GCM

	raw, err := newDirectEncrypter(t, expectedKey).Encrypt([]byte("payload"))
	requireNoError(t, err)
	plaintext, err := decrypter.Decrypt(testContext(), raw)
	requireNoError(t, err)
	requireBytesEqual(t, plaintext, []byte("payload"))
}

func TestDecrypterCompressionPolicyAllowsUncompressedToken(t *testing.T) {
	key := testBytes(32, 33)
	raw, err := newDirectEncrypter(t, key).Encrypt([]byte("payload"))
	requireNoError(t, err)

	decrypter := newDirectDecrypter(t, key, WithCompression(jose.DEFLATE))
	plaintext, err := decrypter.Decrypt(testContext(), raw)
	requireNoError(t, err)
	requireBytesEqual(t, plaintext, []byte("payload"))
}

func TestDecrypterHeaderMutationDoesNotAffectLaterCalls(t *testing.T) {
	key := testBytes(32, 34)
	raw, err := newDirectEncrypter(
		t,
		key,
		WithHeader(jose.HeaderKey("tenant"), "acme"),
	).Encrypt([]byte("payload"))
	requireNoError(t, err)
	decrypter := newDirectDecrypter(t, key)

	first, err := decrypter.DecryptToken(testContext(), raw)
	requireNoError(t, err)
	first.Header.ExtraHeaders[jose.HeaderKey("tenant")] = "mutated"
	first.Plaintext[0] ^= 0xff

	second, err := decrypter.DecryptToken(testContext(), raw)
	requireNoError(t, err)
	if second.Header.ExtraHeaders[jose.HeaderKey("tenant")] != "acme" {
		t.Fatalf("tenant = %#v, want acme", second.Header.ExtraHeaders[jose.HeaderKey("tenant")])
	}
	requireBytesEqual(t, second.Plaintext, []byte("payload"))
}
