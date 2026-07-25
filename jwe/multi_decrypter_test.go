package jwe

import (
	"bytes"
	"context"
	"errors"
	"testing"

	jose "github.com/go-jose/go-jose/v4"
)

func TestNewMultiDecrypterRejectsInvalidConfiguration(t *testing.T) {
	key := testBytes(32, 61)

	tests := []struct {
		name        string
		key         any
		algorithms  []jose.KeyAlgorithm
		encryptions []jose.ContentEncryption
		options     []Option
	}{
		{
			name:        "nil key",
			algorithms:  []jose.KeyAlgorithm{jose.A256KW},
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
			algorithms: []jose.KeyAlgorithm{jose.A256KW},
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
			algorithms:  []jose.KeyAlgorithm{jose.A256KW},
			encryptions: []jose.ContentEncryption{""},
		},
		{
			name:        "nil option",
			key:         key,
			algorithms:  []jose.KeyAlgorithm{jose.A256KW},
			encryptions: []jose.ContentEncryption{jose.A256GCM},
			options:     []Option{nil},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := NewMultiDecrypter(
				test.key,
				test.algorithms,
				test.encryptions,
				test.options...,
			)
			requireErrorIs(t, err, ErrInvalidConfig)
		})
	}
}

func TestNewMultiDecrypterWithResolverRejectsInvalidConfiguration(t *testing.T) {
	resolver := KeyResolverFunc(func(context.Context, Header) (any, error) {
		return testBytes(32, 62), nil
	})

	tests := []struct {
		name        string
		resolver    KeyResolver
		algorithms  []jose.KeyAlgorithm
		encryptions []jose.ContentEncryption
	}{
		{
			name:        "nil resolver",
			algorithms:  []jose.KeyAlgorithm{jose.A256KW},
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
			algorithms: []jose.KeyAlgorithm{jose.A256KW},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := NewMultiDecrypterWithResolver(
				test.resolver,
				test.algorithms,
				test.encryptions,
			)
			requireErrorIs(t, err, ErrInvalidConfig)
		})
	}
}

func TestMultiDecrypterValidatesReceiverContextAndInput(t *testing.T) {
	key := testBytes(32, 63)
	raw, err := newMultiRSAAndSymmetricEncrypter(t, key).Encrypt([]byte("payload"))
	requireNoError(t, err)
	decrypter, err := NewMultiDecrypter(
		key,
		[]jose.KeyAlgorithm{jose.RSA_OAEP_256, jose.A256KW},
		[]jose.ContentEncryption{jose.A256GCM},
	)
	requireNoError(t, err)

	var nilDecrypter *MultiDecrypter
	_, err = nilDecrypter.DecryptToken(testContext(), raw)
	requireErrorIs(t, err, ErrInvalidConfig)

	_, err = decrypter.DecryptToken(nil, raw)
	requireErrorIs(t, err, ErrInvalidConfig)

	_, err = decrypter.DecryptToken(testContext(), "")
	requireErrorIs(t, err, ErrMissingToken)

	limited, err := NewMultiDecrypter(
		key,
		[]jose.KeyAlgorithm{jose.RSA_OAEP_256, jose.A256KW},
		[]jose.ContentEncryption{jose.A256GCM},
		WithMaxTokenSize(len(raw)-1),
	)
	requireNoError(t, err)
	_, err = limited.DecryptToken(testContext(), raw)
	requireErrorIs(t, err, ErrTokenTooLarge)
}

func TestMultiDecrypterFindsEachRecipient(t *testing.T) {
	key := testBytes(32, 64)
	plaintext := []byte("shared plaintext")
	authData := []byte("tenant=acme")
	raw, err := newMultiRSAAndSymmetricEncrypter(
		t,
		key,
		WithType("JWE"),
		WithContentType("application/json"),
		WithHeader(jose.HeaderKey("keyset"), "2026-07"),
	).EncryptWithAuthData(plaintext, authData)
	requireNoError(t, err)

	tests := []struct {
		name    string
		key     any
		index   int
		keyID   string
		keyAlgs []jose.KeyAlgorithm
	}{
		{
			name:    "RSA recipient",
			key:     testRSAKey,
			index:   0,
			keyID:   "rsa-recipient",
			keyAlgs: []jose.KeyAlgorithm{jose.RSA_OAEP_256, jose.A256KW},
		},
		{
			name:    "symmetric recipient",
			key:     key,
			index:   1,
			keyID:   "symmetric-recipient",
			keyAlgs: []jose.KeyAlgorithm{jose.RSA_OAEP_256, jose.A256KW},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			decrypter, err := NewMultiDecrypter(
				test.key,
				test.keyAlgs,
				[]jose.ContentEncryption{jose.A256GCM},
				WithType("JWE"),
				WithContentType("application/json"),
			)
			requireNoError(t, err)
			decrypted, err := decrypter.DecryptToken(testContext(), raw)
			requireNoError(t, err)

			if decrypted.RecipientIndex != test.index {
				t.Fatalf("recipient index = %d, want %d", decrypted.RecipientIndex, test.index)
			}
			if decrypted.Header.KeyID != test.keyID {
				t.Fatalf("key ID = %q, want %q", decrypted.Header.KeyID, test.keyID)
			}
			requireBytesEqual(t, decrypted.Plaintext, plaintext)
			requireBytesEqual(t, decrypted.AuthData, authData)
			if decrypted.Header.ExtraHeaders[jose.HeaderKey("keyset")] != "2026-07" {
				t.Fatalf("keyset = %#v", decrypted.Header.ExtraHeaders[jose.HeaderKey("keyset")])
			}
		})
	}
}

func TestMultiDecrypterResolverSeesSharedHeader(t *testing.T) {
	key := testBytes(32, 65)
	raw, err := newMultiRSAAndSymmetricEncrypter(
		t,
		key,
		WithType("JWE"),
		WithContentType("application/json"),
		WithHeader(jose.HeaderKey("keyset"), "2026-07"),
	).Encrypt([]byte("payload"))
	requireNoError(t, err)

	called := 0
	resolver := KeyResolverFunc(func(ctx context.Context, header Header) (any, error) {
		called++
		if ctx == nil {
			t.Fatal("context is nil")
		}
		if header.Algorithm != "" || header.KeyID != "" {
			t.Fatalf("recipient-specific fields visible before selection: %#v", header)
		}
		if header.Encryption != jose.A256GCM || header.Type != "JWE" || header.ContentType != "application/json" {
			t.Fatalf("shared header = %#v", header)
		}
		if header.ExtraHeaders[jose.HeaderKey("keyset")] != "2026-07" {
			t.Fatalf("keyset = %#v", header.ExtraHeaders[jose.HeaderKey("keyset")])
		}
		return key, nil
	})

	decrypter, err := NewMultiDecrypterWithResolver(
		resolver,
		[]jose.KeyAlgorithm{jose.RSA_OAEP_256, jose.A256KW},
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
	if decrypted.RecipientIndex != 1 || decrypted.Header.KeyID != "symmetric-recipient" {
		t.Fatalf("decrypted = %#v", decrypted)
	}
}

func TestMultiDecrypterResolverSeesRecipientFieldsForFlattenedJWE(t *testing.T) {
	key := testBytes(32, 66)
	encrypter, err := NewMultiEncrypter(
		[]jose.Recipient{{Algorithm: jose.A256KW, Key: key, KeyID: "one"}},
		jose.A256GCM,
	)
	requireNoError(t, err)
	raw, err := encrypter.Encrypt([]byte("payload"))
	requireNoError(t, err)

	decrypter, err := NewMultiDecrypterWithResolver(
		KeyResolverFunc(func(_ context.Context, header Header) (any, error) {
			if header.Algorithm != jose.A256KW || header.KeyID != "one" {
				t.Fatalf("flattened shared header = %#v", header)
			}
			return key, nil
		}),
		[]jose.KeyAlgorithm{jose.A256KW},
		[]jose.ContentEncryption{jose.A256GCM},
	)
	requireNoError(t, err)
	_, err = decrypter.DecryptToken(testContext(), raw)
	requireNoError(t, err)
}

func TestMultiDecrypterPolicyValidationStages(t *testing.T) {
	key := testBytes(32, 67)

	t.Run("present mismatch is rejected before resolver", func(t *testing.T) {
		raw, err := newMultiRSAAndSymmetricEncrypter(t, key, WithType("wrong")).Encrypt([]byte("payload"))
		requireNoError(t, err)
		called := false
		decrypter, err := NewMultiDecrypterWithResolver(
			KeyResolverFunc(func(context.Context, Header) (any, error) {
				called = true
				return key, nil
			}),
			[]jose.KeyAlgorithm{jose.RSA_OAEP_256, jose.A256KW},
			[]jose.ContentEncryption{jose.A256GCM},
			WithType("JWE"),
		)
		requireNoError(t, err)

		_, err = decrypter.DecryptToken(testContext(), raw)
		requireErrorIs(t, err, ErrUnexpectedType)
		if called {
			t.Fatal("resolver called for shared policy mismatch")
		}
	})

	t.Run("missing value is rejected after decryption", func(t *testing.T) {
		raw, err := newMultiRSAAndSymmetricEncrypter(t, key).Encrypt([]byte("payload"))
		requireNoError(t, err)
		called := false
		decrypter, err := NewMultiDecrypterWithResolver(
			KeyResolverFunc(func(context.Context, Header) (any, error) {
				called = true
				return key, nil
			}),
			[]jose.KeyAlgorithm{jose.RSA_OAEP_256, jose.A256KW},
			[]jose.ContentEncryption{jose.A256GCM},
			WithType("JWE"),
		)
		requireNoError(t, err)

		decrypted, err := decrypter.DecryptToken(testContext(), raw)
		requireErrorIs(t, err, ErrUnexpectedType)
		if !called {
			t.Fatal("resolver was not called before final policy validation")
		}
		if decrypted.Plaintext != nil || decrypted.AuthData != nil {
			t.Fatalf("partial decrypted result escaped: %#v", decrypted)
		}
	})

	t.Run("compression mismatch is rejected before resolver", func(t *testing.T) {
		raw, err := newMultiRSAAndSymmetricEncrypter(t, key, WithCompression(jose.DEFLATE)).Encrypt(
			bytes.Repeat([]byte("payload"), 20),
		)
		requireNoError(t, err)
		called := false
		decrypter, err := NewMultiDecrypterWithResolver(
			KeyResolverFunc(func(context.Context, Header) (any, error) {
				called = true
				return key, nil
			}),
			[]jose.KeyAlgorithm{jose.RSA_OAEP_256, jose.A256KW},
			[]jose.ContentEncryption{jose.A256GCM},
		)
		requireNoError(t, err)

		_, err = decrypter.DecryptToken(testContext(), raw)
		requireErrorIs(t, err, ErrUnexpectedCompression)
		if called {
			t.Fatal("resolver called for compression mismatch")
		}
	})
}

func TestMultiDecrypterResolverFailures(t *testing.T) {
	key := testBytes(32, 68)
	raw, err := newMultiRSAAndSymmetricEncrypter(t, key).Encrypt([]byte("payload"))
	requireNoError(t, err)
	resolverError := errors.New("resolver unavailable")

	tests := []struct {
		name     string
		resolver KeyResolverFunc
		ctx      func() context.Context
		want     error
	}{
		{
			name: "resolver error",
			resolver: func(context.Context, Header) (any, error) {
				return nil, resolverError
			},
			ctx:  context.Background,
			want: resolverError,
		},
		{
			name: "nil key",
			resolver: func(context.Context, Header) (any, error) {
				return nil, nil
			},
			ctx:  context.Background,
			want: ErrDecrypt,
		},
		{
			name: "wrong key",
			resolver: func(context.Context, Header) (any, error) {
				return testBytes(32, 69), nil
			},
			ctx:  context.Background,
			want: ErrDecrypt,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			decrypter, err := NewMultiDecrypterWithResolver(
				test.resolver,
				[]jose.KeyAlgorithm{jose.RSA_OAEP_256, jose.A256KW},
				[]jose.ContentEncryption{jose.A256GCM},
			)
			requireNoError(t, err)
			_, err = decrypter.DecryptToken(test.ctx(), raw)
			requireErrorIs(t, err, test.want)
		})
	}
}

func TestMultiDecrypterRejectsMalformedTamperedAndDisallowedTokens(t *testing.T) {
	key := testBytes(32, 70)
	raw, err := newMultiRSAAndSymmetricEncrypter(t, key).EncryptWithAuthData(
		[]byte("payload"),
		[]byte("context"),
	)
	requireNoError(t, err)
	decrypter, err := NewMultiDecrypter(
		key,
		[]jose.KeyAlgorithm{jose.RSA_OAEP_256, jose.A256KW},
		[]jose.ContentEncryption{jose.A256GCM},
	)
	requireNoError(t, err)

	for _, malformed := range []string{"not-json", "{}", `{"recipients":[]}`} {
		_, err := decrypter.DecryptToken(testContext(), malformed)
		requireErrorIs(t, err, ErrMalformedToken)
	}

	for _, field := range []string{"aad", "iv", "ciphertext", "tag"} {
		t.Run("tampered "+field, func(t *testing.T) {
			tampered := tamperJSONBase64Field(t, raw, field)
			plaintext, err := decrypter.Decrypt(testContext(), tampered)
			requireErrorIs(t, err, ErrDecrypt)
			if plaintext != nil {
				t.Fatalf("plaintext = %q, want nil", plaintext)
			}
		})
	}

	wrongAlgorithm, err := NewMultiDecrypter(
		key,
		[]jose.KeyAlgorithm{jose.A128KW},
		[]jose.ContentEncryption{jose.A256GCM},
	)
	requireNoError(t, err)
	_, err = wrongAlgorithm.DecryptToken(testContext(), raw)
	requireErrorIs(t, err, ErrMalformedToken)

	wrongEncryption, err := NewMultiDecrypter(
		key,
		[]jose.KeyAlgorithm{jose.RSA_OAEP_256, jose.A256KW},
		[]jose.ContentEncryption{jose.A128GCM},
	)
	requireNoError(t, err)
	_, err = wrongEncryption.DecryptToken(testContext(), raw)
	requireErrorIs(t, err, ErrMalformedToken)
}

func TestMultiDecrypterMergesUnprotectedHeaders(t *testing.T) {
	key := testBytes(32, 72)
	raw, err := newMultiRSAAndSymmetricEncrypter(t, key).Encrypt([]byte("payload"))
	requireNoError(t, err)

	raw = rewriteJSONObject(t, raw, func(object map[string]any) {
		object["unprotected"] = map[string]any{"route": "shared"}

		recipients := requireType[[]any](t, object["recipients"])
		second := requireType[map[string]any](t, recipients[1])
		header := requireType[map[string]any](t, second["header"])
		header["role"] = "billing"
	})

	resolverSawRole := false
	decrypter, err := NewMultiDecrypterWithResolver(
		KeyResolverFunc(func(_ context.Context, header Header) (any, error) {
			if header.ExtraHeaders[jose.HeaderKey("route")] != "shared" {
				t.Fatalf("shared route = %#v", header.ExtraHeaders[jose.HeaderKey("route")])
			}
			_, resolverSawRole = header.ExtraHeaders[jose.HeaderKey("role")]
			return key, nil
		}),
		[]jose.KeyAlgorithm{jose.RSA_OAEP_256, jose.A256KW},
		[]jose.ContentEncryption{jose.A256GCM},
	)
	requireNoError(t, err)
	decrypted, err := decrypter.DecryptToken(testContext(), raw)
	requireNoError(t, err)
	if resolverSawRole {
		t.Fatal("resolver saw per-recipient header before selection")
	}
	if decrypted.Header.ExtraHeaders[jose.HeaderKey("route")] != "shared" ||
		decrypted.Header.ExtraHeaders[jose.HeaderKey("role")] != "billing" {
		t.Fatalf("merged header = %#v", decrypted.Header.ExtraHeaders)
	}
}

func TestMultiDecrypterEnforcesPlaintextLimit(t *testing.T) {
	key := testBytes(32, 74)
	plaintext := bytes.Repeat([]byte("a"), 64)
	raw, err := newMultiRSAAndSymmetricEncrypter(t, key).Encrypt(plaintext)
	requireNoError(t, err)
	decrypter, err := NewMultiDecrypter(
		key,
		[]jose.KeyAlgorithm{jose.RSA_OAEP_256, jose.A256KW},
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

func TestMultiDecrypterClonesStaticKeyAndAllowlists(t *testing.T) {
	key := testBytes(32, 75)
	expected := bytes.Clone(key)
	algorithms := []jose.KeyAlgorithm{jose.RSA_OAEP_256, jose.A256KW}
	encryptions := []jose.ContentEncryption{jose.A256GCM}
	decrypter, err := NewMultiDecrypter(key, algorithms, encryptions)
	requireNoError(t, err)

	for index := range key {
		key[index] ^= 0xff
	}
	algorithms[0] = jose.A128KW
	algorithms[1] = jose.A192KW
	encryptions[0] = jose.A128GCM

	raw, err := newMultiRSAAndSymmetricEncrypter(t, expected).Encrypt([]byte("payload"))
	requireNoError(t, err)
	plaintext, err := decrypter.Decrypt(testContext(), raw)
	requireNoError(t, err)
	requireBytesEqual(t, plaintext, []byte("payload"))
}

func TestMultiDecrypterReturnedSlicesAreIndependent(t *testing.T) {
	key := testBytes(32, 76)
	raw, err := newMultiRSAAndSymmetricEncrypter(t, key).EncryptWithAuthData(
		[]byte("payload"),
		[]byte("context"),
	)
	requireNoError(t, err)
	decrypter, err := NewMultiDecrypter(
		key,
		[]jose.KeyAlgorithm{jose.RSA_OAEP_256, jose.A256KW},
		[]jose.ContentEncryption{jose.A256GCM},
	)
	requireNoError(t, err)

	first, err := decrypter.DecryptToken(testContext(), raw)
	requireNoError(t, err)
	first.Plaintext[0] ^= 0xff
	first.AuthData[0] ^= 0xff
	first.Header.ExtraHeaders[jose.HeaderKey("enc")] = "mutated"

	second, err := decrypter.DecryptToken(testContext(), raw)
	requireNoError(t, err)
	requireBytesEqual(t, second.Plaintext, []byte("payload"))
	requireBytesEqual(t, second.AuthData, []byte("context"))
	if second.Header.Encryption != jose.A256GCM {
		t.Fatalf("encryption = %q, want %q", second.Header.Encryption, jose.A256GCM)
	}
}

func TestMultiDecrypterValidatePolicy(t *testing.T) {
	decrypter := &MultiDecrypter{config: config{
		typ:         "JWE",
		cty:         "application/json",
		compression: jose.DEFLATE,
	}}

	tests := []struct {
		name         string
		header       Header
		allowMissing bool
		want         error
	}{
		{
			name:         "missing headers allowed",
			allowMissing: true,
		},
		{
			name: "matching headers",
			header: Header{
				Type:        "JWE",
				ContentType: "application/json",
				Compression: jose.DEFLATE,
			},
		},
		{
			name: "uncompressed allowed",
			header: Header{
				Type:        "JWE",
				ContentType: "application/json",
			},
		},
		{
			name: "missing type required",
			header: Header{
				ContentType: "application/json",
			},
			want: ErrUnexpectedType,
		},
		{
			name: "wrong type",
			header: Header{
				Type:        "JWT",
				ContentType: "application/json",
			},
			allowMissing: true,
			want:         ErrUnexpectedType,
		},
		{
			name: "missing content type required",
			header: Header{
				Type: "JWE",
			},
			want: ErrUnexpectedContentType,
		},
		{
			name: "wrong content type",
			header: Header{
				Type:        "JWE",
				ContentType: "text/plain",
			},
			allowMissing: true,
			want:         ErrUnexpectedContentType,
		},
		{
			name: "wrong compression",
			header: Header{
				Type:        "JWE",
				ContentType: "application/json",
				Compression: jose.CompressionAlgorithm("OTHER"),
			},
			want: ErrUnexpectedCompression,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := decrypter.validatePolicy(test.header, test.allowMissing)
			if test.want == nil {
				requireNoError(t, err)
				return
			}
			requireErrorIs(t, err, test.want)
		})
	}
}

func TestMultiDecrypterRejectsPerRecipientCriticalHeader(t *testing.T) {
	key := testBytes(32, 77)
	raw, err := newMultiRSAAndSymmetricEncrypter(t, key).Encrypt([]byte("payload"))
	requireNoError(t, err)
	raw = rewriteJSONObject(t, raw, func(object map[string]any) {
		recipients := requireType[[]any](t, object["recipients"])
		second := requireType[map[string]any](t, recipients[1])
		header := requireType[map[string]any](t, second["header"])
		header["crit"] = []any{"role"}
		header["role"] = "billing"
	})

	decrypter, err := NewMultiDecrypter(
		key,
		[]jose.KeyAlgorithm{jose.RSA_OAEP_256, jose.A256KW},
		[]jose.ContentEncryption{jose.A256GCM},
	)
	requireNoError(t, err)
	decrypted, err := decrypter.DecryptToken(testContext(), raw)
	requireErrorIs(t, err, ErrMalformedToken)
	if decrypted.Plaintext != nil || decrypted.AuthData != nil {
		t.Fatalf("partial result escaped: %#v", decrypted)
	}
}
