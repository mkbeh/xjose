package jwe

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"sync"
	"testing"

	jose "github.com/go-jose/go-jose/v4"
)

func TestMultiEncrypterKeyManagementAlgorithms(t *testing.T) {
	password := []byte("correct horse battery staple")

	tests := []struct {
		name          string
		recipient     jose.Recipient
		decryptionKey any
	}{
		{
			name:          "RSA1_5",
			recipient:     jose.Recipient{Algorithm: jose.RSA1_5, Key: &testRSAKey.PublicKey},
			decryptionKey: testRSAKey,
		},
		{
			name:          "RSA-OAEP",
			recipient:     jose.Recipient{Algorithm: jose.RSA_OAEP, Key: &testRSAKey.PublicKey},
			decryptionKey: testRSAKey,
		},
		{
			name:          "RSA-OAEP-256",
			recipient:     jose.Recipient{Algorithm: jose.RSA_OAEP_256, Key: &testRSAKey.PublicKey},
			decryptionKey: testRSAKey,
		},
		{
			name:          "A128KW",
			recipient:     jose.Recipient{Algorithm: jose.A128KW, Key: testBytes(16, 41)},
			decryptionKey: testBytes(16, 41),
		},
		{
			name:          "A192KW",
			recipient:     jose.Recipient{Algorithm: jose.A192KW, Key: testBytes(24, 42)},
			decryptionKey: testBytes(24, 42),
		},
		{
			name:          "A256KW",
			recipient:     jose.Recipient{Algorithm: jose.A256KW, Key: testBytes(32, 43)},
			decryptionKey: testBytes(32, 43),
		},
		{
			name:          "ECDH-ES+A128KW",
			recipient:     jose.Recipient{Algorithm: jose.ECDH_ES_A128KW, Key: &testECKey.PublicKey},
			decryptionKey: testECKey,
		},
		{
			name:          "ECDH-ES+A192KW",
			recipient:     jose.Recipient{Algorithm: jose.ECDH_ES_A192KW, Key: &testECKey.PublicKey},
			decryptionKey: testECKey,
		},
		{
			name:          "ECDH-ES+A256KW",
			recipient:     jose.Recipient{Algorithm: jose.ECDH_ES_A256KW, Key: &testECKey.PublicKey},
			decryptionKey: testECKey,
		},
		{
			name:          "A128GCMKW",
			recipient:     jose.Recipient{Algorithm: jose.A128GCMKW, Key: testBytes(16, 44)},
			decryptionKey: testBytes(16, 44),
		},
		{
			name:          "A192GCMKW",
			recipient:     jose.Recipient{Algorithm: jose.A192GCMKW, Key: testBytes(24, 45)},
			decryptionKey: testBytes(24, 45),
		},
		{
			name:          "A256GCMKW",
			recipient:     jose.Recipient{Algorithm: jose.A256GCMKW, Key: testBytes(32, 46)},
			decryptionKey: testBytes(32, 46),
		},
		{
			name: "PBES2-HS256+A128KW",
			recipient: jose.Recipient{
				Algorithm:  jose.PBES2_HS256_A128KW,
				Key:        password,
				PBES2Count: 1000,
				PBES2Salt:  testBytes(16, 47),
			},
			decryptionKey: password,
		},
		{
			name: "PBES2-HS384+A192KW",
			recipient: jose.Recipient{
				Algorithm:  jose.PBES2_HS384_A192KW,
				Key:        password,
				PBES2Count: 1000,
				PBES2Salt:  testBytes(16, 48),
			},
			decryptionKey: password,
		},
		{
			name: "PBES2-HS512+A256KW",
			recipient: jose.Recipient{
				Algorithm:  jose.PBES2_HS512_A256KW,
				Key:        password,
				PBES2Count: 1000,
				PBES2Salt:  testBytes(16, 49),
			},
			decryptionKey: password,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			encrypter, err := NewMultiEncrypter(
				[]jose.Recipient{test.recipient},
				jose.A256GCM,
			)
			requireNoError(t, err)
			raw, err := encrypter.Encrypt([]byte("flattened-round-trip"))
			requireNoError(t, err)

			decrypter, err := NewMultiDecrypter(
				test.decryptionKey,
				[]jose.KeyAlgorithm{test.recipient.Algorithm},
				[]jose.ContentEncryption{jose.A256GCM},
			)
			requireNoError(t, err)
			decrypted, err := decrypter.DecryptToken(testContext(), raw)
			requireNoError(t, err)
			if decrypted.RecipientIndex != 0 {
				t.Fatalf("recipient index = %d, want 0", decrypted.RecipientIndex)
			}
			requireBytesEqual(t, decrypted.Plaintext, []byte("flattened-round-trip"))
		})
	}
}

func TestMultiEncrypterContentEncryptionAlgorithms(t *testing.T) {
	key := testBytes(32, 50)
	algorithms := []jose.ContentEncryption{
		jose.A128GCM,
		jose.A192GCM,
		jose.A256GCM,
		jose.A128CBC_HS256,
		jose.A192CBC_HS384,
		jose.A256CBC_HS512,
	}

	for _, algorithm := range algorithms {
		t.Run(string(algorithm), func(t *testing.T) {
			encrypter, err := NewMultiEncrypter(
				[]jose.Recipient{{Algorithm: jose.A256KW, Key: key}},
				algorithm,
			)
			requireNoError(t, err)
			raw, err := encrypter.Encrypt([]byte("content-encryption-round-trip"))
			requireNoError(t, err)

			decrypter, err := NewMultiDecrypter(
				key,
				[]jose.KeyAlgorithm{jose.A256KW},
				[]jose.ContentEncryption{algorithm},
			)
			requireNoError(t, err)
			plaintext, err := decrypter.Decrypt(testContext(), raw)
			requireNoError(t, err)
			requireBytesEqual(t, plaintext, []byte("content-encryption-round-trip"))
		})
	}
}

func TestNewMultiEncrypterRejectsInvalidConfiguration(t *testing.T) {
	key := testBytes(32, 51)

	tests := []struct {
		name       string
		recipients []jose.Recipient
		encryption jose.ContentEncryption
		options    []Option
	}{
		{name: "no recipients", encryption: jose.A256GCM},
		{
			name:       "missing encryption",
			recipients: []jose.Recipient{{Algorithm: jose.A256KW, Key: key}},
		},
		{
			name:       "missing recipient algorithm",
			recipients: []jose.Recipient{{Key: key}},
			encryption: jose.A256GCM,
		},
		{
			name:       "missing recipient key",
			recipients: []jose.Recipient{{Algorithm: jose.A256KW}},
			encryption: jose.A256GCM,
		},
		{
			name:       "direct is unsupported",
			recipients: []jose.Recipient{{Algorithm: jose.DIRECT, Key: key}},
			encryption: jose.A256GCM,
		},
		{
			name:       "direct ECDH-ES is unsupported",
			recipients: []jose.Recipient{{Algorithm: jose.ECDH_ES, Key: &testECKey.PublicKey}},
			encryption: jose.A256GCM,
		},
		{
			name:       "unsupported content encryption",
			recipients: []jose.Recipient{{Algorithm: jose.A256KW, Key: key}},
			encryption: jose.ContentEncryption("unsupported"),
		},
		{
			name:       "nil option",
			recipients: []jose.Recipient{{Algorithm: jose.A256KW, Key: key}},
			encryption: jose.A256GCM,
			options:    []Option{nil},
		},
		{
			name:       "unsupported compression",
			recipients: []jose.Recipient{{Algorithm: jose.A256KW, Key: key}},
			encryption: jose.A256GCM,
			options:    []Option{WithCompression(jose.CompressionAlgorithm("GZIP"))},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := NewMultiEncrypter(test.recipients, test.encryption, test.options...)
			requireErrorIs(t, err, ErrInvalidConfig)
		})
	}
}

func TestMultiEncrypterValidatesInput(t *testing.T) {
	key := testBytes(32, 52)
	encrypter, err := NewMultiEncrypter(
		[]jose.Recipient{{Algorithm: jose.A256KW, Key: key}},
		jose.A256GCM,
	)
	requireNoError(t, err)

	var nilEncrypter *MultiEncrypter
	_, err = nilEncrypter.Encrypt([]byte("payload"))
	requireErrorIs(t, err, ErrInvalidConfig)

	_, err = encrypter.Encrypt(nil)
	requireErrorIs(t, err, ErrMissingPlaintext)

	limited, err := NewMultiEncrypter(
		[]jose.Recipient{{Algorithm: jose.A256KW, Key: key}},
		jose.A256GCM,
		WithMaxPlaintextSize(3),
	)
	requireNoError(t, err)
	_, err = limited.Encrypt([]byte("four"))
	requireErrorIs(t, err, ErrPlaintextTooLarge)

	aadLimited, err := NewMultiEncrypter(
		[]jose.Recipient{{Algorithm: jose.A256KW, Key: key}},
		jose.A256GCM,
		WithMaxTokenSize(8),
	)
	requireNoError(t, err)
	_, err = aadLimited.EncryptWithAuthData([]byte("x"), []byte("123456789"))
	requireErrorIs(t, err, ErrTokenTooLarge)

	_, err = aadLimited.Encrypt([]byte("x"))
	requireErrorIs(t, err, ErrTokenTooLarge)
}

func TestMultiEncrypterSerializationForms(t *testing.T) {
	key := testBytes(32, 53)

	t.Run("one recipient uses flattened JSON", func(t *testing.T) {
		encrypter, err := NewMultiEncrypter(
			[]jose.Recipient{{Algorithm: jose.A256KW, Key: key, KeyID: "one"}},
			jose.A256GCM,
		)
		requireNoError(t, err)
		raw, err := encrypter.Encrypt([]byte("payload"))
		requireNoError(t, err)
		object := decodeJSONObject(t, raw)

		if _, exists := object["recipients"]; exists {
			t.Fatal("flattened JWE unexpectedly contains recipients")
		}
		if _, exists := object["encrypted_key"]; !exists {
			t.Fatal("flattened JWE is missing encrypted_key")
		}
		header := protectedJSONHeader(t, raw)
		if header["alg"] != string(jose.A256KW) || header["kid"] != "one" {
			t.Fatalf("protected header = %#v", header)
		}
	})

	t.Run("multiple recipients use general JSON", func(t *testing.T) {
		encrypter := newMultiRSAAndSymmetricEncrypter(t, key)
		raw, err := encrypter.Encrypt([]byte("payload"))
		requireNoError(t, err)
		object := decodeJSONObject(t, raw)
		recipients, ok := object["recipients"].([]any)
		if !ok || len(recipients) != 2 {
			t.Fatalf("recipients = %#v, want 2 entries", object["recipients"])
		}
	})
}

func TestMultiEncrypterAuthData(t *testing.T) {
	key := testBytes(32, 54)
	encrypter, err := NewMultiEncrypter(
		[]jose.Recipient{{Algorithm: jose.A256KW, Key: key}},
		jose.A256GCM,
	)
	requireNoError(t, err)

	for _, authData := range [][]byte{nil, {}} {
		raw, err := encrypter.EncryptWithAuthData([]byte("payload"), authData)
		requireNoError(t, err)
		if _, exists := decodeJSONObject(t, raw)["aad"]; exists {
			t.Fatalf("empty auth data serialized as aad: %s", raw)
		}
	}

	authData := []byte("tenant=acme;record=42")
	raw, err := encrypter.EncryptWithAuthData([]byte("payload"), authData)
	requireNoError(t, err)
	encoded, ok := decodeJSONObject(t, raw)["aad"].(string)
	if !ok {
		t.Fatal("aad field is missing")
	}
	decoded, err := base64.RawURLEncoding.DecodeString(encoded)
	requireNoError(t, err)
	requireBytesEqual(t, decoded, authData)
}

func TestMultiEncrypterClonesRecipients(t *testing.T) {
	key := testBytes(32, 55)
	expectedKey := bytes.Clone(key)
	recipients := []jose.Recipient{{Algorithm: jose.A256KW, Key: key, KeyID: "original"}}

	encrypter, err := NewMultiEncrypter(recipients, jose.A256GCM)
	requireNoError(t, err)

	recipients[0].Algorithm = jose.A128KW
	recipients[0].KeyID = "mutated"
	for index := range key {
		key[index] ^= 0xff
	}

	raw, err := encrypter.Encrypt([]byte("payload"))
	requireNoError(t, err)
	decrypter, err := NewMultiDecrypter(
		expectedKey,
		[]jose.KeyAlgorithm{jose.A256KW},
		[]jose.ContentEncryption{jose.A256GCM},
	)
	requireNoError(t, err)
	decrypted, err := decrypter.DecryptToken(testContext(), raw)
	requireNoError(t, err)
	if decrypted.Header.KeyID != "original" {
		t.Fatalf("key ID = %q, want original", decrypted.Header.KeyID)
	}
}

func TestMultiEncrypterInteroperatesWithGoJOSE(t *testing.T) {
	key := testBytes(32, 56)
	plaintext := []byte("interoperable JSON JWE")
	authData := []byte("context")
	encrypter := newMultiRSAAndSymmetricEncrypter(
		t,
		key,
		WithHeader(jose.HeaderKey("keyset"), "2026-07"),
	)
	raw, err := encrypter.EncryptWithAuthData(plaintext, authData)
	requireNoError(t, err)

	object, err := jose.ParseEncryptedJSON(
		raw,
		[]jose.KeyAlgorithm{jose.RSA_OAEP_256, jose.A256KW},
		[]jose.ContentEncryption{jose.A256GCM},
	)
	requireNoError(t, err)
	index, _, got, err := object.DecryptMulti(key)
	requireNoError(t, err)
	if index != 1 {
		t.Fatalf("recipient index = %d, want 1", index)
	}
	requireBytesEqual(t, got, plaintext)
	requireBytesEqual(t, object.GetAuthData(), authData)

	backend, err := jose.NewMultiEncrypter(
		jose.A256GCM,
		[]jose.Recipient{
			{Algorithm: jose.RSA_OAEP_256, Key: &testRSAKey.PublicKey},
			{Algorithm: jose.A256KW, Key: key},
		},
		(&jose.EncrypterOptions{}).WithHeader(jose.HeaderKey("keyset"), "2026-07"),
	)
	requireNoError(t, err)
	object, err = backend.EncryptWithAuthData(plaintext, authData)
	requireNoError(t, err)

	decrypter, err := NewMultiDecrypter(
		key,
		[]jose.KeyAlgorithm{jose.RSA_OAEP_256, jose.A256KW},
		[]jose.ContentEncryption{jose.A256GCM},
	)
	requireNoError(t, err)
	decrypted, err := decrypter.DecryptToken(testContext(), object.FullSerialize())
	requireNoError(t, err)
	requireBytesEqual(t, decrypted.Plaintext, plaintext)
	requireBytesEqual(t, decrypted.AuthData, authData)
}

func TestMultiEncrypterConcurrentUse(t *testing.T) {
	firstKey := testBytes(32, 57)
	secondKey := testBytes(32, 58)
	encrypter, err := NewMultiEncrypter(
		[]jose.Recipient{
			{Algorithm: jose.A256KW, Key: firstKey},
			{Algorithm: jose.A256KW, Key: secondKey},
		},
		jose.A256GCM,
	)
	requireNoError(t, err)
	decrypter, err := NewMultiDecrypter(
		secondKey,
		[]jose.KeyAlgorithm{jose.A256KW},
		[]jose.ContentEncryption{jose.A256GCM},
	)
	requireNoError(t, err)

	const workers = 24
	var wait sync.WaitGroup
	errorsChannel := make(chan error, workers)

	for worker := 0; worker < workers; worker++ {
		wait.Add(1)
		go func(worker int) {
			defer wait.Done()
			plaintext := []byte(fmt.Sprintf("payload-%d", worker))
			raw, err := encrypter.EncryptWithAuthData(plaintext, []byte("context"))
			if err != nil {
				errorsChannel <- err
				return
			}
			decrypted, err := decrypter.DecryptToken(testContext(), raw)
			if err != nil {
				errorsChannel <- err
				return
			}
			if !bytes.Equal(decrypted.Plaintext, plaintext) || decrypted.RecipientIndex != 1 {
				errorsChannel <- fmt.Errorf("unexpected decrypted result: %#v", decrypted)
			}
		}(worker)
	}

	wait.Wait()
	close(errorsChannel)
	for err := range errorsChannel {
		if err != nil {
			t.Fatalf("concurrent multi-encryption failed: %v", err)
		}
	}
}

func TestMultiEncrypterProtectedHeaders(t *testing.T) {
	key := testBytes(32, 59)
	encrypter, err := NewMultiEncrypter(
		[]jose.Recipient{{Algorithm: jose.A256KW, Key: key}},
		jose.A256GCM,
		WithType("JWE"),
		WithContentType("application/json"),
		WithCompression(jose.DEFLATE),
		WithHeader(jose.HeaderKey("keyset"), "2026-07"),
	)
	requireNoError(t, err)
	raw, err := encrypter.Encrypt(bytes.Repeat([]byte("payload"), 20))
	requireNoError(t, err)

	header := protectedJSONHeader(t, raw)
	want := map[string]any{
		"alg":    string(jose.A256KW),
		"enc":    string(jose.A256GCM),
		"typ":    "JWE",
		"cty":    "application/json",
		"zip":    string(jose.DEFLATE),
		"keyset": "2026-07",
	}
	for name, value := range want {
		if header[name] != value {
			t.Fatalf("header[%q] = %#v, want %#v", name, header[name], value)
		}
	}

	encoded, err := json.Marshal(header)
	requireNoError(t, err)
	if len(encoded) == 0 {
		t.Fatal("protected header is empty")
	}
}

func TestMultiEncrypterWrapsHeaderSerializationFailure(t *testing.T) {
	encrypter, err := NewMultiEncrypter(
		[]jose.Recipient{{Algorithm: jose.A256KW, Key: testBytes(32, 60)}},
		jose.A256GCM,
		WithHeader(jose.HeaderKey("invalid"), make(chan struct{})),
	)
	requireNoError(t, err)

	_, err = encrypter.Encrypt([]byte("payload"))
	requireErrorIs(t, err, ErrEncrypt)
}
