package jwe

import (
	"bytes"
	"crypto/rand"
	"encoding/json"
	"sync"
	"testing"

	jose "github.com/go-jose/go-jose/v4"
)

func TestEncrypterKeyManagementAlgorithms(t *testing.T) {
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
			recipient:     jose.Recipient{Algorithm: jose.A128KW, Key: testBytes(16, 1)},
			decryptionKey: testBytes(16, 1),
		},
		{
			name:          "A192KW",
			recipient:     jose.Recipient{Algorithm: jose.A192KW, Key: testBytes(24, 2)},
			decryptionKey: testBytes(24, 2),
		},
		{
			name:          "A256KW",
			recipient:     jose.Recipient{Algorithm: jose.A256KW, Key: testBytes(32, 3)},
			decryptionKey: testBytes(32, 3),
		},
		{
			name:          "dir",
			recipient:     jose.Recipient{Algorithm: jose.DIRECT, Key: testBytes(32, 4)},
			decryptionKey: testBytes(32, 4),
		},
		{
			name:          "ECDH-ES",
			recipient:     jose.Recipient{Algorithm: jose.ECDH_ES, Key: &testECKey.PublicKey},
			decryptionKey: testECKey,
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
			recipient:     jose.Recipient{Algorithm: jose.A128GCMKW, Key: testBytes(16, 5)},
			decryptionKey: testBytes(16, 5),
		},
		{
			name:          "A192GCMKW",
			recipient:     jose.Recipient{Algorithm: jose.A192GCMKW, Key: testBytes(24, 6)},
			decryptionKey: testBytes(24, 6),
		},
		{
			name:          "A256GCMKW",
			recipient:     jose.Recipient{Algorithm: jose.A256GCMKW, Key: testBytes(32, 7)},
			decryptionKey: testBytes(32, 7),
		},
		{
			name: "PBES2-HS256+A128KW",
			recipient: jose.Recipient{
				Algorithm:  jose.PBES2_HS256_A128KW,
				Key:        password,
				PBES2Count: 1000,
				PBES2Salt:  testBytes(16, 8),
			},
			decryptionKey: password,
		},
		{
			name: "PBES2-HS384+A192KW",
			recipient: jose.Recipient{
				Algorithm:  jose.PBES2_HS384_A192KW,
				Key:        password,
				PBES2Count: 1000,
				PBES2Salt:  testBytes(16, 9),
			},
			decryptionKey: password,
		},
		{
			name: "PBES2-HS512+A256KW",
			recipient: jose.Recipient{
				Algorithm:  jose.PBES2_HS512_A256KW,
				Key:        password,
				PBES2Count: 1000,
				PBES2Salt:  testBytes(16, 10),
			},
			decryptionKey: password,
		},
	}

	plaintext := []byte("key-management-round-trip")

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			encrypter, err := NewEncrypter(test.recipient, jose.A256GCM)
			requireNoError(t, err)

			raw, err := encrypter.Encrypt(plaintext)
			requireNoError(t, err)

			decrypter, err := NewDecrypter(
				test.decryptionKey,
				[]jose.KeyAlgorithm{test.recipient.Algorithm},
				[]jose.ContentEncryption{jose.A256GCM},
			)
			requireNoError(t, err)

			got, err := decrypter.Decrypt(testContext(), raw)
			requireNoError(t, err)
			requireBytesEqual(t, got, plaintext)
		})
	}
}

func TestEncrypterContentEncryptionAlgorithms(t *testing.T) {
	tests := []struct {
		algorithm jose.ContentEncryption
		keySize   int
	}{
		{algorithm: jose.A128GCM, keySize: 16},
		{algorithm: jose.A192GCM, keySize: 24},
		{algorithm: jose.A256GCM, keySize: 32},
		{algorithm: jose.A128CBC_HS256, keySize: 32},
		{algorithm: jose.A192CBC_HS384, keySize: 48},
		{algorithm: jose.A256CBC_HS512, keySize: 64},
	}

	for _, test := range tests {
		t.Run(string(test.algorithm), func(t *testing.T) {
			key := testBytes(test.keySize, 11)
			encrypter, err := NewEncrypter(
				jose.Recipient{Algorithm: jose.DIRECT, Key: key},
				test.algorithm,
			)
			requireNoError(t, err)

			raw, err := encrypter.Encrypt([]byte("content-encryption-round-trip"))
			requireNoError(t, err)

			decrypter, err := NewDecrypter(
				key,
				[]jose.KeyAlgorithm{jose.DIRECT},
				[]jose.ContentEncryption{test.algorithm},
			)
			requireNoError(t, err)

			plaintext, err := decrypter.Decrypt(testContext(), raw)
			requireNoError(t, err)
			requireBytesEqual(t, plaintext, []byte("content-encryption-round-trip"))
		})
	}
}

func TestNewEncrypterRejectsInvalidConfiguration(t *testing.T) {
	tests := []struct {
		name       string
		recipient  jose.Recipient
		encryption jose.ContentEncryption
		options    []Option
	}{
		{
			name:       "missing algorithm",
			recipient:  jose.Recipient{Key: testBytes(32, 1)},
			encryption: jose.A256GCM,
		},
		{
			name:       "missing key",
			recipient:  jose.Recipient{Algorithm: jose.DIRECT},
			encryption: jose.A256GCM,
		},
		{
			name:      "missing content encryption",
			recipient: jose.Recipient{Algorithm: jose.DIRECT, Key: testBytes(32, 1)},
		},
		{
			name:       "invalid direct key size",
			recipient:  jose.Recipient{Algorithm: jose.DIRECT, Key: testBytes(16, 1)},
			encryption: jose.A256GCM,
		},
		{
			name:       "unsupported algorithm",
			recipient:  jose.Recipient{Algorithm: jose.ED25519, Key: &testRSAKey.PublicKey},
			encryption: jose.A256GCM,
		},
		{
			name:       "unsupported content encryption",
			recipient:  jose.Recipient{Algorithm: jose.DIRECT, Key: testBytes(32, 1)},
			encryption: jose.ContentEncryption("unsupported"),
		},
		{
			name:       "nil option",
			recipient:  jose.Recipient{Algorithm: jose.DIRECT, Key: testBytes(32, 1)},
			encryption: jose.A256GCM,
			options:    []Option{nil},
		},
		{
			name:       "unsupported compression",
			recipient:  jose.Recipient{Algorithm: jose.DIRECT, Key: testBytes(32, 1)},
			encryption: jose.A256GCM,
			options:    []Option{WithCompression(jose.CompressionAlgorithm("GZIP"))},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := NewEncrypter(test.recipient, test.encryption, test.options...)
			requireErrorIs(t, err, ErrInvalidConfig)
		})
	}
}

func TestEncrypterEncryptValidatesInput(t *testing.T) {
	key := testBytes(32, 12)
	encrypter := newDirectEncrypter(t, key)

	var nilEncrypter *Encrypter
	_, err := nilEncrypter.Encrypt([]byte("payload"))
	requireErrorIs(t, err, ErrInvalidConfig)

	_, err = encrypter.Encrypt(nil)
	requireErrorIs(t, err, ErrMissingPlaintext)

	limited, err := NewEncrypter(
		jose.Recipient{Algorithm: jose.DIRECT, Key: key},
		jose.A256GCM,
		WithMaxPlaintextSize(3),
	)
	requireNoError(t, err)
	_, err = limited.Encrypt([]byte("four"))
	requireErrorIs(t, err, ErrPlaintextTooLarge)

	tokenLimited, err := NewEncrypter(
		jose.Recipient{Algorithm: jose.DIRECT, Key: key},
		jose.A256GCM,
		WithMaxTokenSize(10),
	)
	requireNoError(t, err)
	_, err = tokenLimited.Encrypt([]byte("x"))
	requireErrorIs(t, err, ErrTokenTooLarge)
}

func TestEncrypterHeadersCompressionAndFreshCiphertext(t *testing.T) {
	key := testBytes(32, 13)
	encrypter := newDirectEncrypter(
		t,
		key,
		WithType("JWE"),
		WithContentType("application/json"),
		WithCompression(jose.DEFLATE),
		WithHeader(jose.HeaderKey("tenant"), "acme"),
	)
	plaintext := bytes.Repeat([]byte("compressible payload "), 50)

	first, err := encrypter.Encrypt(plaintext)
	requireNoError(t, err)
	second, err := encrypter.Encrypt(plaintext)
	requireNoError(t, err)
	if first == second {
		t.Fatal("repeated encryption produced identical compact JWE")
	}

	decrypter := newDirectDecrypter(
		t,
		key,
		WithType("JWE"),
		WithContentType("application/json"),
		WithCompression(jose.DEFLATE),
	)
	decrypted, err := decrypter.DecryptToken(testContext(), first)
	requireNoError(t, err)
	requireBytesEqual(t, decrypted.Plaintext, plaintext)

	if decrypted.Header.Type != "JWE" || decrypted.Header.ContentType != "application/json" {
		t.Fatalf("header = %#v", decrypted.Header)
	}
	if decrypted.Header.Compression != jose.DEFLATE {
		t.Fatalf("compression = %q, want %q", decrypted.Header.Compression, jose.DEFLATE)
	}
	if decrypted.Header.ExtraHeaders[jose.HeaderKey("tenant")] != "acme" {
		t.Fatalf("tenant = %#v", decrypted.Header.ExtraHeaders[jose.HeaderKey("tenant")])
	}
}

func TestEncrypterClonesSymmetricKeyAndPBES2Salt(t *testing.T) {
	key := testBytes(32, 14)
	originalKey := bytes.Clone(key)
	salt := testBytes(16, 15)
	originalSalt := bytes.Clone(salt)

	encrypter, err := NewEncrypter(
		jose.Recipient{
			Algorithm:  jose.PBES2_HS256_A128KW,
			Key:        key,
			PBES2Count: 1000,
			PBES2Salt:  salt,
		},
		jose.A256GCM,
	)
	requireNoError(t, err)

	for index := range key {
		key[index] ^= 0xff
	}
	for index := range salt {
		salt[index] ^= 0xff
	}

	raw, err := encrypter.Encrypt([]byte("payload"))
	requireNoError(t, err)
	decrypter, err := NewDecrypter(
		originalKey,
		[]jose.KeyAlgorithm{jose.PBES2_HS256_A128KW},
		[]jose.ContentEncryption{jose.A256GCM},
	)
	requireNoError(t, err)
	plaintext, err := decrypter.Decrypt(testContext(), raw)
	requireNoError(t, err)
	requireBytesEqual(t, plaintext, []byte("payload"))

	parts := compactParts(t, raw)
	protected, err := jose.ParseEncryptedCompact(
		raw,
		[]jose.KeyAlgorithm{jose.PBES2_HS256_A128KW},
		[]jose.ContentEncryption{jose.A256GCM},
	)
	requireNoError(t, err)
	_ = parts
	if protected.Header.ExtraHeaders[jose.HeaderKey("p2s")] == nil {
		t.Fatal("p2s header is missing")
	}
	if bytes.Equal(salt, originalSalt) {
		t.Fatal("test did not mutate source salt")
	}
}

func TestEncrypterInteroperatesWithGoJOSE(t *testing.T) {
	key := testBytes(32, 16)
	plaintext := []byte("interoperable payload")

	encrypter := newDirectEncrypter(t, key, WithType("JWE"))
	raw, err := encrypter.Encrypt(plaintext)
	requireNoError(t, err)

	object, err := jose.ParseEncryptedCompact(
		raw,
		[]jose.KeyAlgorithm{jose.DIRECT},
		[]jose.ContentEncryption{jose.A256GCM},
	)
	requireNoError(t, err)
	got, err := object.Decrypt(key)
	requireNoError(t, err)
	requireBytesEqual(t, got, plaintext)

	backend, err := jose.NewEncrypter(
		jose.A256GCM,
		jose.Recipient{Algorithm: jose.DIRECT, Key: key},
		(&jose.EncrypterOptions{}).WithType("JWE"),
	)
	requireNoError(t, err)
	object, err = backend.Encrypt(plaintext)
	requireNoError(t, err)
	raw, err = object.CompactSerialize()
	requireNoError(t, err)

	decrypter := newDirectDecrypter(t, key, WithType("JWE"))
	got, err = decrypter.Decrypt(testContext(), raw)
	requireNoError(t, err)
	requireBytesEqual(t, got, plaintext)
}

func TestEncrypterConcurrentUse(t *testing.T) {
	encrypter, err := NewEncrypter(
		jose.Recipient{Algorithm: jose.ECDH_ES, Key: &testECKey.PublicKey},
		jose.A256GCM,
	)
	requireNoError(t, err)
	decrypter, err := NewDecrypter(
		testECKey,
		[]jose.KeyAlgorithm{jose.ECDH_ES},
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

			plaintext, err := json.Marshal(map[string]int{"worker": worker})
			if err != nil {
				errorsChannel <- err
				return
			}
			raw, err := encrypter.Encrypt(plaintext)
			if err != nil {
				errorsChannel <- err
				return
			}
			got, err := decrypter.Decrypt(testContext(), raw)
			if err != nil {
				errorsChannel <- err
				return
			}
			if !bytes.Equal(got, plaintext) {
				errorsChannel <- bytes.ErrTooLarge
			}
		}(worker)
	}

	wait.Wait()
	close(errorsChannel)
	for err := range errorsChannel {
		if err != nil {
			t.Fatalf("concurrent encryption failed: %v", err)
		}
	}
}

func TestEncrypterUsesCryptographicRandomness(t *testing.T) {
	original := jose.RandReader
	jose.RandReader = rand.Reader
	t.Cleanup(func() { jose.RandReader = original })

	encrypter := newDirectEncrypter(t, testBytes(32, 17))
	first, err := encrypter.Encrypt([]byte("payload"))
	requireNoError(t, err)
	second, err := encrypter.Encrypt([]byte("payload"))
	requireNoError(t, err)
	if first == second {
		t.Fatal("ciphertexts unexpectedly match")
	}
}

func TestEncrypterWrapsHeaderSerializationFailure(t *testing.T) {
	encrypter, err := NewEncrypter(
		jose.Recipient{Algorithm: jose.DIRECT, Key: testBytes(32, 18)},
		jose.A256GCM,
		WithHeader(jose.HeaderKey("invalid"), make(chan struct{})),
	)
	requireNoError(t, err)

	_, err = encrypter.Encrypt([]byte("payload"))
	requireErrorIs(t, err, ErrEncrypt)
}
