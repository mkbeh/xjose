package jwe

import (
	"bytes"
	"testing"

	"github.com/go-jose/go-jose/v4"
)

func FuzzDecrypterDecryptToken(f *testing.F) {
	key := testBytes(32, 101)
	encrypter, err := NewEncrypter(
		jose.Recipient{Algorithm: jose.DIRECT, Key: key},
		jose.A256GCM,
	)
	if err != nil {
		f.Fatalf("create encrypter: %v", err)
	}
	valid, err := encrypter.Encrypt([]byte("seed payload"))
	if err != nil {
		f.Fatalf("encrypt seed: %v", err)
	}
	decrypter, err := NewDecrypter(
		key,
		[]jose.KeyAlgorithm{jose.DIRECT},
		[]jose.ContentEncryption{jose.A256GCM},
		WithMaxTokenSize(4096),
		WithMaxPlaintextSize(2048),
	)
	if err != nil {
		f.Fatalf("create decrypter: %v", err)
	}

	f.Add(valid)
	f.Add("")
	f.Add("not-a-jwe")
	f.Add("....")

	f.Fuzz(func(t *testing.T, raw string) {
		if len(raw) > 4096 {
			t.Skip()
		}

		_, _ = decrypter.DecryptToken(testContext(), raw)
	})
}

func FuzzMultiDecrypterDecryptToken(f *testing.F) {
	key := testBytes(32, 102)
	encrypter, err := NewMultiEncrypter(
		[]jose.Recipient{{Algorithm: jose.A256KW, Key: key}},
		jose.A256GCM,
	)
	if err != nil {
		f.Fatalf("create multi-encrypter: %v", err)
	}
	valid, err := encrypter.EncryptWithAuthData(
		[]byte("seed payload"),
		[]byte("seed context"),
	)
	if err != nil {
		f.Fatalf("encrypt seed: %v", err)
	}
	decrypter, err := NewMultiDecrypter(
		key,
		[]jose.KeyAlgorithm{jose.A256KW},
		[]jose.ContentEncryption{jose.A256GCM},
		WithMaxTokenSize(4096),
		WithMaxPlaintextSize(2048),
	)
	if err != nil {
		f.Fatalf("create multi-decrypter: %v", err)
	}

	f.Add(valid)
	f.Add("")
	f.Add("not-json")
	f.Add("{}")

	f.Fuzz(func(t *testing.T, raw string) {
		if len(raw) > 4096 {
			t.Skip()
		}

		_, _ = decrypter.DecryptToken(testContext(), raw)
	})
}

func FuzzCompactRoundTrip(f *testing.F) {
	key := testBytes(32, 103)
	encrypter, err := NewEncrypter(
		jose.Recipient{Algorithm: jose.DIRECT, Key: key},
		jose.A256GCM,
		WithMaxPlaintextSize(1024),
		WithMaxTokenSize(4096),
	)
	if err != nil {
		f.Fatalf("create encrypter: %v", err)
	}
	decrypter, err := NewDecrypter(
		key,
		[]jose.KeyAlgorithm{jose.DIRECT},
		[]jose.ContentEncryption{jose.A256GCM},
		WithMaxPlaintextSize(1024),
		WithMaxTokenSize(4096),
	)
	if err != nil {
		f.Fatalf("create decrypter: %v", err)
	}

	f.Add([]byte("payload"))
	f.Add([]byte{0, 1, 2, 3})

	f.Fuzz(func(t *testing.T, plaintext []byte) {
		if len(plaintext) == 0 || len(plaintext) > 1024 {
			t.Skip()
		}

		raw, err := encrypter.Encrypt(plaintext)
		if err != nil {
			t.Fatalf("encrypt: %v", err)
		}
		got, err := decrypter.Decrypt(testContext(), raw)
		if err != nil {
			t.Fatalf("decrypt: %v", err)
		}
		if !bytes.Equal(got, plaintext) {
			t.Fatalf("plaintext = %x, want %x", got, plaintext)
		}
	})
}

func FuzzMultiRoundTrip(f *testing.F) {
	key := testBytes(32, 104)
	encrypter, err := NewMultiEncrypter(
		[]jose.Recipient{{Algorithm: jose.A256KW, Key: key}},
		jose.A256GCM,
		WithMaxPlaintextSize(1024),
		WithMaxTokenSize(4096),
	)
	if err != nil {
		f.Fatalf("create multi-encrypter: %v", err)
	}
	decrypter, err := NewMultiDecrypter(
		key,
		[]jose.KeyAlgorithm{jose.A256KW},
		[]jose.ContentEncryption{jose.A256GCM},
		WithMaxPlaintextSize(1024),
		WithMaxTokenSize(4096),
	)
	if err != nil {
		f.Fatalf("create multi-decrypter: %v", err)
	}

	f.Add([]byte("payload"), []byte("context"))
	f.Add([]byte{0, 1, 2, 3}, []byte{})

	f.Fuzz(func(t *testing.T, plaintext, authData []byte) {
		if len(plaintext) == 0 || len(plaintext) > 1024 || len(authData) > 512 {
			t.Skip()
		}

		raw, err := encrypter.EncryptWithAuthData(plaintext, authData)
		if err != nil {
			t.Fatalf("encrypt: %v", err)
		}
		decrypted, err := decrypter.DecryptToken(testContext(), raw)
		if err != nil {
			t.Fatalf("decrypt: %v", err)
		}
		if !bytes.Equal(decrypted.Plaintext, plaintext) {
			t.Fatalf("plaintext = %x, want %x", decrypted.Plaintext, plaintext)
		}
		if !bytes.Equal(decrypted.AuthData, authData) {
			t.Fatalf("auth data = %x, want %x", decrypted.AuthData, authData)
		}
	})
}
