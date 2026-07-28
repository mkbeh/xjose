package jwe

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"testing"

	"github.com/go-jose/go-jose/v4"
)

const (
	benchmarkMaxTokenSize     = 128 << 10
	benchmarkMaxPlaintextSize = 64 << 10
)

var (
	benchmarkStringSink string
	benchmarkBytesSink  []byte
)

func BenchmarkEncrypterEncrypt(b *testing.B) {
	privateKey := benchmarkRSAKey(b)

	algorithms := []struct {
		name      string
		recipient jose.Recipient
	}{
		{
			name: "Direct_A256GCM",
			recipient: jose.Recipient{
				Algorithm: jose.DIRECT,
				Key:       benchmarkBytes(32, 1),
			},
		},
		{
			name: "RSA-OAEP-256_A256GCM",
			recipient: jose.Recipient{
				Algorithm: jose.RSA_OAEP_256,
				Key:       &privateKey.PublicKey,
			},
		},
	}

	for _, algorithm := range algorithms {
		b.Run(algorithm.name, func(b *testing.B) {
			for _, size := range benchmarkPayloadSizes() {
				b.Run(size.name, func(b *testing.B) {
					plaintext := benchmarkBytes(size.bytes, 11)

					encrypter, err := NewEncrypter(
						algorithm.recipient,
						jose.A256GCM,
						benchmarkOptions()...,
					)
					if err != nil {
						b.Fatal(err)
					}

					b.ReportAllocs()
					b.SetBytes(int64(len(plaintext)))
					b.ResetTimer()

					var raw string
					for i := 0; i < b.N; i++ {
						raw, err = encrypter.Encrypt(plaintext)
						if err != nil {
							b.Fatal(err)
						}
					}

					benchmarkStringSink = raw
				})
			}
		})
	}
}

func BenchmarkDecrypterDecrypt(b *testing.B) {
	ctx := context.Background()
	privateKey := benchmarkRSAKey(b)

	algorithms := []struct {
		name         string
		recipient    jose.Recipient
		decryptKey   any
		keyAlgorithm jose.KeyAlgorithm
	}{
		{
			name: "Direct_A256GCM",
			recipient: jose.Recipient{
				Algorithm: jose.DIRECT,
				Key:       benchmarkBytes(32, 21),
			},
			decryptKey:   benchmarkBytes(32, 21),
			keyAlgorithm: jose.DIRECT,
		},
		{
			name: "RSA-OAEP-256_A256GCM",
			recipient: jose.Recipient{
				Algorithm: jose.RSA_OAEP_256,
				Key:       &privateKey.PublicKey,
			},
			decryptKey:   privateKey,
			keyAlgorithm: jose.RSA_OAEP_256,
		},
	}

	for _, algorithm := range algorithms {
		b.Run(algorithm.name, func(b *testing.B) {
			for _, size := range benchmarkPayloadSizes() {
				b.Run(size.name, func(b *testing.B) {
					plaintext := benchmarkBytes(size.bytes, 31)

					encrypter, err := NewEncrypter(
						algorithm.recipient,
						jose.A256GCM,
						benchmarkOptions()...,
					)
					if err != nil {
						b.Fatal(err)
					}

					raw, err := encrypter.Encrypt(plaintext)
					if err != nil {
						b.Fatal(err)
					}

					decrypter, err := NewDecrypter(
						algorithm.decryptKey,
						[]jose.KeyAlgorithm{algorithm.keyAlgorithm},
						[]jose.ContentEncryption{jose.A256GCM},
						benchmarkOptions()...,
					)
					if err != nil {
						b.Fatal(err)
					}

					decrypted, err := decrypter.Decrypt(ctx, raw)
					if err != nil {
						b.Fatal(err)
					}
					if len(decrypted) != len(plaintext) {
						b.Fatalf("decrypted plaintext size = %d, want %d", len(decrypted), len(plaintext))
					}

					b.ReportAllocs()
					b.SetBytes(int64(len(plaintext)))
					b.ResetTimer()

					for i := 0; i < b.N; i++ {
						decrypted, err = decrypter.Decrypt(ctx, raw)
						if err != nil {
							b.Fatal(err)
						}
					}

					benchmarkBytesSink = decrypted
				})
			}
		})
	}
}

func BenchmarkMultiEncrypterEncrypt(b *testing.B) {
	plaintext := benchmarkBytes(1<<10, 41)

	for _, recipientCount := range []int{1, 2, 4, 8} {
		b.Run(fmt.Sprintf("Recipients=%d", recipientCount), func(b *testing.B) {
			recipients, _ := benchmarkRecipients(recipientCount)

			encrypter, err := NewMultiEncrypter(
				recipients,
				jose.A256GCM,
				benchmarkOptions()...,
			)
			if err != nil {
				b.Fatal(err)
			}

			b.Run("NoAAD", func(b *testing.B) {
				b.ReportAllocs()
				b.SetBytes(int64(len(plaintext)))
				b.ResetTimer()

				var raw string
				for i := 0; i < b.N; i++ {
					raw, err = encrypter.Encrypt(plaintext)
					if err != nil {
						b.Fatal(err)
					}
				}

				benchmarkStringSink = raw
			})

			if recipientCount == 2 {
				authData := benchmarkBytes(64, 51)

				b.Run("AAD=64B", func(b *testing.B) {
					b.ReportAllocs()
					b.SetBytes(int64(len(plaintext)))
					b.ResetTimer()

					var raw string
					for i := 0; i < b.N; i++ {
						raw, err = encrypter.EncryptWithAuthData(plaintext, authData)
						if err != nil {
							b.Fatal(err)
						}
					}

					benchmarkStringSink = raw
				})
			}
		})
	}
}

func BenchmarkMultiDecrypterDecrypt(b *testing.B) {
	ctx := context.Background()
	plaintext := benchmarkBytes(1<<10, 61)

	tests := []struct {
		recipientCount int
		selectedIndex  int
		withAuthData   bool
	}{
		{recipientCount: 1, selectedIndex: 0},
		{recipientCount: 2, selectedIndex: 0},
		{recipientCount: 2, selectedIndex: 1},
		{recipientCount: 4, selectedIndex: 3},
		{recipientCount: 8, selectedIndex: 7},
		{recipientCount: 2, selectedIndex: 1, withAuthData: true},
	}

	for _, test := range tests {
		name := fmt.Sprintf(
			"Recipients=%d/Selected=%d",
			test.recipientCount,
			test.selectedIndex,
		)
		if test.withAuthData {
			name += "/AAD=64B"
		}

		b.Run(name, func(b *testing.B) {
			recipients, keys := benchmarkRecipients(test.recipientCount)

			encrypter, err := NewMultiEncrypter(
				recipients,
				jose.A256GCM,
				benchmarkOptions()...,
			)
			if err != nil {
				b.Fatal(err)
			}

			var raw string
			if test.withAuthData {
				raw, err = encrypter.EncryptWithAuthData(
					plaintext,
					benchmarkBytes(64, 71),
				)
			} else {
				raw, err = encrypter.Encrypt(plaintext)
			}
			if err != nil {
				b.Fatal(err)
			}

			decrypter, err := NewMultiDecrypter(
				keys[test.selectedIndex],
				[]jose.KeyAlgorithm{jose.A256KW},
				[]jose.ContentEncryption{jose.A256GCM},
				benchmarkOptions()...,
			)
			if err != nil {
				b.Fatal(err)
			}

			decrypted, err := decrypter.Decrypt(ctx, raw)
			if err != nil {
				b.Fatal(err)
			}
			if len(decrypted) != len(plaintext) {
				b.Fatalf("decrypted plaintext size = %d, want %d", len(decrypted), len(plaintext))
			}

			b.ReportAllocs()
			b.SetBytes(int64(len(plaintext)))
			b.ResetTimer()

			for i := 0; i < b.N; i++ {
				decrypted, err = decrypter.Decrypt(ctx, raw)
				if err != nil {
					b.Fatal(err)
				}
			}

			benchmarkBytesSink = decrypted
		})
	}
}

func benchmarkRSAKey(b *testing.B) *rsa.PrivateKey {
	b.Helper()

	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		b.Fatal(err)
	}

	return privateKey
}

func benchmarkRecipients(count int) ([]jose.Recipient, [][]byte) {
	recipients := make([]jose.Recipient, count)
	keys := make([][]byte, count)

	for index := range count {
		key := benchmarkBytes(32, byte(81+index))
		keys[index] = key
		recipients[index] = jose.Recipient{
			Algorithm: jose.A256KW,
			Key:       key,
			KeyID:     fmt.Sprintf("recipient-%d", index),
		}
	}

	return recipients, keys
}

func benchmarkPayloadSizes() []struct {
	name  string
	bytes int
} {
	return []struct {
		name  string
		bytes int
	}{
		{name: "128B", bytes: 128},
		{name: "1KiB", bytes: 1 << 10},
		{name: "16KiB", bytes: 16 << 10},
	}
}

func benchmarkOptions() []Option {
	return []Option{
		WithMaxTokenSize(benchmarkMaxTokenSize),
		WithMaxPlaintextSize(benchmarkMaxPlaintextSize),
	}
}

func benchmarkBytes(size int, seed byte) []byte {
	value := make([]byte, size)
	for index := range value {
		value[index] = seed + byte(index%17)
	}

	return value
}
