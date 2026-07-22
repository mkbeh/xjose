package jwe

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"

	jose "github.com/go-jose/go-jose/v4"
)

var (
	testRSAKey *rsa.PrivateKey
	testECKey  *ecdsa.PrivateKey
)

func TestMain(m *testing.M) {
	var err error

	testRSAKey, err = rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(fmt.Sprintf("generate RSA test key: %v", err))
	}
	testRSAKey.Precompute()

	testECKey, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		panic(fmt.Sprintf("generate ECDSA test key: %v", err))
	}

	os.Exit(m.Run())
}

func testContext() context.Context {
	return context.Background()
}

func testBytes(size int, seed byte) []byte {
	result := make([]byte, size)
	for index := range result {
		result[index] = seed + byte(index%17)
	}

	return result
}

func requireNoError(t *testing.T, err error) {
	t.Helper()

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func requireErrorIs(t *testing.T, err, target error) {
	t.Helper()

	if !errors.Is(err, target) {
		t.Fatalf("error = %v, want errors.Is(_, %v)", err, target)
	}
}

func requireBytesEqual(t *testing.T, got, want []byte) {
	t.Helper()

	if !bytes.Equal(got, want) {
		t.Fatalf("bytes = %q, want %q", got, want)
	}
}

func requireStringEqual(t *testing.T, got, want string) {
	t.Helper()

	if got != want {
		t.Fatalf("string = %q, want %q", got, want)
	}
}

func compactParts(t *testing.T, raw string) []string {
	t.Helper()

	parts := strings.Split(raw, ".")
	if len(parts) != 5 {
		t.Fatalf("compact JWE has %d parts, want 5", len(parts))
	}

	return parts
}

func rewriteCompactProtected(
	t *testing.T,
	raw string,
	mutate func(map[string]any),
) string {
	t.Helper()

	parts := compactParts(t, raw)
	protected, err := base64.RawURLEncoding.DecodeString(parts[0])
	requireNoError(t, err)

	var header map[string]any
	requireNoError(t, json.Unmarshal(protected, &header))
	mutate(header)

	protected, err = json.Marshal(header)
	requireNoError(t, err)
	parts[0] = base64.RawURLEncoding.EncodeToString(protected)

	return strings.Join(parts, ".")
}

func tamperCompactPart(t *testing.T, raw string, part int) string {
	t.Helper()

	parts := compactParts(t, raw)
	decoded, err := base64.RawURLEncoding.DecodeString(parts[part])
	requireNoError(t, err)

	if len(decoded) == 0 {
		decoded = []byte{1}
	} else {
		decoded[0] ^= 0x80
	}
	parts[part] = base64.RawURLEncoding.EncodeToString(decoded)

	return strings.Join(parts, ".")
}

func decodeJSONObject(t *testing.T, raw string) map[string]any {
	t.Helper()

	var object map[string]any
	requireNoError(t, json.Unmarshal([]byte(raw), &object))

	return object
}

func rewriteJSONObject(
	t *testing.T,
	raw string,
	mutate func(map[string]any),
) string {
	t.Helper()

	object := decodeJSONObject(t, raw)
	mutate(object)

	encoded, err := json.Marshal(object)
	requireNoError(t, err)

	return string(encoded)
}

func tamperJSONBase64Field(t *testing.T, raw, name string) string {
	t.Helper()

	return rewriteJSONObject(t, raw, func(object map[string]any) {
		value, ok := object[name].(string)
		if !ok {
			t.Fatalf("JSON field %q is %T, want string", name, object[name])
		}

		decoded, err := base64.RawURLEncoding.DecodeString(value)
		requireNoError(t, err)
		if len(decoded) == 0 {
			decoded = []byte{1}
		} else {
			decoded[0] ^= 0x80
		}
		object[name] = base64.RawURLEncoding.EncodeToString(decoded)
	})
}

func protectedJSONHeader(t *testing.T, raw string) map[string]any {
	t.Helper()

	object := decodeJSONObject(t, raw)
	encoded, ok := object["protected"].(string)
	if !ok {
		t.Fatalf("protected field is %T, want string", object["protected"])
	}

	decoded, err := base64.RawURLEncoding.DecodeString(encoded)
	requireNoError(t, err)

	var header map[string]any
	requireNoError(t, json.Unmarshal(decoded, &header))

	return header
}

func newDirectEncrypter(t *testing.T, key []byte, options ...Option) *Encrypter {
	t.Helper()

	encrypter, err := NewEncrypter(
		jose.Recipient{
			Algorithm: jose.DIRECT,
			Key:       key,
			KeyID:     "encryption-key",
		},
		jose.A256GCM,
		options...,
	)
	requireNoError(t, err)

	return encrypter
}

func newDirectDecrypter(t *testing.T, key []byte, options ...Option) *Decrypter {
	t.Helper()

	decrypter, err := NewDecrypter(
		key,
		[]jose.KeyAlgorithm{jose.DIRECT},
		[]jose.ContentEncryption{jose.A256GCM},
		options...,
	)
	requireNoError(t, err)

	return decrypter
}

func newMultiRSAAndSymmetricEncrypter(
	t *testing.T,
	key []byte,
	options ...Option,
) *MultiEncrypter {
	t.Helper()

	encrypter, err := NewMultiEncrypter(
		[]jose.Recipient{
			{
				Algorithm: jose.RSA_OAEP_256,
				Key:       &testRSAKey.PublicKey,
				KeyID:     "rsa-recipient",
			},
			{
				Algorithm: jose.A256KW,
				Key:       key,
				KeyID:     "symmetric-recipient",
			},
		},
		jose.A256GCM,
		options...,
	)
	requireNoError(t, err)

	return encrypter
}
