package jws

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"

	jose "github.com/go-jose/go-jose/v4"
)

const (
	testType        = "example+jws"
	testContentType = "application/json"
)

type signingFixture struct {
	name            string
	algorithm       jose.SignatureAlgorithm
	keyID           string
	signingKey      any
	verificationKey any
}

func testSigningFixtures(t *testing.T) []signingFixture {
	t.Helper()

	rsaKey, err := rsa.GenerateKey(rand.Reader, 1024)
	requireNoError(t, err)

	ecdsaKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	requireNoError(t, err)

	edPublic, edPrivate, err := ed25519.GenerateKey(rand.Reader)
	requireNoError(t, err)

	hmacKey := bytes.Repeat([]byte{0x42}, 32)

	return []signingFixture{
		{
			name:       "HS256",
			algorithm:  jose.HS256,
			keyID:      "hmac-2026-07",
			signingKey: hmacKey,
			verificationKey: jose.JSONWebKey{
				Key:       bytes.Clone(hmacKey),
				KeyID:     "hmac-2026-07",
				Algorithm: string(jose.HS256),
				Use:       "sig",
			},
		},
		{
			name:       "PS256",
			algorithm:  jose.PS256,
			keyID:      "rsa-2026-07",
			signingKey: rsaKey,
			verificationKey: jose.JSONWebKey{
				Key:       &rsaKey.PublicKey,
				KeyID:     "rsa-2026-07",
				Algorithm: string(jose.PS256),
				Use:       "sig",
			},
		},
		{
			name:       "ES256",
			algorithm:  jose.ES256,
			keyID:      "ecdsa-2026-07",
			signingKey: ecdsaKey,
			verificationKey: jose.JSONWebKey{
				Key:       &ecdsaKey.PublicKey,
				KeyID:     "ecdsa-2026-07",
				Algorithm: string(jose.ES256),
				Use:       "sig",
			},
		},
		{
			name:       "EdDSA",
			algorithm:  jose.EdDSA,
			keyID:      "ed25519-2026-07",
			signingKey: edPrivate,
			verificationKey: jose.JSONWebKey{
				Key:       edPublic,
				KeyID:     "ed25519-2026-07",
				Algorithm: string(jose.EdDSA),
				Use:       "sig",
			},
		},
	}
}

func newHMACSigner(t *testing.T, key []byte, keyID string, options ...Option) *Signer {
	t.Helper()

	signer, err := NewSigner(
		SigningKey{
			Algorithm: jose.HS256,
			KeyID:     keyID,
			Key:       key,
		},
		options...,
	)
	requireNoError(t, err)

	return signer
}

func newHMACVerifier(t *testing.T, key []byte, keyID string, options ...Option) *Verifier {
	t.Helper()

	verificationKey := any(key)
	if keyID != "" {
		verificationKey = jose.JSONWebKey{
			Key:       key,
			KeyID:     keyID,
			Algorithm: string(jose.HS256),
			Use:       "sig",
		}
	}

	verifier, err := NewVerifier(
		verificationKey,
		[]jose.SignatureAlgorithm{jose.HS256},
		options...,
	)
	requireNoError(t, err)

	return verifier
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

func parseCompact(t *testing.T, raw string, algorithms ...jose.SignatureAlgorithm) *jose.JSONWebSignature {
	t.Helper()

	object, err := jose.ParseSignedCompact(raw, algorithms)
	requireNoError(t, err)

	return object
}

func corruptBase64URL(value string) string {
	decoded, err := base64.RawURLEncoding.DecodeString(value)
	if err != nil || len(decoded) == 0 {
		return value + "A"
	}

	decoded[0] ^= 0x01

	return base64.RawURLEncoding.EncodeToString(decoded)
}

func corruptCompactSignature(raw string) string {
	parts := strings.Split(raw, ".")
	if len(parts) != 3 {
		return raw + "."
	}

	parts[2] = corruptBase64URL(parts[2])

	return strings.Join(parts, ".")
}

func corruptFirstJSONSignature(t *testing.T, raw string) string {
	t.Helper()

	var object struct {
		Payload    string `json:"payload"`
		Signatures []struct {
			Protected string `json:"protected"`
			Header    any    `json:"header,omitempty"`
			Signature string `json:"signature"`
		} `json:"signatures"`
	}

	requireNoError(t, json.Unmarshal([]byte(raw), &object))
	if len(object.Signatures) == 0 {
		t.Fatal("JWS JSON contains no signatures")
	}

	object.Signatures[0].Signature = corruptBase64URL(
		object.Signatures[0].Signature,
	)

	encoded, err := json.Marshal(object)
	requireNoError(t, err)

	return string(encoded)
}

type trustedKey struct {
	algorithm jose.SignatureAlgorithm
	key       any
}

func newMapResolver(keys map[string]trustedKey) KeyResolver {
	return KeyResolverFunc(func(
		ctx context.Context,
		header Header,
	) (ResolvedKey, error) {
		if err := ctx.Err(); err != nil {
			return ResolvedKey{}, err
		}

		trusted, exists := keys[header.KeyID]
		if !exists || trusted.algorithm != header.Algorithm {
			return ResolvedKey{}, fmt.Errorf(
				"%w: key ID %q",
				ErrKeyNotFound,
				header.KeyID,
			)
		}

		return ResolvedKey{
			KeyID: header.KeyID,
			Key:   trusted.key,
		}, nil
	})
}

type opaqueEdSigner struct {
	privateKey ed25519.PrivateKey
	publicKey  ed25519.PublicKey

	mu    sync.RWMutex
	keyID string
}

var _ jose.OpaqueSigner = (*opaqueEdSigner)(nil)

func newOpaqueEdSigner(t *testing.T, keyID string) *opaqueEdSigner {
	t.Helper()

	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	requireNoError(t, err)

	return &opaqueEdSigner{
		privateKey: privateKey,
		publicKey:  publicKey,
		keyID:      keyID,
	}
}

func (signer *opaqueEdSigner) Public() *jose.JSONWebKey {
	signer.mu.RLock()
	defer signer.mu.RUnlock()

	return &jose.JSONWebKey{
		Key:       signer.publicKey,
		KeyID:     signer.keyID,
		Algorithm: string(jose.EdDSA),
		Use:       "sig",
	}
}

func (*opaqueEdSigner) Algs() []jose.SignatureAlgorithm {
	return []jose.SignatureAlgorithm{jose.EdDSA}
}

func (signer *opaqueEdSigner) SignPayload(
	payload []byte,
	algorithm jose.SignatureAlgorithm,
) ([]byte, error) {
	if algorithm != jose.EdDSA {
		return nil, fmt.Errorf("unsupported algorithm %q", algorithm)
	}

	return ed25519.Sign(signer.privateKey, payload), nil
}

func (signer *opaqueEdSigner) setKeyID(keyID string) {
	signer.mu.Lock()
	defer signer.mu.Unlock()

	signer.keyID = keyID
}

type multiFixture struct {
	keys       []SigningKey
	algorithms []jose.SignatureAlgorithm
	resolver   KeyResolver
}

func newMultiFixture(t *testing.T) multiFixture {
	t.Helper()

	rsaKey, err := rsa.GenerateKey(rand.Reader, 1024)
	requireNoError(t, err)

	edPublic, edPrivate, err := ed25519.GenerateKey(rand.Reader)
	requireNoError(t, err)

	return multiFixture{
		keys: []SigningKey{
			{
				Algorithm: jose.PS256,
				KeyID:     "issuer",
				Key:       rsaKey,
			},
			{
				Algorithm: jose.EdDSA,
				KeyID:     "approval",
				Key:       edPrivate,
			},
		},
		algorithms: []jose.SignatureAlgorithm{
			jose.PS256,
			jose.EdDSA,
		},
		resolver: newMapResolver(map[string]trustedKey{
			"issuer": {
				algorithm: jose.PS256,
				key:       &rsaKey.PublicKey,
			},
			"approval": {
				algorithm: jose.EdDSA,
				key:       edPublic,
			},
		}),
	}
}

func signMultiFixture(t *testing.T, fixture multiFixture, payload []byte) string {
	t.Helper()

	signer, err := NewMultiSigner(
		fixture.keys,
		WithType(testType),
		WithContentType(testContentType),
	)
	requireNoError(t, err)

	raw, err := signer.Sign(payload)
	requireNoError(t, err)

	return raw
}
