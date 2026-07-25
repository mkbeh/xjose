package jws

import (
	"bytes"
	"testing"

	jose "github.com/go-jose/go-jose/v4"
)

func TestSigningKeyValidationAndJWKMetadata(t *testing.T) {
	secret := bytes.Repeat([]byte{0x91}, 32)

	tests := []struct {
		name string
		key  SigningKey
	}{
		{
			name: "missing algorithm",
			key: SigningKey{
				Key: secret,
			},
		},
		{
			name: "missing key",
			key: SigningKey{
				Algorithm: jose.HS256,
			},
		},
		{
			name: "conflicting key ID",
			key: SigningKey{
				Algorithm: jose.HS256,
				KeyID:     "outer",
				Key: jose.JSONWebKey{
					Key:   secret,
					KeyID: "inner",
				},
			},
		},
		{
			name: "conflicting algorithm",
			key: SigningKey{
				Algorithm: jose.HS256,
				Key: jose.JSONWebKey{
					Key:       secret,
					Algorithm: string(jose.HS512),
				},
			},
		},
		{
			name: "invalid use",
			key: SigningKey{
				Algorithm: jose.HS256,
				Key: jose.JSONWebKey{
					Key: secret,
					Use: "enc",
				},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := test.key.build()
			requireErrorIs(t, err, ErrInvalidConfig)
		})
	}

	built, err := (SigningKey{
		Algorithm: jose.HS256,
		KeyID:     "key-1",
		Key: jose.JSONWebKey{
			Key: secret,
		},
	}).build()
	requireNoError(t, err)

	jwk, ok := built.Key.(jose.JSONWebKey)
	if !ok {
		t.Fatalf("built key type = %T, want jose.JSONWebKey", built.Key)
	}
	if jwk.KeyID != "key-1" || jwk.Algorithm != string(jose.HS256) || jwk.Use != "sig" {
		t.Fatalf("JWK metadata = %#v", jwk)
	}
}

func TestBuildSigningKeys(t *testing.T) {
	secret := bytes.Repeat([]byte{0x92}, 64)

	keys, err := buildSigningKeys([]SigningKey{
		{Algorithm: jose.HS256, KeyID: "one", Key: secret},
		{Algorithm: jose.HS512, KeyID: "two", Key: secret},
	})
	requireNoError(t, err)
	if len(keys) != 2 {
		t.Fatalf("key count = %d, want 2", len(keys))
	}

	_, err = buildSigningKeys([]SigningKey{
		{Algorithm: jose.HS256, Key: secret},
		{},
	})
	requireErrorIs(t, err, ErrInvalidConfig)
}
