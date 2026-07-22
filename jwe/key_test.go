package jwe

import (
	"bytes"
	"testing"

	"github.com/go-jose/go-jose/v4"
)

func TestCloneKeyMaterial(t *testing.T) {
	t.Run("byte slice", func(t *testing.T) {
		original := []byte("secret")
		cloned := cloneKeyMaterial(original).([]byte)
		cloned[0] ^= 0xff
		if bytes.Equal(original, cloned) {
			t.Fatal("byte slice shares storage")
		}
	})

	t.Run("JWK value", func(t *testing.T) {
		originalKey := []byte("secret")
		original := jose.JSONWebKey{Key: originalKey, KeyID: "key"}
		cloned := cloneKeyMaterial(original).(jose.JSONWebKey)
		cloned.Key.([]byte)[0] ^= 0xff
		if !bytes.Equal(originalKey, []byte("secret")) {
			t.Fatal("JWK key material shares storage")
		}
	})

	t.Run("JWK pointer", func(t *testing.T) {
		originalKey := []byte("secret")
		original := &jose.JSONWebKey{Key: originalKey, KeyID: "key"}
		cloned := cloneKeyMaterial(original).(*jose.JSONWebKey)
		if cloned == original {
			t.Fatal("JWK pointer was not cloned")
		}
		cloned.Key.([]byte)[0] ^= 0xff
		if !bytes.Equal(originalKey, []byte("secret")) {
			t.Fatal("JWK key material shares storage")
		}
	})

	t.Run("nil JWK pointer", func(t *testing.T) {
		var original *jose.JSONWebKey
		if cloneKeyMaterial(original) != original {
			t.Fatal("nil JWK pointer changed")
		}
	})

	t.Run("opaque object retained", func(t *testing.T) {
		original := &struct{ value int }{value: 1}
		if cloneKeyMaterial(original) != original {
			t.Fatal("unknown key object should be retained")
		}
	})
}

func TestCloneRecipients(t *testing.T) {
	key := []byte("0123456789abcdef0123456789abcdef")
	salt := []byte("0123456789abcdef")
	original := []jose.Recipient{{
		Algorithm:  jose.PBES2_HS256_A128KW,
		Key:        key,
		KeyID:      "key",
		PBES2Count: 1000,
		PBES2Salt:  salt,
	}}

	cloned := cloneRecipients(original)
	cloned[0].Key.([]byte)[0] ^= 0xff
	cloned[0].PBES2Salt[0] ^= 0xff
	cloned[0].KeyID = "changed"

	if !bytes.Equal(key, []byte("0123456789abcdef0123456789abcdef")) {
		t.Fatal("recipient key shares storage")
	}
	if !bytes.Equal(salt, []byte("0123456789abcdef")) {
		t.Fatal("recipient salt shares storage")
	}
	if original[0].KeyID != "key" {
		t.Fatal("recipient descriptor shares storage")
	}
}
