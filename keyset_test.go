package xjwt

import (
	"testing"

	"github.com/golang-jwt/jwt/v5"
)

func TestStaticKeySetResolvesAnonymousAndNamedKeys(t *testing.T) {
	anonymous, err := NewVerificationKey("", jwt.SigningMethodHS256, testHMACSecret())
	requireNoError(t, err)
	anonymousSet, err := NewStaticKeySet(anonymous)
	requireNoError(t, err)

	resolved, err := anonymousSet.Resolve(testContext(), Header{Algorithm: jwt.SigningMethodHS256.Alg()})
	requireNoError(t, err)
	if resolved.ID() != "" {
		t.Fatalf("anonymous key ID = %q", resolved.ID())
	}

	first, err := NewVerificationKey("b-key", jwt.SigningMethodHS256, testHMACSecret())
	requireNoError(t, err)
	second, err := NewVerificationKey("a-key", jwt.SigningMethodHS256, testHMACSecret())
	requireNoError(t, err)
	namedSet, err := NewStaticKeySet(first, second)
	requireNoError(t, err)

	if namedSet.Len() != 2 {
		t.Fatalf("Len() = %d, want 2", namedSet.Len())
	}
	keys := namedSet.Keys()
	if keys[0].ID() != "a-key" || keys[1].ID() != "b-key" {
		t.Fatalf("Keys() order = [%q %q]", keys[0].ID(), keys[1].ID())
	}

	resolved, err = namedSet.Resolve(testContext(), Header{
		Algorithm: jwt.SigningMethodHS256.Alg(),
		KeyID:     "b-key",
	})
	requireNoError(t, err)
	if resolved.ID() != "b-key" {
		t.Fatalf("resolved key ID = %q, want %q", resolved.ID(), "b-key")
	}
}

func TestStaticKeySetRejectsInvalidConfiguration(t *testing.T) {
	key, err := NewVerificationKey("key-1", jwt.SigningMethodHS256, testHMACSecret())
	requireNoError(t, err)
	anonymous, err := NewVerificationKey("", jwt.SigningMethodHS256, testHMACSecret())
	requireNoError(t, err)

	_, err = NewStaticKeySet()
	requireErrorIs(t, err, ErrInvalidConfig)

	_, err = NewStaticKeySet(VerificationKey{})
	requireErrorIs(t, err, ErrInvalidKey)

	_, err = NewStaticKeySet(key, key)
	requireErrorIs(t, err, ErrDuplicateKeyID)

	_, err = NewStaticKeySet(anonymous, key)
	requireErrorIs(t, err, ErrInvalidConfig)
}

func TestStaticKeySetResolveErrors(t *testing.T) {
	key, err := NewVerificationKey("key-1", jwt.SigningMethodHS256, testHMACSecret())
	requireNoError(t, err)
	keySet, err := NewStaticKeySet(key)
	requireNoError(t, err)

	_, err = keySet.Resolve(testContext(), Header{Algorithm: jwt.SigningMethodHS256.Alg()})
	requireErrorIs(t, err, ErrMissingKeyID)

	_, err = keySet.Resolve(testContext(), Header{
		Algorithm: jwt.SigningMethodHS256.Alg(),
		KeyID:     "unknown",
	})
	requireErrorIs(t, err, ErrUnknownKey)

	_, err = keySet.Resolve(testContext(), Header{
		Algorithm: jwt.SigningMethodHS384.Alg(),
		KeyID:     "key-1",
	})
	requireErrorIs(t, err, ErrUnexpectedAlgorithm)

	var nilSet *StaticKeySet
	_, err = nilSet.Resolve(testContext(), Header{})
	requireErrorIs(t, err, ErrInvalidConfig)

	if nilSet.Len() != 0 || nilSet.Keys() != nil {
		t.Fatal("nil key set accessors returned non-zero values")
	}
}
