package jwks

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"sync"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	gojwt "github.com/golang-jwt/jwt/v5"
	"github.com/mkbeh/xjose/jwt"
)

type keyFixture struct {
	name       string
	keyID      string
	method     gojwt.SigningMethod
	privateKey any
	publicKey  any
}

type accessClaims struct {
	UserID string `json:"user_id"`

	gojwt.RegisteredClaims
}

func TestNew(t *testing.T) {
	fixtures := asymmetricKeyFixtures(t)
	keys := make([]Key, 0, len(fixtures))

	for _, fixture := range fixtures {
		keys = append(keys, Key{
			Key:       fixture.publicKey,
			KeyID:     fixture.keyID,
			Algorithm: fixture.method.Alg(),
			Use:       keyUseSignature,
		})
	}

	set, err := New(keys...)
	requireNoError(t, err)

	returned := set.Keys()
	if len(returned) != len(keys) {
		t.Fatalf("Keys() length = %d, want %d", len(returned), len(keys))
	}

	for index, key := range returned {
		if key.KeyID != keys[index].KeyID {
			t.Fatalf("Keys()[%d].KeyID = %q, want %q", index, key.KeyID, keys[index].KeyID)
		}
		if key.Algorithm != keys[index].Algorithm {
			t.Fatalf(
				"Keys()[%d].Algorithm = %q, want %q",
				index,
				key.Algorithm,
				keys[index].Algorithm,
			)
		}
		if key.Use != keyUseSignature {
			t.Fatalf("Keys()[%d].Use = %q, want %q", index, key.Use, keyUseSignature)
		}
		if !reflect.DeepEqual(key.Key, keys[index].Key) {
			t.Fatalf("Keys()[%d] contains unexpected key material", index)
		}
	}
}

func TestNewAllowsSingleAnonymousKey(t *testing.T) {
	fixture := asymmetricKeyFixtures(t)[0]

	set, err := New(Key{
		Key:       fixture.publicKey,
		Algorithm: fixture.method.Alg(),
		Use:       keyUseSignature,
	})
	requireNoError(t, err)

	resolved, err := set.Resolve(context.Background(), jwt.Header{
		Algorithm: fixture.method.Alg(),
	})
	requireNoError(t, err)

	if resolved.ID() != "" {
		t.Fatalf("resolved key ID = %q, want empty", resolved.ID())
	}
	if resolved.Method().Alg() != fixture.method.Alg() {
		t.Fatalf(
			"resolved algorithm = %q, want %q",
			resolved.Method().Alg(),
			fixture.method.Alg(),
		)
	}
}

func TestNewRejectsInvalidSets(t *testing.T) {
	fixtures := asymmetricKeyFixtures(t)

	privateKey := Key{
		Key:       fixtures[0].privateKey,
		KeyID:     "private",
		Algorithm: fixtures[0].method.Alg(),
		Use:       keyUseSignature,
	}
	symmetricKey := Key{
		Key:       bytes.Repeat([]byte{0x42}, 32),
		KeyID:     "symmetric",
		Algorithm: gojwt.SigningMethodHS256.Alg(),
		Use:       keyUseSignature,
	}
	anonymous := Key{
		Key:       fixtures[0].publicKey,
		Algorithm: fixtures[0].method.Alg(),
		Use:       keyUseSignature,
	}
	named := Key{
		Key:       fixtures[1].publicKey,
		KeyID:     "named",
		Algorithm: fixtures[1].method.Alg(),
		Use:       keyUseSignature,
	}
	duplicateA := named
	duplicateA.KeyID = "duplicate"
	duplicateB := Key{
		Key:       fixtures[2].publicKey,
		KeyID:     "duplicate",
		Algorithm: fixtures[2].method.Alg(),
		Use:       keyUseSignature,
	}

	tests := []struct {
		name string
		keys []Key
		want error
	}{
		{name: "empty", keys: nil, want: jwt.ErrInvalidKey},
		{name: "zero key", keys: []Key{{}}, want: jwt.ErrInvalidKey},
		{name: "private key", keys: []Key{privateKey}, want: jwt.ErrInvalidKey},
		{name: "symmetric key", keys: []Key{symmetricKey}, want: jwt.ErrInvalidKey},
		{name: "anonymous in multi-key set", keys: []Key{anonymous, named}, want: jwt.ErrInvalidKey},
		{name: "duplicate key ID", keys: []Key{duplicateA, duplicateB}, want: jwt.ErrDuplicateKeyID},
	}

	for _, testCase := range tests {
		t.Run(testCase.name, func(t *testing.T) {
			_, err := New(testCase.keys...)
			requireErrorIs(t, err, testCase.want)
		})
	}
}

func TestParse(t *testing.T) {
	fixtures := asymmetricKeyFixtures(t)
	original := make([]Key, 0, len(fixtures))

	for _, fixture := range fixtures {
		original = append(original, Key{
			Key:       fixture.publicKey,
			KeyID:     fixture.keyID,
			Algorithm: fixture.method.Alg(),
			Use:       keyUseSignature,
		})
	}

	data, err := json.Marshal(jose.JSONWebKeySet{Keys: original})
	requireNoError(t, err)

	set, err := Parse(data)
	requireNoError(t, err)

	parsed := set.Keys()
	if len(parsed) != len(original) {
		t.Fatalf("parsed key count = %d, want %d", len(parsed), len(original))
	}

	for index := range original {
		if parsed[index].KeyID != original[index].KeyID ||
			parsed[index].Algorithm != original[index].Algorithm ||
			parsed[index].Use != original[index].Use ||
			!reflect.DeepEqual(parsed[index].Key, original[index].Key) {
			t.Fatalf("parsed key %d does not match the original", index)
		}
	}
}

func TestParseRejectsInvalidDocuments(t *testing.T) {
	fixture := asymmetricKeyFixtures(t)[0]

	privateData := marshalSet(t, []Key{{
		Key:       fixture.privateKey,
		KeyID:     "private",
		Algorithm: fixture.method.Alg(),
		Use:       keyUseSignature,
	}})
	symmetricData := marshalSet(t, []Key{{
		Key:       bytes.Repeat([]byte{0x24}, 32),
		KeyID:     "symmetric",
		Algorithm: gojwt.SigningMethodHS256.Alg(),
		Use:       keyUseSignature,
	}})

	tests := []struct {
		name string
		data []byte
		want error
	}{
		{name: "nil", data: nil, want: jwt.ErrInvalidKey},
		{name: "empty", data: []byte{}, want: jwt.ErrInvalidKey},
		{name: "malformed", data: []byte(`{"keys":`), want: jwt.ErrInvalidKey},
		{name: "null", data: []byte(`null`), want: jwt.ErrInvalidKey},
		{name: "empty object", data: []byte(`{}`), want: jwt.ErrInvalidKey},
		{name: "empty keys", data: []byte(`{"keys":[]}`), want: jwt.ErrInvalidKey},
		{name: "keys is not an array", data: []byte(`{"keys":{}}`), want: jwt.ErrInvalidKey},
		{name: "private key", data: privateData, want: jwt.ErrInvalidKey},
		{name: "symmetric key", data: symmetricData, want: jwt.ErrInvalidKey},
	}

	for _, testCase := range tests {
		t.Run(testCase.name, func(t *testing.T) {
			_, err := Parse(testCase.data)
			requireErrorIs(t, err, testCase.want)
		})
	}
}

func TestParseWithLimit(t *testing.T) {
	fixture := asymmetricKeyFixtures(t)[0]
	keys := makeKeys(fixture, 3)
	data := marshalSet(t, keys)

	set, err := ParseWithLimit(data, len(keys))
	requireNoError(t, err)
	if len(set.Keys()) != len(keys) {
		t.Fatalf("parsed key count = %d, want %d", len(set.Keys()), len(keys))
	}

	_, err = ParseWithLimit(data, len(keys)-1)
	requireErrorIs(t, err, jwt.ErrInvalidKey)

	for _, maxKeys := range []int{0, -1} {
		_, err = ParseWithLimit(data, maxKeys)
		requireErrorIs(t, err, jwt.ErrInvalidConfig)
	}
}

func TestParseUsesDefaultMaxKeys(t *testing.T) {
	fixture := asymmetricKeyFixtures(t)[0]
	data := marshalSet(t, makeKeys(fixture, DefaultMaxKeys+1))

	_, err := Parse(data)
	requireErrorIs(t, err, jwt.ErrInvalidKey)
}

func TestResolve(t *testing.T) {
	fixtures := asymmetricKeyFixtures(t)

	keys := make([]Key, 0, len(fixtures))
	for _, fixture := range fixtures {
		keys = append(keys, Key{
			Key:       fixture.publicKey,
			KeyID:     fixture.keyID,
			Algorithm: fixture.method.Alg(),
			Use:       keyUseSignature,
		})
	}

	set, err := New(keys...)
	requireNoError(t, err)

	for _, fixture := range fixtures {
		t.Run(fixture.name, func(t *testing.T) {
			resolved, err := set.Resolve(context.Background(), jwt.Header{
				Algorithm: fixture.method.Alg(),
				KeyID:     fixture.keyID,
			})
			requireNoError(t, err)

			if resolved.ID() != fixture.keyID {
				t.Fatalf("resolved ID = %q, want %q", resolved.ID(), fixture.keyID)
			}
			if resolved.Method().Alg() != fixture.method.Alg() {
				t.Fatalf(
					"resolved algorithm = %q, want %q",
					resolved.Method().Alg(),
					fixture.method.Alg(),
				)
			}
			if !reflect.DeepEqual(resolved.Key(), fixture.publicKey) {
				t.Fatal("Resolve() returned unexpected key material")
			}
		})
	}
}

func TestResolveErrors(t *testing.T) {
	fixture := asymmetricKeyFixtures(t)[0]
	named := Key{
		Key:       fixture.publicKey,
		KeyID:     fixture.keyID,
		Algorithm: fixture.method.Alg(),
		Use:       keyUseSignature,
	}
	set, err := New(named)
	requireNoError(t, err)

	var nilSet *Set
	_, err = nilSet.Resolve(context.Background(), jwt.Header{
		Algorithm: fixture.method.Alg(),
		KeyID:     fixture.keyID,
	})
	requireErrorIs(t, err, jwt.ErrInvalidConfig)

	var zero Set
	_, err = zero.Resolve(context.Background(), jwt.Header{
		Algorithm: fixture.method.Alg(),
		KeyID:     fixture.keyID,
	})
	requireErrorIs(t, err, jwt.ErrInvalidConfig)

	_, err = set.Resolve(context.Background(), jwt.Header{
		Algorithm: fixture.method.Alg(),
	})
	requireErrorIs(t, err, jwt.ErrMissingKeyID)

	_, err = set.Resolve(context.Background(), jwt.Header{
		Algorithm: fixture.method.Alg(),
		KeyID:     "missing",
	})
	requireErrorIs(t, err, jwt.ErrUnknownKey)

	_, err = set.Resolve(context.Background(), jwt.Header{
		Algorithm: gojwt.SigningMethodES256.Alg(),
		KeyID:     fixture.keyID,
	})
	requireErrorIs(t, err, jwt.ErrUnexpectedAlgorithm)
}

func TestResolveValidatesJWKPolicy(t *testing.T) {
	fixture := asymmetricKeyFixtures(t)[0]

	t.Run("empty optional metadata", func(t *testing.T) {
		set, err := New(Key{Key: fixture.publicKey})
		requireNoError(t, err)

		resolved, err := set.Resolve(context.Background(), jwt.Header{
			Algorithm: fixture.method.Alg(),
		})
		requireNoError(t, err)

		if resolved.Method().Alg() != fixture.method.Alg() {
			t.Fatalf(
				"resolved algorithm = %q, want %q",
				resolved.Method().Alg(),
				fixture.method.Alg(),
			)
		}
	})

	t.Run("encryption use", func(t *testing.T) {
		set, err := New(Key{
			Key:       fixture.publicKey,
			Algorithm: fixture.method.Alg(),
			Use:       "enc",
		})
		requireNoError(t, err)

		_, err = set.Resolve(context.Background(), jwt.Header{
			Algorithm: fixture.method.Alg(),
		})
		requireErrorIs(t, err, jwt.ErrInvalidKey)
	})

	t.Run("unknown algorithm", func(t *testing.T) {
		set, err := New(Key{Key: fixture.publicKey})
		requireNoError(t, err)

		_, err = set.Resolve(context.Background(), jwt.Header{
			Algorithm: "unknown",
		})
		requireErrorIs(t, err, jwt.ErrUnexpectedAlgorithm)
	})

	t.Run("algorithm incompatible with key type", func(t *testing.T) {
		set, err := New(Key{
			Key:       fixture.publicKey,
			Algorithm: gojwt.SigningMethodES256.Alg(),
		})
		requireNoError(t, err)

		_, err = set.Resolve(context.Background(), jwt.Header{
			Algorithm: gojwt.SigningMethodES256.Alg(),
		})
		requireErrorIs(t, err, jwt.ErrInvalidKey)
	})
}

func TestKeysReturnsSequenceCopy(t *testing.T) {
	fixtures := asymmetricKeyFixtures(t)
	input := []Key{
		{
			Key:       fixtures[0].publicKey,
			KeyID:     fixtures[0].keyID,
			Algorithm: fixtures[0].method.Alg(),
			Use:       keyUseSignature,
		},
		{
			Key:       fixtures[1].publicKey,
			KeyID:     fixtures[1].keyID,
			Algorithm: fixtures[1].method.Alg(),
			Use:       keyUseSignature,
		},
	}

	set, err := New(input...)
	requireNoError(t, err)

	input[0].KeyID = "changed-input"
	returned := set.Keys()
	returned[0].KeyID = "changed-output"
	returned[1] = Key{}

	again := set.Keys()
	if again[0].KeyID != fixtures[0].keyID {
		t.Fatalf("stored first key ID = %q, want %q", again[0].KeyID, fixtures[0].keyID)
	}
	if again[1].KeyID != fixtures[1].keyID {
		t.Fatalf("stored second key ID = %q, want %q", again[1].KeyID, fixtures[1].keyID)
	}
}

func TestNilSetAccessors(t *testing.T) {
	var set *Set

	if keys := set.Keys(); keys != nil {
		t.Fatalf("Keys() = %#v, want nil", keys)
	}

	data, err := set.MarshalJSON()
	requireNoError(t, err)
	if string(data) != "null" {
		t.Fatalf("MarshalJSON() = %s, want null", data)
	}
}

func TestFromVerificationKeyRejectsUninitializedKey(t *testing.T) {
	_, err := fromVerificationKey(jwt.VerificationKey{})
	requireErrorIs(t, err, jwt.ErrInvalidKey)
}

func TestMarshalJSON(t *testing.T) {
	fixtures := asymmetricKeyFixtures(t)
	keys := []Key{
		{
			Key:       fixtures[0].publicKey,
			KeyID:     fixtures[0].keyID,
			Algorithm: fixtures[0].method.Alg(),
			Use:       keyUseSignature,
		},
		{
			Key:       fixtures[1].publicKey,
			KeyID:     fixtures[1].keyID,
			Algorithm: fixtures[1].method.Alg(),
			Use:       keyUseSignature,
		},
	}

	set, err := New(keys...)
	requireNoError(t, err)

	data, err := json.Marshal(set)
	requireNoError(t, err)

	var document jose.JSONWebKeySet
	requireNoError(t, json.Unmarshal(data, &document))
	if len(document.Keys) != len(keys) {
		t.Fatalf("serialized key count = %d, want %d", len(document.Keys), len(keys))
	}
	for index := range keys {
		if document.Keys[index].KeyID != keys[index].KeyID {
			t.Fatalf(
				"serialized key %d ID = %q, want %q",
				index,
				document.Keys[index].KeyID,
				keys[index].KeyID,
			)
		}
	}

	roundTrip, err := Parse(data)
	requireNoError(t, err)
	if len(roundTrip.Keys()) != len(keys) {
		t.Fatalf("round-trip key count = %d, want %d", len(roundTrip.Keys()), len(keys))
	}

	var nilSet *Set
	nullData, err := json.Marshal(nilSet)
	requireNoError(t, err)
	if string(nullData) != "null" {
		t.Fatalf("json.Marshal(nil set) = %s, want null", nullData)
	}
}

func TestFromStaticKeySet(t *testing.T) {
	fixtures := asymmetricKeyFixtures(t)
	verificationKeys := make([]jwt.VerificationKey, 0, len(fixtures))

	for _, fixture := range fixtures {
		verificationKey, err := jwt.NewVerificationKey(
			fixture.keyID,
			fixture.method,
			fixture.publicKey,
		)
		requireNoError(t, err)
		verificationKeys = append(verificationKeys, verificationKey)
	}

	staticSet, err := jwt.NewStaticKeySet(verificationKeys...)
	requireNoError(t, err)

	set, err := FromStaticKeySet(staticSet)
	requireNoError(t, err)

	keys := set.Keys()
	if len(keys) != len(fixtures) {
		t.Fatalf("exported key count = %d, want %d", len(keys), len(fixtures))
	}

	for _, fixture := range fixtures {
		resolved, err := set.Resolve(context.Background(), jwt.Header{
			Algorithm: fixture.method.Alg(),
			KeyID:     fixture.keyID,
		})
		requireNoError(t, err)

		if !reflect.DeepEqual(resolved.Key(), fixture.publicKey) {
			t.Fatalf("resolved %s key does not match", fixture.name)
		}
	}
}

func TestFromStaticKeySetRejectsInvalidSets(t *testing.T) {
	_, err := FromStaticKeySet(nil)
	requireErrorIs(t, err, jwt.ErrInvalidConfig)

	_, err = FromStaticKeySet(&jwt.StaticKeySet{})
	requireErrorIs(t, err, jwt.ErrInvalidKey)

	hmacKey, err := jwt.NewVerificationKey(
		"hmac",
		gojwt.SigningMethodHS256,
		bytes.Repeat([]byte{0x7a}, 32),
	)
	requireNoError(t, err)
	hmacSet, err := jwt.NewStaticKeySet(hmacKey)
	requireNoError(t, err)

	_, err = FromStaticKeySet(hmacSet)
	requireErrorIs(t, err, jwt.ErrInvalidKey)
}

func TestSetEndToEndVerifier(t *testing.T) {
	oldPrivateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	requireNoError(t, err)
	currentPrivateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	requireNoError(t, err)

	keys := []Key{
		{
			Key:       &oldPrivateKey.PublicKey,
			KeyID:     "rsa-old",
			Algorithm: gojwt.SigningMethodPS256.Alg(),
			Use:       keyUseSignature,
		},
		{
			Key:       &currentPrivateKey.PublicKey,
			KeyID:     "rsa-current",
			Algorithm: gojwt.SigningMethodPS256.Alg(),
			Use:       keyUseSignature,
		},
	}
	set, err := New(keys...)
	requireNoError(t, err)

	signingKey, err := jwt.NewSigningKey(
		"rsa-current",
		gojwt.SigningMethodPS256,
		currentPrivateKey,
	)
	requireNoError(t, err)
	signer, err := jwt.NewSigner(signingKey)
	requireNoError(t, err)

	now := time.Unix(1_800_000_000, 0).UTC()
	raw, err := signer.Sign(context.Background(), &accessClaims{
		UserID: "user-123",
		RegisteredClaims: gojwt.RegisteredClaims{
			Issuer:    "https://issuer.example",
			Subject:   "subject-123",
			Audience:  gojwt.ClaimStrings{"orders-api"},
			ExpiresAt: gojwt.NewNumericDate(now.Add(15 * time.Minute)),
			IssuedAt:  gojwt.NewNumericDate(now),
		},
	})
	requireNoError(t, err)

	verifier, err := jwt.NewVerifier(
		set,
		jwt.WithMethods(gojwt.SigningMethodPS256),
		jwt.WithIssuer("https://issuer.example"),
		jwt.WithAudience("orders-api"),
		jwt.WithClock(func() time.Time { return now }),
	)
	requireNoError(t, err)

	claims := new(accessClaims)
	requireNoError(t, verifier.Verify(context.Background(), raw, claims))

	if claims.UserID != "user-123" {
		t.Fatalf("verified UserID = %q, want user-123", claims.UserID)
	}
	if claims.Subject != "subject-123" {
		t.Fatalf("verified Subject = %q, want subject-123", claims.Subject)
	}
}

func TestSetConcurrentUse(t *testing.T) {
	fixtures := asymmetricKeyFixtures(t)
	keys := make([]Key, 0, len(fixtures))

	for _, fixture := range fixtures {
		keys = append(keys, Key{
			Key:       fixture.publicKey,
			KeyID:     fixture.keyID,
			Algorithm: fixture.method.Alg(),
			Use:       keyUseSignature,
		})
	}

	set, err := New(keys...)
	requireNoError(t, err)

	const goroutines = 32
	const iterations = 100

	var waitGroup sync.WaitGroup
	errorsChannel := make(chan error, goroutines)

	for worker := 0; worker < goroutines; worker++ {
		waitGroup.Add(1)

		go func(worker int) {
			defer waitGroup.Done()

			fixture := fixtures[worker%len(fixtures)]
			for iteration := 0; iteration < iterations; iteration++ {
				resolved, err := set.Resolve(context.Background(), jwt.Header{
					Algorithm: fixture.method.Alg(),
					KeyID:     fixture.keyID,
				})
				if err != nil {
					errorsChannel <- fmt.Errorf("Resolve: %w", err)
					return
				}
				if resolved.ID() != fixture.keyID {
					errorsChannel <- fmt.Errorf(
						"Resolve ID = %q, want %q",
						resolved.ID(),
						fixture.keyID,
					)
					return
				}

				if len(set.Keys()) != len(fixtures) {
					errorsChannel <- errors.New("Keys returned unexpected length")
					return
				}

				if _, err := json.Marshal(set); err != nil {
					errorsChannel <- fmt.Errorf("MarshalJSON: %w", err)
					return
				}
			}
		}(worker)
	}

	waitGroup.Wait()
	close(errorsChannel)

	for err := range errorsChannel {
		t.Error(err)
	}
}

func asymmetricKeyFixtures(t testing.TB) []keyFixture {
	t.Helper()

	rsaPrivateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa.GenerateKey() error = %v", err)
	}

	ecdsaPrivateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("ecdsa.GenerateKey() error = %v", err)
	}

	ed25519PublicKey, ed25519PrivateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ed25519.GenerateKey() error = %v", err)
	}

	return []keyFixture{
		{
			name:       "RSA",
			keyID:      "rsa-2026-07",
			method:     gojwt.SigningMethodPS256,
			privateKey: rsaPrivateKey,
			publicKey:  &rsaPrivateKey.PublicKey,
		},
		{
			name:       "ECDSA",
			keyID:      "ecdsa-2026-07",
			method:     gojwt.SigningMethodES256,
			privateKey: ecdsaPrivateKey,
			publicKey:  &ecdsaPrivateKey.PublicKey,
		},
		{
			name:       "Ed25519",
			keyID:      "ed25519-2026-07",
			method:     gojwt.SigningMethodEdDSA,
			privateKey: ed25519PrivateKey,
			publicKey:  ed25519PublicKey,
		},
	}
}

func makeKeys(fixture keyFixture, count int) []Key {
	keys := make([]Key, count)
	for index := range keys {
		keys[index] = Key{
			Key:       fixture.publicKey,
			KeyID:     fmt.Sprintf("key-%03d", index),
			Algorithm: fixture.method.Alg(),
			Use:       keyUseSignature,
		}
	}
	return keys
}

func marshalSet(t testing.TB, keys []Key) []byte {
	t.Helper()

	data, err := json.Marshal(jose.JSONWebKeySet{Keys: keys})
	if err != nil {
		t.Fatalf("json.Marshal() error = %v", err)
	}

	return data
}

func requireNoError(t testing.TB, err error) {
	t.Helper()

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func requireErrorIs(t testing.TB, err, target error) {
	t.Helper()

	if !errors.Is(err, target) {
		t.Fatalf("error = %v, want errors.Is(_, %v)", err, target)
	}
}
