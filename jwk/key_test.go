package jwk

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
	"strings"
	"sync"
	"testing"
	"time"

	gojwt "github.com/golang-jwt/jwt/v5"
	"github.com/mkbeh/xjose/jwt"
)

func TestValidate(t *testing.T) {
	fixtures := asymmetricKeyFixtures(t)

	for _, testCase := range fixtures {
		t.Run(testCase.name, func(t *testing.T) {
			err := Validate(Key{Key: testCase.publicKey})
			requireNoError(t, err)
		})
	}
}

func TestValidateRejectsInvalidKeys(t *testing.T) {
	fixtures := asymmetricKeyFixtures(t)

	tests := []struct {
		name string
		key  Key
	}{
		{name: "empty", key: Key{}},
		{name: "private", key: Key{Key: fixtures[0].privateKey}},
		{name: "symmetric", key: Key{Key: bytes.Repeat([]byte{0x42}, 32)}},
		{name: "typed nil RSA public", key: Key{Key: (*rsa.PublicKey)(nil)}},
		{name: "typed nil RSA private", key: Key{Key: (*rsa.PrivateKey)(nil)}},
		{name: "typed nil ECDSA public", key: Key{Key: (*ecdsa.PublicKey)(nil)}},
		{name: "typed nil ECDSA private", key: Key{Key: (*ecdsa.PrivateKey)(nil)}},
	}

	for _, testCase := range tests {
		t.Run(testCase.name, func(t *testing.T) {
			err := Validate(testCase.key)
			requireErrorIs(t, err, jwt.ErrInvalidKey)
		})
	}
}

func TestFromVerificationKey(t *testing.T) {
	for _, testCase := range asymmetricKeyFixtures(t) {
		t.Run(testCase.name, func(t *testing.T) {
			verificationKey, err := jwt.NewVerificationKey(
				testCase.keyID,
				testCase.method,
				testCase.publicKey,
			)
			requireNoError(t, err)

			key, err := FromVerificationKey(verificationKey)
			requireNoError(t, err)

			if !key.Valid() {
				t.Fatal("FromVerificationKey() returned an invalid JWK")
			}
			if !key.IsPublic() {
				t.Fatal("FromVerificationKey() returned a non-public JWK")
			}
			if key.KeyID != testCase.keyID {
				t.Fatalf(
					"FromVerificationKey() kid = %q, want %q",
					key.KeyID,
					testCase.keyID,
				)
			}
			if key.Algorithm != testCase.method.Alg() {
				t.Fatalf(
					"FromVerificationKey() alg = %q, want %q",
					key.Algorithm,
					testCase.method.Alg(),
				)
			}
			if key.Use != keyUseSignature {
				t.Fatalf(
					"FromVerificationKey() use = %q, want %q",
					key.Use,
					keyUseSignature,
				)
			}
			if !publicKeysEqual(key.Key, testCase.publicKey) {
				t.Fatal("FromVerificationKey() returned unexpected key material")
			}
		})
	}
}

func TestFromVerificationKeyRejectsInvalidKeys(t *testing.T) {
	t.Run("uninitialized", func(t *testing.T) {
		_, err := FromVerificationKey(jwt.VerificationKey{})
		requireErrorIs(t, err, jwt.ErrInvalidKey)
	})

	t.Run("symmetric", func(t *testing.T) {
		verificationKey, err := jwt.NewVerificationKey(
			"hmac-2026-07",
			gojwt.SigningMethodHS256,
			bytes.Repeat([]byte{0x42}, 32),
		)
		requireNoError(t, err)

		_, err = FromVerificationKey(verificationKey)
		requireErrorIs(t, err, jwt.ErrInvalidKey)
	})
}

func TestParse(t *testing.T) {
	for _, testCase := range asymmetricKeyFixtures(t) {
		t.Run(testCase.name, func(t *testing.T) {
			original := Key{
				Key:       testCase.publicKey,
				KeyID:     testCase.keyID,
				Algorithm: testCase.method.Alg(),
				Use:       keyUseSignature,
			}

			data, err := json.Marshal(original)
			requireNoError(t, err)

			parsed, err := Parse(data)
			requireNoError(t, err)

			if !parsed.Valid() || !parsed.IsPublic() {
				t.Fatal("Parse() returned an invalid or non-public JWK")
			}
			if parsed.KeyID != original.KeyID {
				t.Fatalf("Parse() kid = %q, want %q", parsed.KeyID, original.KeyID)
			}
			if parsed.Algorithm != original.Algorithm {
				t.Fatalf(
					"Parse() alg = %q, want %q",
					parsed.Algorithm,
					original.Algorithm,
				)
			}
			if parsed.Use != original.Use {
				t.Fatalf("Parse() use = %q, want %q", parsed.Use, original.Use)
			}
			if !publicKeysEqual(parsed.Key, original.Key) {
				t.Fatal("Parse() returned unexpected key material")
			}
		})
	}
}

func TestParseRejectsInvalidKeys(t *testing.T) {
	fixtures := asymmetricKeyFixtures(t)

	privateData, err := json.Marshal(Key{
		Key:       fixtures[0].privateKey,
		KeyID:     "private-rsa",
		Algorithm: fixtures[0].method.Alg(),
		Use:       keyUseSignature,
	})
	requireNoError(t, err)

	symmetricData, err := json.Marshal(Key{
		Key:       bytes.Repeat([]byte{0x33}, 32),
		KeyID:     "symmetric",
		Algorithm: gojwt.SigningMethodHS256.Alg(),
		Use:       keyUseSignature,
	})
	requireNoError(t, err)

	tests := []struct {
		name string
		data []byte
	}{
		{name: "nil", data: nil},
		{name: "empty", data: []byte{}},
		{name: "malformed json", data: []byte(`{"kty":`)},
		{name: "null", data: []byte(`null`)},
		{name: "empty object", data: []byte(`{}`)},
		{name: "unknown key type", data: []byte(`{"kty":"unknown"}`)},
		{name: "invalid rsa encoding", data: []byte(`{"kty":"RSA","n":"***","e":"AQAB"}`)},
		{name: "private", data: privateData},
		{name: "symmetric", data: symmetricData},
	}

	for _, testCase := range tests {
		t.Run(testCase.name, func(t *testing.T) {
			_, err := Parse(testCase.data)
			requireErrorIs(t, err, jwt.ErrInvalidKey)
		})
	}
}

func TestToVerificationKey(t *testing.T) {
	for _, testCase := range asymmetricKeyFixtures(t) {
		t.Run(testCase.name, func(t *testing.T) {
			key := Key{
				Key:       testCase.publicKey,
				KeyID:     testCase.keyID,
				Algorithm: testCase.method.Alg(),
				Use:       keyUseSignature,
			}

			verificationKey, err := ToVerificationKey(key, testCase.method)
			requireNoError(t, err)

			if verificationKey.ID() != testCase.keyID {
				t.Fatalf(
					"ToVerificationKey() id = %q, want %q",
					verificationKey.ID(),
					testCase.keyID,
				)
			}
			if verificationKey.Method() != testCase.method {
				t.Fatalf(
					"ToVerificationKey() method = %v, want %v",
					verificationKey.Method(),
					testCase.method,
				)
			}
			if !publicKeysEqual(verificationKey.Key(), testCase.publicKey) {
				t.Fatal("ToVerificationKey() returned unexpected key material")
			}
		})
	}
}

func TestToVerificationKeyAllowsEmptyOptionalMetadata(t *testing.T) {
	fixture := asymmetricKeyFixtures(t)[0]

	verificationKey, err := ToVerificationKey(
		Key{Key: fixture.publicKey},
		fixture.method,
	)
	requireNoError(t, err)

	if verificationKey.ID() != "" {
		t.Fatalf("ToVerificationKey() id = %q, want empty", verificationKey.ID())
	}
	if verificationKey.Method() != fixture.method {
		t.Fatalf(
			"ToVerificationKey() method = %v, want %v",
			verificationKey.Method(),
			fixture.method,
		)
	}
}

func TestToVerificationKeyRejectsInvalidConfiguration(t *testing.T) {
	fixture := asymmetricKeyFixtures(t)[0]
	validKey := Key{
		Key:       fixture.publicKey,
		KeyID:     fixture.keyID,
		Algorithm: fixture.method.Alg(),
		Use:       keyUseSignature,
	}

	t.Run("nil method", func(t *testing.T) {
		_, err := ToVerificationKey(validKey, nil)
		requireErrorIs(t, err, jwt.ErrInvalidConfig)
	})

	t.Run("invalid key", func(t *testing.T) {
		_, err := ToVerificationKey(Key{}, fixture.method)
		requireErrorIs(t, err, jwt.ErrInvalidKey)
	})

	t.Run("private key", func(t *testing.T) {
		_, err := ToVerificationKey(
			Key{Key: fixture.privateKey},
			fixture.method,
		)
		requireErrorIs(t, err, jwt.ErrInvalidKey)
	})

	t.Run("encryption use", func(t *testing.T) {
		key := validKey
		key.Use = "enc"

		_, err := ToVerificationKey(key, fixture.method)
		requireErrorIs(t, err, jwt.ErrInvalidKey)
	})

	t.Run("unexpected algorithm", func(t *testing.T) {
		key := validKey
		key.Algorithm = gojwt.SigningMethodRS256.Alg()

		_, err := ToVerificationKey(key, fixture.method)
		requireErrorIs(t, err, jwt.ErrUnexpectedAlgorithm)
	})
}

func TestThumbprintID(t *testing.T) {
	fixtures := asymmetricKeyFixtures(t)

	for _, testCase := range fixtures {
		t.Run(testCase.name, func(t *testing.T) {
			key := Key{
				Key:       testCase.publicKey,
				KeyID:     testCase.keyID,
				Algorithm: testCase.method.Alg(),
				Use:       keyUseSignature,
			}

			first, err := ThumbprintID(key)
			requireNoError(t, err)
			second, err := ThumbprintID(key)
			requireNoError(t, err)

			if first != second {
				t.Fatalf("ThumbprintID() is not stable: %q != %q", first, second)
			}
			if strings.Contains(first, "=") {
				t.Fatalf("ThumbprintID() = %q, want unpadded base64url", first)
			}

			decoded, err := base64.RawURLEncoding.DecodeString(first)
			requireNoError(t, err)
			if len(decoded) != 32 {
				t.Fatalf("decoded thumbprint length = %d, want 32", len(decoded))
			}

			metadataChanged := key
			metadataChanged.KeyID = "different-kid"
			metadataChanged.Algorithm = "different-alg"
			metadataChanged.Use = "enc"

			metadataThumbprint, err := ThumbprintID(metadataChanged)
			requireNoError(t, err)
			if metadataThumbprint != first {
				t.Fatalf(
					"metadata changed thumbprint: got %q, want %q",
					metadataThumbprint,
					first,
				)
			}
		})
	}

	first, err := ThumbprintID(Key{Key: fixtures[0].publicKey})
	requireNoError(t, err)
	second, err := ThumbprintID(Key{Key: fixtures[1].publicKey})
	requireNoError(t, err)
	if first == second {
		t.Fatalf("different keys produced the same thumbprint %q", first)
	}
}

func TestThumbprintIDRejectsInvalidKeys(t *testing.T) {
	fixture := asymmetricKeyFixtures(t)[0]

	tests := []struct {
		name string
		key  Key
	}{
		{name: "empty", key: Key{}},
		{name: "private", key: Key{Key: fixture.privateKey}},
		{name: "symmetric", key: Key{Key: bytes.Repeat([]byte{0x77}, 32)}},
	}

	for _, testCase := range tests {
		t.Run(testCase.name, func(t *testing.T) {
			_, err := ThumbprintID(testCase.key)
			requireErrorIs(t, err, jwt.ErrInvalidKey)
		})
	}
}

func TestJWTVerificationRoundTrip(t *testing.T) {
	for _, testCase := range asymmetricKeyFixtures(t) {
		t.Run(testCase.name, func(t *testing.T) {
			signingKey, err := jwt.NewSigningKey(
				testCase.keyID,
				testCase.method,
				testCase.privateKey,
			)
			requireNoError(t, err)

			key, err := FromVerificationKey(signingKey.VerificationKey())
			requireNoError(t, err)

			encoded, err := json.Marshal(key)
			requireNoError(t, err)

			parsed, err := Parse(encoded)
			requireNoError(t, err)

			verificationKey, err := ToVerificationKey(parsed, testCase.method)
			requireNoError(t, err)

			signer, err := jwt.NewSigner(signingKey)
			requireNoError(t, err)

			issuedAt := time.Now().UTC().Truncate(time.Second)
			token, err := signer.Sign(
				context.Background(),
				gojwt.RegisteredClaims{
					Subject:   "user-123",
					IssuedAt:  gojwt.NewNumericDate(issuedAt),
					ExpiresAt: gojwt.NewNumericDate(issuedAt.Add(time.Hour)),
				},
			)
			requireNoError(t, err)

			verifier, err := jwt.NewVerifier(
				verificationKey,
				jwt.WithMethods(testCase.method),
			)
			requireNoError(t, err)

			var claims gojwt.RegisteredClaims
			err = verifier.Verify(context.Background(), token, &claims)
			requireNoError(t, err)

			if claims.Subject != "user-123" {
				t.Fatalf("verified subject = %q, want %q", claims.Subject, "user-123")
			}
		})
	}
}

type asymmetricKeyFixture struct {
	name       string
	keyID      string
	method     gojwt.SigningMethod
	privateKey any
	publicKey  any
}

var (
	asymmetricFixturesOnce sync.Once
	asymmetricFixtures     []asymmetricKeyFixture
	asymmetricFixturesErr  error
)

func asymmetricKeyFixtures(t testing.TB) []asymmetricKeyFixture {
	t.Helper()

	asymmetricFixturesOnce.Do(func() {
		rsaPrivateKey, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			asymmetricFixturesErr = err
			return
		}

		ecdsaPrivateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			asymmetricFixturesErr = err
			return
		}

		ed25519PublicKey, ed25519PrivateKey, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			asymmetricFixturesErr = err
			return
		}

		asymmetricFixtures = []asymmetricKeyFixture{
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
	})

	if asymmetricFixturesErr != nil {
		t.Fatalf("generate asymmetric test keys: %v", asymmetricFixturesErr)
	}

	return asymmetricFixtures
}

func publicKeysEqual(first, second any) bool {
	switch first := first.(type) {
	case *rsa.PublicKey:
		second, ok := second.(*rsa.PublicKey)
		return ok &&
			first != nil &&
			second != nil &&
			first.E == second.E &&
			first.N.Cmp(second.N) == 0

	case *ecdsa.PublicKey:
		second, ok := second.(*ecdsa.PublicKey)
		return ok &&
			first != nil &&
			second != nil &&
			first.Equal(second)

	case ed25519.PublicKey:
		second, ok := second.(ed25519.PublicKey)
		return ok && bytes.Equal(first, second)

	default:
		return false
	}
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
