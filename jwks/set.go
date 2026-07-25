package jwks

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/go-jose/go-jose/v4"
	gojwt "github.com/golang-jwt/jwt/v5"
	"github.com/mkbeh/xjose/jwt"
)

const (
	// DefaultMaxKeys is the default maximum number of keys parsed from a JWKS document.
	DefaultMaxKeys = 100

	keyUseSignature = "sig"
)

// Key represents a JSON Web Key.
type Key = jose.JSONWebKey

// Set is a public JWK Set that implements xjwt.KeyResolver.
//
// Set copies the JWK sequence. The key objects stored in individual entries
// must be treated as immutable.
//
// A set containing multiple keys requires every key to have a unique kid.
type Set struct {
	keys    []Key
	keyByID map[string]int
}

var _ jwt.KeyResolver = (*Set)(nil)

// New creates a JWK Set from trusted in-memory public keys.
func New(keys ...Key) (*Set, error) {
	return newSet(keys)
}

// Parse parses a JWK Set using DefaultMaxKeys.
func Parse(data []byte) (*Set, error) {
	return ParseWithLimit(data, DefaultMaxKeys)
}

// ParseWithLimit parses a JWK Set and limits the number of accepted keys.
func ParseWithLimit(data []byte, maxKeys int) (*Set, error) {
	if maxKeys <= 0 {
		return nil, fmt.Errorf(
			"%w: maximum key count must be positive",
			jwt.ErrInvalidConfig,
		)
	}

	var document jose.JSONWebKeySet

	if err := json.Unmarshal(data, &document); err != nil {
		return nil, fmt.Errorf(
			"%w: parse JWKS: %w",
			jwt.ErrInvalidKey,
			err,
		)
	}

	if len(document.Keys) > maxKeys {
		return nil, fmt.Errorf(
			"%w: JWKS contains %d keys, limit is %d",
			jwt.ErrInvalidKey,
			len(document.Keys),
			maxKeys,
		)
	}

	return newSet(document.Keys)
}

// FromStaticKeySet exports an xjwt verification-key set as a public JWK Set.
//
// Symmetric verification keys cannot be exported as public JWKs.
func FromStaticKeySet(keySet *jwt.StaticKeySet) (*Set, error) {
	if keySet == nil {
		return nil, fmt.Errorf(
			"%w: key set is nil",
			jwt.ErrInvalidConfig,
		)
	}

	verificationKeys := keySet.Keys()
	keys := make([]Key, 0, len(verificationKeys))

	for index, verificationKey := range verificationKeys {
		key, err := fromVerificationKey(verificationKey)
		if err != nil {
			return nil, fmt.Errorf(
				"verification key %d: %w",
				index,
				err,
			)
		}

		keys = append(keys, key)
	}

	return New(keys...)
}

func newSet(keys []Key) (*Set, error) {
	if len(keys) == 0 {
		return nil, fmt.Errorf(
			"%w: JWKS contains no keys",
			jwt.ErrInvalidKey,
		)
	}

	ownedKeys := append([]Key(nil), keys...)
	keyByID := make(map[string]int, len(ownedKeys))

	for index, key := range ownedKeys {
		if err := validatePublicKey(key); err != nil {
			return nil, fmt.Errorf(
				"JWK %d: %w",
				index,
				err,
			)
		}

		if len(ownedKeys) > 1 && key.KeyID == "" {
			return nil, fmt.Errorf(
				"%w: JWK %d has no key ID",
				jwt.ErrInvalidKey,
				index,
			)
		}

		if key.KeyID == "" {
			continue
		}

		if _, exists := keyByID[key.KeyID]; exists {
			return nil, fmt.Errorf(
				"%w: %q",
				jwt.ErrDuplicateKeyID,
				key.KeyID,
			)
		}

		keyByID[key.KeyID] = index
	}

	return &Set{
		keys:    ownedKeys,
		keyByID: keyByID,
	}, nil
}

// Resolve selects a public verification key using the protected alg and kid
// header parameters.
func (s *Set) Resolve(_ context.Context, header jwt.Header) (jwt.VerificationKey, error) {
	if s == nil || len(s.keys) == 0 {
		return jwt.VerificationKey{}, fmt.Errorf(
			"%w: JWKS is uninitialized",
			jwt.ErrInvalidConfig,
		)
	}

	key, err := s.resolveKey(header.KeyID)
	if err != nil {
		return jwt.VerificationKey{}, err
	}

	return toVerificationKey(key, header.Algorithm)
}

func (s *Set) resolveKey(keyID string) (Key, error) {
	if keyID == "" {
		if len(s.keys) != 1 || s.keys[0].KeyID != "" {
			return Key{}, jwt.ErrMissingKeyID
		}

		return s.keys[0], nil
	}

	index, exists := s.keyByID[keyID]
	if !exists {
		return Key{}, fmt.Errorf(
			"%w: key ID %q",
			jwt.ErrUnknownKey,
			keyID,
		)
	}

	return s.keys[index], nil
}

func toVerificationKey(key Key, algorithm string) (jwt.VerificationKey, error) {
	if key.Use != "" && key.Use != keyUseSignature {
		return jwt.VerificationKey{}, fmt.Errorf(
			"%w: JWK use %q does not permit signature verification",
			jwt.ErrInvalidKey,
			key.Use,
		)
	}

	if key.Algorithm != "" && key.Algorithm != algorithm {
		return jwt.VerificationKey{}, jwt.ErrUnexpectedAlgorithm
	}

	method := gojwt.GetSigningMethod(algorithm)
	if method == nil {
		return jwt.VerificationKey{}, jwt.ErrUnexpectedAlgorithm
	}

	return jwt.NewVerificationKey(key.KeyID, method, key.Key)
}

func fromVerificationKey(key jwt.VerificationKey) (Key, error) {
	method := key.Method()
	if method == nil {
		return Key{}, fmt.Errorf(
			"%w: verification key is uninitialized",
			jwt.ErrInvalidKey,
		)
	}

	raw := key.Key()
	if raw == nil {
		return Key{}, fmt.Errorf(
			"%w: verification key is uninitialized",
			jwt.ErrInvalidKey,
		)
	}

	if _, symmetric := raw.([]byte); symmetric {
		return Key{}, fmt.Errorf(
			"%w: symmetric keys cannot be exported as public JWKs",
			jwt.ErrInvalidKey,
		)
	}

	result := Key{
		Key:       raw,
		KeyID:     key.ID(),
		Algorithm: method.Alg(),
		Use:       keyUseSignature,
	}

	if err := validatePublicKey(result); err != nil {
		return Key{}, err
	}

	return result, nil
}

func validatePublicKey(key Key) error {
	if !key.Valid() || !key.IsPublic() {
		return fmt.Errorf(
			"%w: JWK must contain a valid public key",
			jwt.ErrInvalidKey,
		)
	}

	return nil
}

// Keys returns a shallow copy of the JWK sequence.
func (s *Set) Keys() []Key {
	if s == nil {
		return nil
	}

	return append([]Key(nil), s.keys...)
}

// MarshalJSON serializes the JWK Set document.
func (s *Set) MarshalJSON() ([]byte, error) {
	if s == nil {
		return []byte("null"), nil
	}

	return json.Marshal(
		jose.JSONWebKeySet{
			Keys: s.keys,
		},
	)
}
