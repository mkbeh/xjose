package jwk

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/go-jose/go-jose/v4"
	gojwt "github.com/golang-jwt/jwt/v5"
	"github.com/mkbeh/xjose/jwt"
)

const (
	// DefaultMaxSetKeys is the default maximum number of keys parsed from a JWK Set document.
	DefaultMaxSetKeys = 100
)

// Set is a public JWK Set that implements jwt.KeyResolver.
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

// NewSet creates a JWK Set from trusted in-memory public keys.
func NewSet(keys ...Key) (*Set, error) {
	return newSet(keys)
}

// ParseSet parses a JWK Set using DefaultMaxSetKeys.
func ParseSet(data []byte) (*Set, error) {
	return ParseSetWithLimit(data, DefaultMaxSetKeys)
}

// ParseSetWithLimit parses a JWK Set and limits the number of accepted keys.
func ParseSetWithLimit(data []byte, maxKeys int) (*Set, error) {
	if maxKeys <= 0 {
		return nil, fmt.Errorf(
			"%w: maximum key count must be positive",
			jwt.ErrInvalidConfig,
		)
	}

	var document jose.JSONWebKeySet

	if err := json.Unmarshal(data, &document); err != nil {
		return nil, fmt.Errorf(
			"%w: parse JWK Set: %w",
			jwt.ErrInvalidKey,
			err,
		)
	}

	if len(document.Keys) > maxKeys {
		return nil, fmt.Errorf(
			"%w: JWK Set contains %d keys, limit is %d",
			jwt.ErrInvalidKey,
			len(document.Keys),
			maxKeys,
		)
	}

	return newSet(document.Keys)
}

// FromStaticKeySet exports a JWT verification-key set as a public JWK Set.
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
		key, err := FromVerificationKey(verificationKey)
		if err != nil {
			return nil, fmt.Errorf(
				"verification key %d: %w",
				index,
				err,
			)
		}

		keys = append(keys, key)
	}

	return NewSet(keys...)
}

func newSet(keys []Key) (*Set, error) {
	if len(keys) == 0 {
		return nil, fmt.Errorf(
			"%w: JWK Set contains no keys",
			jwt.ErrInvalidKey,
		)
	}

	// Copy the key sequence so later slice mutations by the caller
	// cannot change the set.
	ownedKeys := make([]Key, len(keys))
	copy(ownedKeys, keys)

	keyByID := make(map[string]int, len(ownedKeys))

	for index, key := range ownedKeys {
		if err := Validate(key); err != nil {
			return nil, fmt.Errorf(
				"JWK %d: %w",
				index,
				err,
			)
		}

		// A single anonymous key is allowed. Multiple keys require
		// non-empty IDs for deterministic resolution.
		if key.KeyID == "" {
			if len(ownedKeys) > 1 {
				return nil, fmt.Errorf(
					"%w: JWK %d has no key ID",
					jwt.ErrInvalidKey,
					index,
				)
			}

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
			"%w: JWK Set is uninitialized",
			jwt.ErrInvalidConfig,
		)
	}

	key, err := s.resolveKey(header.KeyID)
	if err != nil {
		return jwt.VerificationKey{}, err
	}

	method := gojwt.GetSigningMethod(header.Algorithm)
	if method == nil {
		return jwt.VerificationKey{}, jwt.ErrUnexpectedAlgorithm
	}

	return ToVerificationKey(key, method)
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
