package jwks

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/go-jose/go-jose/v4"
	"github.com/golang-jwt/jwt/v5"
	"github.com/mkbeh/xjwt"
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

var _ xjwt.KeyResolver = (*Set)(nil)

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
			xjwt.ErrInvalidConfig,
		)
	}

	var document jose.JSONWebKeySet

	if err := json.Unmarshal(data, &document); err != nil {
		return nil, fmt.Errorf(
			"%w: parse JWKS: %w",
			xjwt.ErrInvalidKey,
			err,
		)
	}

	if len(document.Keys) > maxKeys {
		return nil, fmt.Errorf(
			"%w: JWKS contains %d keys, limit is %d",
			xjwt.ErrInvalidKey,
			len(document.Keys),
			maxKeys,
		)
	}

	return newSet(document.Keys)
}

// FromStaticKeySet exports an xjwt verification-key set as a public JWK Set.
//
// Symmetric verification keys cannot be exported as public JWKs.
func FromStaticKeySet(keySet *xjwt.StaticKeySet) (*Set, error) {
	if keySet == nil {
		return nil, fmt.Errorf(
			"%w: key set is nil",
			xjwt.ErrInvalidConfig,
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
			xjwt.ErrInvalidKey,
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
				xjwt.ErrInvalidKey,
				index,
			)
		}

		if key.KeyID == "" {
			continue
		}

		if _, exists := keyByID[key.KeyID]; exists {
			return nil, fmt.Errorf(
				"%w: %q",
				xjwt.ErrDuplicateKeyID,
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
func (s *Set) Resolve(_ context.Context, header xjwt.Header) (xjwt.VerificationKey, error) {
	if s == nil || len(s.keys) == 0 {
		return xjwt.VerificationKey{}, fmt.Errorf(
			"%w: JWKS is uninitialized",
			xjwt.ErrInvalidConfig,
		)
	}

	key, err := s.resolveKey(header.KeyID)
	if err != nil {
		return xjwt.VerificationKey{}, err
	}

	return toVerificationKey(key, header.Algorithm)
}

func (s *Set) resolveKey(keyID string) (Key, error) {
	if keyID == "" {
		if len(s.keys) != 1 || s.keys[0].KeyID != "" {
			return Key{}, xjwt.ErrMissingKeyID
		}

		return s.keys[0], nil
	}

	index, exists := s.keyByID[keyID]
	if !exists {
		return Key{}, fmt.Errorf(
			"%w: key ID %q",
			xjwt.ErrUnknownKey,
			keyID,
		)
	}

	return s.keys[index], nil
}

func toVerificationKey(key Key, algorithm string) (xjwt.VerificationKey, error) {
	if key.Use != "" && key.Use != keyUseSignature {
		return xjwt.VerificationKey{}, fmt.Errorf(
			"%w: JWK use %q does not permit signature verification",
			xjwt.ErrInvalidKey,
			key.Use,
		)
	}

	if key.Algorithm != "" && key.Algorithm != algorithm {
		return xjwt.VerificationKey{}, xjwt.ErrUnexpectedAlgorithm
	}

	method := jwt.GetSigningMethod(algorithm)
	if method == nil {
		return xjwt.VerificationKey{}, xjwt.ErrUnexpectedAlgorithm
	}

	return xjwt.NewVerificationKey(key.KeyID, method, key.Key)
}

func fromVerificationKey(key xjwt.VerificationKey) (Key, error) {
	method := key.Method()
	if method == nil {
		return Key{}, fmt.Errorf(
			"%w: verification key is uninitialized",
			xjwt.ErrInvalidKey,
		)
	}

	raw := key.Key()
	if raw == nil {
		return Key{}, fmt.Errorf(
			"%w: verification key is uninitialized",
			xjwt.ErrInvalidKey,
		)
	}

	if _, symmetric := raw.([]byte); symmetric {
		return Key{}, fmt.Errorf(
			"%w: symmetric keys cannot be exported as public JWKs",
			xjwt.ErrInvalidKey,
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
			xjwt.ErrInvalidKey,
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
