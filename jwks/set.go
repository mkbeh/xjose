package jwks

import (
	"context"
	"encoding/json"
	"fmt"

	xjwt "github.com/mkbeh/xjwt"
	"github.com/mkbeh/xjwt/internal/josejson"
	"github.com/mkbeh/xjwt/jwk"
)

// DefaultMaxKeys is the default maximum number of JWK values accepted from a
// serialized JWK Set.
const DefaultMaxKeys = 100

// Set is an immutable collection of public signature-verification JWKs. It
// implements xjwt.KeyResolver.
type Set struct {
	keys []jwk.Key
	byID map[string]int
}

var _ xjwt.KeyResolver = (*Set)(nil)

// New creates an immutable JWK Set. A single key may omit kid; every key in a
// multi-key set must have a unique non-empty kid.
func New(keys ...jwk.Key) (*Set, error) {
	if len(keys) == 0 {
		return nil, fmt.Errorf("%w: %w", ErrInvalidSet, ErrNoUsableKeys)
	}

	set := &Set{
		keys: make([]jwk.Key, len(keys)),
		byID: make(map[string]int, len(keys)),
	}
	copy(set.keys, keys)

	for index, key := range set.keys {
		if err := key.Validate(); err != nil {
			return nil, fmt.Errorf("%w: key %d: %w", ErrInvalidSet, index, err)
		}

		id := key.ID()
		if len(set.keys) > 1 && id == "" {
			return nil, fmt.Errorf(
				"%w: key %d has no kid in a multi-key set",
				ErrInvalidSet,
				index,
			)
		}
		if _, duplicate := set.byID[id]; duplicate {
			return nil, fmt.Errorf(
				"%w: %w: %q",
				ErrInvalidSet,
				xjwt.ErrDuplicateKeyID,
				id,
			)
		}

		set.byID[id] = index
	}

	return set, nil
}

// Parse parses a JWK Set using DefaultMaxKeys. Unsupported or non-signature
// keys are ignored, as permitted for mixed-use JWK Sets.
func Parse(data []byte) (*Set, error) {
	return ParseWithLimit(data, DefaultMaxKeys)
}

// ParseWithLimit parses a JWK Set and rejects documents containing more than
// maxKeys array entries. Unsupported or non-signature keys are ignored;
// malformed supported signature keys fail the complete document.
func ParseWithLimit(data []byte, maxKeys int) (*Set, error) {
	if maxKeys <= 0 {
		return nil, fmt.Errorf("%w: maximum key count must be positive", ErrInvalidSet)
	}

	members, err := josejson.DecodeObject(data)
	if err != nil {
		return nil, fmt.Errorf("%w: decode object: %w", ErrInvalidSet, err)
	}

	rawKeys, exists := members["keys"]
	if !exists {
		return nil, fmt.Errorf("%w: missing keys member", ErrInvalidSet)
	}

	var encodedKeys []json.RawMessage
	if err := json.Unmarshal(rawKeys, &encodedKeys); err != nil {
		return nil, fmt.Errorf("%w: keys must be an array: %w", ErrInvalidSet, err)
	}
	if len(encodedKeys) > maxKeys {
		return nil, fmt.Errorf(
			"%w: %w: got %d, limit is %d",
			ErrInvalidSet,
			ErrTooManyKeys,
			len(encodedKeys),
			maxKeys,
		)
	}

	keys := make([]jwk.Key, 0, len(encodedKeys))
	for index, encoded := range encodedKeys {
		key, err := jwk.Parse(encoded)
		if err != nil {
			if jwk.IsIgnorable(err) {
				continue
			}

			return nil, fmt.Errorf("%w: key %d: %w", ErrInvalidSet, index, err)
		}

		keys = append(keys, key)
	}

	if len(keys) == 0 {
		return nil, fmt.Errorf("%w: %w", ErrInvalidSet, ErrNoUsableKeys)
	}

	return New(keys...)
}

// Len returns the number of usable keys in the set.
func (s *Set) Len() int {
	if s == nil {
		return 0
	}

	return len(s.keys)
}

// Keys returns a copy of the immutable JWK values in declaration order.
func (s *Set) Keys() []jwk.Key {
	if s == nil {
		return nil
	}

	result := make([]jwk.Key, len(s.keys))
	copy(result, s.keys)

	return result
}

// Resolve selects a key by exact kid and binds it to the token algorithm.
func (s *Set) Resolve(
	ctx context.Context,
	header xjwt.Header,
) (xjwt.VerificationKey, error) {
	if s == nil || len(s.keys) == 0 || len(s.byID) == 0 {
		return xjwt.VerificationKey{}, xjwt.ErrInvalidConfig
	}
	if err := ctx.Err(); err != nil {
		return xjwt.VerificationKey{}, err
	}

	if header.KeyID == "" {
		index, exists := s.byID[""]
		if !exists {
			return xjwt.VerificationKey{}, xjwt.ErrMissingKeyID
		}

		return s.keys[index].VerificationKey(header.Algorithm)
	}

	index, exists := s.byID[header.KeyID]
	if !exists {
		return xjwt.VerificationKey{}, xjwt.ErrUnknownKey
	}

	return s.keys[index].VerificationKey(header.Algorithm)
}

// MarshalJSON serializes the set as {"keys":[...]}.
func (s *Set) MarshalJSON() ([]byte, error) {
	if s == nil || len(s.keys) == 0 {
		return nil, fmt.Errorf("%w: %w", ErrInvalidSet, ErrNoUsableKeys)
	}

	return json.Marshal(struct {
		Keys []jwk.Key `json:"keys"`
	}{
		Keys: s.Keys(),
	})
}

// FromStaticKeySet creates a public JWK Set from an xjwt static verification
// key set. Symmetric HMAC keys cannot be exported as public JWKs.
func FromStaticKeySet(keySet *xjwt.StaticKeySet) (*Set, error) {
	if keySet == nil || keySet.Len() == 0 {
		return nil, fmt.Errorf("%w: %w", ErrInvalidSet, ErrNoUsableKeys)
	}

	verificationKeys := keySet.Keys()
	keys := make([]jwk.Key, 0, len(verificationKeys))
	for index, verificationKey := range verificationKeys {
		key, err := jwk.FromVerificationKey(verificationKey)
		if err != nil {
			return nil, fmt.Errorf("%w: key %d: %w", ErrInvalidSet, index, err)
		}
		keys = append(keys, key)
	}

	return New(keys...)
}
