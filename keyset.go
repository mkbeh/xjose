package xjwt

import (
	"context"
	"fmt"
	"slices"
)

// StaticKeySet is an immutable in-memory collection of verification keys.
//
// A set may contain either exactly one anonymous key or one or more uniquely
// named keys. Mixing anonymous and named keys is rejected because it makes kid
// selection ambiguous.
type StaticKeySet struct {
	anonymous *VerificationKey
	keys      map[string]VerificationKey
}

// NewStaticKeySet creates an immutable verification-key set.
//
// A single anonymous key accepts only tokens without kid. Named keys require a
// matching kid. When more than one key is supplied, every key must have a
// unique non-empty identifier.
func NewStaticKeySet(keys ...VerificationKey) (*StaticKeySet, error) {
	if len(keys) == 0 {
		return nil, fmt.Errorf("%w: at least one verification key is required", ErrInvalidConfig)
	}

	set := &StaticKeySet{}

	if len(keys) == 1 && keys[0].id == "" {
		key, err := validatedVerificationKey(keys[0])
		if err != nil {
			return nil, fmt.Errorf("verification key 0: %w", err)
		}
		set.anonymous = &key

		return set, nil
	}

	set.keys = make(map[string]VerificationKey, len(keys))
	for index, candidate := range keys {
		key, err := validatedVerificationKey(candidate)
		if err != nil {
			return nil, fmt.Errorf("verification key %d: %w", index, err)
		}
		if key.id == "" {
			return nil, fmt.Errorf(
				"%w: verification key %d is anonymous; named keys are required in a multi-key set",
				ErrInvalidConfig,
				index,
			)
		}
		if _, exists := set.keys[key.id]; exists {
			return nil, fmt.Errorf("%w: %q", ErrDuplicateKeyID, key.id)
		}
		set.keys[key.id] = key
	}

	return set, nil
}

// Len returns the number of verification keys in the set.
func (s *StaticKeySet) Len() int {
	if s == nil {
		return 0
	}
	if s.anonymous != nil {
		return 1
	}

	return len(s.keys)
}

// Keys returns independent copies of all verification keys in deterministic
// order. A single anonymous key is returned as the only element; named keys are
// ordered lexicographically by kid.
func (s *StaticKeySet) Keys() []VerificationKey {
	if s == nil {
		return nil
	}
	if s.anonymous != nil {
		return []VerificationKey{s.anonymous.clone()}
	}

	ids := make([]string, 0, len(s.keys))
	for id := range s.keys {
		ids = append(ids, id)
	}
	slices.Sort(ids)

	keys := make([]VerificationKey, 0, len(ids))
	for _, id := range ids {
		keys = append(keys, s.keys[id].clone())
	}

	return keys
}

// Resolve selects a key by the untrusted JOSE alg and kid header parameters.
func (s *StaticKeySet) Resolve(ctx context.Context, header Header) (VerificationKey, error) {
	if err := ctx.Err(); err != nil {
		return VerificationKey{}, err
	}
	if s == nil || (s.anonymous == nil && len(s.keys) == 0) {
		return VerificationKey{}, fmt.Errorf("%w: static key set is not initialized", ErrInvalidConfig)
	}

	if s.anonymous != nil {
		return s.anonymous.Resolve(ctx, header)
	}
	if header.KeyID == "" {
		return VerificationKey{}, ErrMissingKeyID
	}

	key, exists := s.keys[header.KeyID]
	if !exists {
		return VerificationKey{}, fmt.Errorf("%w: %q", ErrUnknownKey, header.KeyID)
	}
	if key.algorithm != header.Algorithm {
		return VerificationKey{}, fmt.Errorf(
			"%w: key %q uses %s, token uses %s",
			ErrUnexpectedAlgorithm,
			header.KeyID,
			key.algorithm,
			header.Algorithm,
		)
	}

	return key.clone(), nil
}

func validatedVerificationKey(key VerificationKey) (VerificationKey, error) {
	if err := validateKeyID(key.id); err != nil {
		return VerificationKey{}, err
	}
	if key.value == nil {
		return VerificationKey{}, fmt.Errorf("%w: verification key is not initialized", ErrInvalidKey)
	}
	if _, err := key.algorithm.spec(); err != nil {
		return VerificationKey{}, err
	}

	return key.clone(), nil
}
