package xjwt

import (
	"cmp"
	"context"
	"fmt"
	"slices"
)

type StaticKeySet struct {
	anonymous *VerificationKey
	named     map[string]VerificationKey
}

var _ KeyResolver = (*StaticKeySet)(nil)

func NewStaticKeySet(keys ...VerificationKey) (*StaticKeySet, error) {
	if len(keys) == 0 {
		return nil, fmt.Errorf(
			"%w: at least one verification key is required",
			ErrInvalidConfig,
		)
	}

	keySet := &StaticKeySet{
		named: make(map[string]VerificationKey, len(keys)),
	}

	for _, key := range keys {
		if key.method == nil || key.key == nil {
			return nil, fmt.Errorf(
				"%w: uninitialized verification key",
				ErrInvalidKey,
			)
		}

		if key.id == "" {
			if len(keys) != 1 {
				return nil, fmt.Errorf(
					"%w: anonymous key cannot be mixed with other keys",
					ErrInvalidConfig,
				)
			}

			keySet.anonymous = new(key)
			continue
		}

		if _, exists := keySet.named[key.id]; exists {
			return nil, fmt.Errorf(
				"%w: %q",
				ErrDuplicateKeyID,
				key.id,
			)
		}

		keySet.named[key.id] = key
	}

	return keySet, nil
}

func (s *StaticKeySet) Len() int {
	if s == nil {
		return 0
	}

	if s.anonymous != nil {
		return 1
	}

	return len(s.named)
}

func (s *StaticKeySet) Keys() []VerificationKey {
	if s == nil {
		return nil
	}

	if s.anonymous != nil {
		return []VerificationKey{
			*s.anonymous,
		}
	}

	keys := make([]VerificationKey, 0, len(s.named))

	for _, key := range s.named {
		keys = append(keys, key)
	}

	slices.SortFunc(
		keys,
		func(a, b VerificationKey) int {
			return cmp.Compare(a.id, b.id)
		},
	)

	return keys
}

func (s *StaticKeySet) Resolve(ctx context.Context, header Header) (VerificationKey, error) {
	if s == nil {
		return VerificationKey{}, fmt.Errorf(
			"%w: key set is nil",
			ErrInvalidConfig,
		)
	}

	if s.anonymous != nil {
		return s.anonymous.Resolve(ctx, header)
	}

	if header.KeyID == "" {
		return VerificationKey{}, ErrMissingKeyID
	}

	key, exists := s.named[header.KeyID]
	if !exists {
		return VerificationKey{}, ErrUnknownKey
	}

	return key.Resolve(ctx, header)
}
