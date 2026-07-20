package xjwt

import (
	"context"
	"fmt"
	"sort"
)

type StaticKeySet struct {
	anonymous *VerificationKey
	named     map[string]VerificationKey
}

func NewStaticKeySet(keys ...VerificationKey) (*StaticKeySet, error) {
	if len(keys) == 0 {
		return nil, fmt.Errorf("%w: at least one verification key is required", ErrInvalidConfig)
	}
	s := &StaticKeySet{named: make(map[string]VerificationKey, len(keys))}
	for _, k := range keys {
		if k.method == nil || k.key == nil {
			return nil, fmt.Errorf("%w: uninitialized verification key", ErrInvalidKey)
		}
		if k.id == "" {
			if len(keys) != 1 {
				return nil, fmt.Errorf("%w: anonymous key cannot be mixed with other keys", ErrInvalidConfig)
			}
			c := k.clone()
			s.anonymous = &c
			continue
		}
		if _, ok := s.named[k.id]; ok {
			return nil, fmt.Errorf("%w: %q", ErrDuplicateKeyID, k.id)
		}
		s.named[k.id] = k.clone()
	}
	return s, nil
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
		return []VerificationKey{s.anonymous.clone()}
	}
	ids := make([]string, 0, len(s.named))
	for id := range s.named {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	out := make([]VerificationKey, 0, len(ids))
	for _, id := range ids {
		out = append(out, s.named[id].clone())
	}
	return out
}
func (s *StaticKeySet) Resolve(_ context.Context, h Header) (VerificationKey, error) {
	if s == nil {
		return VerificationKey{}, fmt.Errorf("%w: key set is nil", ErrInvalidConfig)
	}
	if s.anonymous != nil {
		return s.anonymous.Resolve(context.Background(), h)
	}
	if h.KeyID == "" {
		return VerificationKey{}, ErrMissingKeyID
	}
	k, ok := s.named[h.KeyID]
	if !ok {
		return VerificationKey{}, ErrUnknownKey
	}
	if h.Algorithm != k.method.Alg() {
		return VerificationKey{}, ErrUnexpectedAlgorithm
	}
	return k.clone(), nil
}
