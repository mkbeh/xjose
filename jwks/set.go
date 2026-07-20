package jwks

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/go-jose/go-jose/v4
	"github.com/golang-jwt/jwt/v5"
	"github.com/mkbeh/xjwt"
)

const DefaultMaxKeys = 100

type Set struct {
	document jose.JSONWebKeySet
	keys     *xjwt.StaticKeySet
}

func New(methods []jwt.SigningMethod, keys ...jose.JSONWebKey) (*Set, error) {
	return newSet(methods, jose.JSONWebKeySet{Keys: append([]jose.JSONWebKey(nil), keys...)}, DefaultMaxKeys)
}
func Parse(data []byte, methods ...jwt.SigningMethod) (*Set, error) {
	return ParseWithLimit(data, DefaultMaxKeys, methods...)
}
func ParseWithLimit(data []byte, max int, methods ...jwt.SigningMethod) (*Set, error) {
	if max <= 0 {
		return nil, fmt.Errorf("%w: max keys must be positive", xjwt.ErrInvalidConfig)
	}
	var doc jose.JSONWebKeySet
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, fmt.Errorf("parse JWKS: %w", err)
	}
	return newSet(methods, doc, max)
}
func FromStaticKeySet(set *xjwt.StaticKeySet) (*Set, error) {
	if set == nil {
		return nil, fmt.Errorf("%w: key set is nil", xjwt.ErrInvalidConfig)
	}
	keys := set.Keys()
	doc := jose.JSONWebKeySet{Keys: make([]jose.JSONWebKey, 0, len(keys))}
	methods := make([]jwt.SigningMethod, 0, len(keys))
	for _, k := range keys {
		raw := k.Key()
		if _, ok := raw.([]byte); ok {
			return nil, fmt.Errorf("%w: symmetric keys are not exported as public JWK", xjwt.ErrInvalidKey)
		}

		v := jose.JSONWebKey{
			Key:       raw,
			KeyID:     k.ID(),
			Algorithm: k.Method().Alg(),
			Use:       "sig",
		}
		if !v.Valid() || !v.IsPublic() {
			return nil, fmt.Errorf("%w: invalid public JWK", xjwt.ErrInvalidKey)
		}

		doc.Keys = append(doc.Keys, v)
		methods = append(methods, k.Method())
	}
	return newSet(methods, doc, DefaultMaxKeys)
}
func newSet(methods []jwt.SigningMethod, doc jose.JSONWebKeySet, max int) (*Set, error) {
	if len(methods) == 0 {
		return nil, fmt.Errorf("%w: at least one signing method is required", xjwt.ErrInvalidConfig)
	}
	if len(doc.Keys) == 0 {
		return nil, fmt.Errorf("%w: JWKS contains no keys", xjwt.ErrInvalidKey)
	}
	if len(doc.Keys) > max {
		return nil, fmt.Errorf("%w: JWKS contains too many keys", xjwt.ErrInvalidKey)
	}
	byAlg := map[string]jwt.SigningMethod{}
	for _, m := range methods {
		if m == nil {
			return nil, fmt.Errorf("%w: nil signing method", xjwt.ErrInvalidConfig)
		}
		byAlg[m.Alg()] = m
	}
	verification := make([]xjwt.VerificationKey, 0, len(doc.Keys))
	for _, k := range doc.Keys {
		if !k.Valid() || !k.IsPublic() || k.Use != "" && k.Use != "sig" {
			continue
		}
		m := byAlg[k.Algorithm]
		if m == nil {
			continue
		}
		if k.Algorithm != "" && k.Algorithm != m.Alg() {
			return nil, xjwt.ErrUnexpectedAlgorithm
		}
		vk, err := xjwt.NewVerificationKey(k.KeyID, m, k.Key)
		if err != nil {
			return nil, err
		}
		verification = append(verification, vk)
	}
	if len(verification) == 0 {
		return nil, fmt.Errorf("%w: JWKS contains no usable verification keys", xjwt.ErrInvalidKey)
	}
	ks, err := xjwt.NewStaticKeySet(verification...)
	if err != nil {
		return nil, err
	}
	return &Set{document: doc, keys: ks}, nil
}
func (s *Set) Resolve(ctx context.Context, h xjwt.Header) (xjwt.VerificationKey, error) {
	if s == nil {
		return xjwt.VerificationKey{}, fmt.Errorf("%w: JWKS is nil", xjwt.ErrInvalidConfig)
	}
	return s.keys.Resolve(ctx, h)
}
func (s *Set) Keys() []jose.JSONWebKey {
	if s == nil {
		return nil
	}
	return append([]jose.JSONWebKey(nil), s.document.Keys...)
}
func (s Set) MarshalJSON() ([]byte, error) { return json.Marshal(s.document) }
