package jwk

import (
	"crypto"
	"encoding/base64"
	"encoding/json"
	"fmt"

	"github.com/go-jose/go-jose/v4
	"github.com/golang-jwt/jwt/v5"
	"github.com/mkbeh/xjwt"
)

type Key = jose.JSONWebKey

func FromVerificationKey(key xjwt.VerificationKey) (jose.JSONWebKey, error) {
	raw := key.Key()
	switch raw.(type) {
	case []byte:
		return jose.JSONWebKey{}, fmt.Errorf("%w: symmetric keys are not exported as public JWK", xjwt.ErrInvalidKey)
	}
	jwk := jose.JSONWebKey{Key: raw, KeyID: key.ID(), Algorithm: key.Method().Alg(), Use: "sig"}
	if !jwk.Valid() || !jwk.IsPublic() {
		return jose.JSONWebKey{}, fmt.Errorf("%w: invalid public JWK", xjwt.ErrInvalidKey)
	}
	return jwk, nil
}
func Parse(data []byte) (jose.JSONWebKey, error) {
	var key jose.JSONWebKey
	if err := json.Unmarshal(data, &key); err != nil {
		return jose.JSONWebKey{}, fmt.Errorf("parse JWK: %w", err)
	}
	if !key.Valid() || !key.IsPublic() {
		return jose.JSONWebKey{}, fmt.Errorf("%w: JWK must contain a valid public key", xjwt.ErrInvalidKey)
	}
	return key, nil
}
func VerificationKey(key jose.JSONWebKey, method jwt.SigningMethod) (xjwt.VerificationKey, error) {
	if method == nil {
		return xjwt.VerificationKey{}, fmt.Errorf("%w: signing method is nil", xjwt.ErrInvalidConfig)
	}
	if key.Algorithm != "" && key.Algorithm != method.Alg() {
		return xjwt.VerificationKey{}, xjwt.ErrUnexpectedAlgorithm
	}
	if !key.Valid() || !key.IsPublic() {
		return xjwt.VerificationKey{}, fmt.Errorf("%w: invalid public JWK", xjwt.ErrInvalidKey)
	}
	return xjwt.NewVerificationKey(key.KeyID, method, key.Key)
}
func ThumbprintID(key jose.JSONWebKey) (string, error) {
	sum, err := key.Thumbprint(crypto.SHA256)
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(sum), nil
}
