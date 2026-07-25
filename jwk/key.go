package jwk

import (
	"crypto"
	"encoding/base64"
	"encoding/json"
	"fmt"

	"github.com/go-jose/go-jose/v4"
	gojwt "github.com/golang-jwt/jwt/v5"
	"github.com/mkbeh/xjose/jwt"
)

const keyUseSignature = "sig"

// Key represents a JSON Web Key.
type Key = jose.JSONWebKey

// FromVerificationKey converts verification key to a public JWK.
//
// Symmetric verification keys cannot be represented as public JWKs.
func FromVerificationKey(key jwt.VerificationKey) (Key, error) {
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

// Parse parses and validates a public JWK.
func Parse(data []byte) (Key, error) {
	var key Key

	if err := json.Unmarshal(data, &key); err != nil {
		return Key{}, fmt.Errorf(
			"%w: parse JWK: %w",
			jwt.ErrInvalidKey,
			err,
		)
	}

	if err := validatePublicKey(key); err != nil {
		return Key{}, err
	}

	return key, nil
}

// ToVerificationKey converts a public JWK to verification key.
func ToVerificationKey(key Key, method gojwt.SigningMethod) (jwt.VerificationKey, error) {
	if method == nil {
		return jwt.VerificationKey{}, fmt.Errorf(
			"%w: signing method is nil",
			jwt.ErrInvalidConfig,
		)
	}

	if err := validatePublicKey(key); err != nil {
		return jwt.VerificationKey{}, err
	}

	if key.Use != "" && key.Use != keyUseSignature {
		return jwt.VerificationKey{}, fmt.Errorf(
			"%w: JWK use %q does not permit signature verification",
			jwt.ErrInvalidKey,
			key.Use,
		)
	}

	if key.Algorithm != "" && key.Algorithm != method.Alg() {
		return jwt.VerificationKey{}, jwt.ErrUnexpectedAlgorithm
	}

	return jwt.NewVerificationKey(
		key.KeyID,
		method,
		key.Key,
	)
}

// ThumbprintID returns the base64url-encoded SHA-256 RFC 7638 thumbprint.
func ThumbprintID(key Key) (string, error) {
	if err := validatePublicKey(key); err != nil {
		return "", err
	}

	thumbprint, err := key.Thumbprint(crypto.SHA256)
	if err != nil {
		return "", fmt.Errorf(
			"%w: calculate JWK thumbprint: %w",
			jwt.ErrInvalidKey,
			err,
		)
	}

	return base64.RawURLEncoding.EncodeToString(thumbprint), nil
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
