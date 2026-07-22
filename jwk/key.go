package jwk

import (
	"crypto"
	"encoding/base64"
	"encoding/json"
	"fmt"

	"github.com/go-jose/go-jose/v4"
	"github.com/golang-jwt/jwt/v5"
	"github.com/mkbeh/xjwt"
)

const keyUseSignature = "sig"

// Key represents a JSON Web Key.
type Key = jose.JSONWebKey

// FromVerificationKey converts verification key to a public JWK.
//
// Symmetric verification keys cannot be represented as public JWKs.
func FromVerificationKey(key xjwt.VerificationKey) (Key, error) {
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

// Parse parses and validates a public JWK.
func Parse(data []byte) (Key, error) {
	var key Key

	if err := json.Unmarshal(data, &key); err != nil {
		return Key{}, fmt.Errorf(
			"%w: parse JWK: %w",
			xjwt.ErrInvalidKey,
			err,
		)
	}

	if err := validatePublicKey(key); err != nil {
		return Key{}, err
	}

	return key, nil
}

// ToVerificationKey converts a public JWK to verification key.
func ToVerificationKey(key Key, method jwt.SigningMethod) (xjwt.VerificationKey, error) {
	if method == nil {
		return xjwt.VerificationKey{}, fmt.Errorf(
			"%w: signing method is nil",
			xjwt.ErrInvalidConfig,
		)
	}

	if err := validatePublicKey(key); err != nil {
		return xjwt.VerificationKey{}, err
	}

	if key.Use != "" && key.Use != keyUseSignature {
		return xjwt.VerificationKey{}, fmt.Errorf(
			"%w: JWK use %q does not permit signature verification",
			xjwt.ErrInvalidKey,
			key.Use,
		)
	}

	if key.Algorithm != "" && key.Algorithm != method.Alg() {
		return xjwt.VerificationKey{}, xjwt.ErrUnexpectedAlgorithm
	}

	return xjwt.NewVerificationKey(
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
			xjwt.ErrInvalidKey,
			err,
		)
	}

	return base64.RawURLEncoding.EncodeToString(thumbprint), nil
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
