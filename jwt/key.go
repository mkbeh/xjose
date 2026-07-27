package jwt

import (
	"context"
	"crypto"
	"fmt"

	"github.com/golang-jwt/jwt/v5"
)

// SignFunc signs the JWT signing input and returns the signature in the
// format expected by the configured signing method.
type SignFunc func(ctx context.Context, signingInput []byte) ([]byte, error)

// SigningKey binds local or external signing material to one signing method.
type SigningKey struct {
	id           string
	method       jwt.SigningMethod
	key          any
	sign         SignFunc
	verification VerificationKey
}

// NewSigningKey creates a local signing key using an upstream signing method.
//
// Key material is retained as-is and must not be modified while the returned
// SigningKey is in use.
func NewSigningKey(
	id string,
	method jwt.SigningMethod,
	key any,
) (SigningKey, error) {
	if err := validateKeyID(id); err != nil {
		return SigningKey{}, err
	}

	if method == nil {
		return SigningKey{}, fmt.Errorf(
			"%w: signing method is nil",
			ErrInvalidKey,
		)
	}

	verificationMaterial, err := verificationKeyMaterial(key)
	if err != nil {
		return SigningKey{}, err
	}

	verification, err := NewVerificationKey(id, method, verificationMaterial)
	if err != nil {
		return SigningKey{}, err
	}

	return SigningKey{
		id:           id,
		method:       method,
		key:          key,
		verification: verification,
	}, nil
}

// NewExternalSigningKey creates a context-aware signing key for KMS, Vault or
// another remote signing service.
//
// The public key is retained as-is and must not be modified while the returned
// SigningKey is in use.
func NewExternalSigningKey(
	id string,
	method jwt.SigningMethod,
	publicKey crypto.PublicKey,
	sign SignFunc,
) (SigningKey, error) {
	if err := validateKeyID(id); err != nil {
		return SigningKey{}, err
	}

	if method == nil {
		return SigningKey{}, fmt.Errorf(
			"%w: signing method is nil",
			ErrInvalidKey,
		)
	}

	if publicKey == nil {
		return SigningKey{}, fmt.Errorf(
			"%w: public key is nil",
			ErrInvalidKey,
		)
	}

	if sign == nil {
		return SigningKey{}, fmt.Errorf(
			"%w: sign function is nil",
			ErrInvalidKey,
		)
	}

	verification, err := NewVerificationKey(id, method, publicKey)
	if err != nil {
		return SigningKey{}, err
	}

	return SigningKey{
		id:           id,
		method:       method,
		sign:         sign,
		verification: verification,
	}, nil
}

// ID returns the key identifier.
func (k SigningKey) ID() string {
	return k.id
}

// Method returns the signing method associated with the key.
func (k SigningKey) Method() jwt.SigningMethod {
	return k.method
}

// VerificationKey returns the verification key associated with the signing key.
func (k SigningKey) VerificationKey() VerificationKey {
	return k.verification
}

// VerificationKey binds verification material to one signing method.
type VerificationKey struct {
	id     string
	method jwt.SigningMethod
	key    any
}

// NewVerificationKey creates a verification key for an upstream signing method.
//
// Key material is retained as-is and must not be modified while the returned
// VerificationKey is in use.
func NewVerificationKey(
	id string,
	method jwt.SigningMethod,
	key any,
) (VerificationKey, error) {
	if err := validateKeyID(id); err != nil {
		return VerificationKey{}, err
	}

	if method == nil {
		return VerificationKey{}, fmt.Errorf(
			"%w: signing method is nil",
			ErrInvalidKey,
		)
	}

	if key == nil {
		return VerificationKey{}, fmt.Errorf(
			"%w: key is nil",
			ErrInvalidKey,
		)
	}

	return VerificationKey{
		id:     id,
		method: method,
		key:    key,
	}, nil
}

// ID returns the key identifier.
func (k VerificationKey) ID() string {
	return k.id
}

// Method returns the signing method associated with the key.
func (k VerificationKey) Method() jwt.SigningMethod {
	return k.method
}

// Key returns the stored verification key material.
//
// The returned value shares its underlying key material with the
// VerificationKey and must not be modified while the key is in use.
func (k VerificationKey) Key() any {
	return k.key
}

// Resolve returns the key when the protected header matches its identifier
// and signing algorithm.
func (k VerificationKey) Resolve(_ context.Context, header Header) (VerificationKey, error) {
	if k.method == nil || k.key == nil {
		return VerificationKey{}, fmt.Errorf(
			"%w: uninitialized verification key",
			ErrInvalidKey,
		)
	}

	if k.id != "" && header.KeyID == "" {
		return VerificationKey{}, ErrMissingKeyID
	}

	if header.KeyID != k.id {
		return VerificationKey{}, ErrUnknownKey
	}

	if header.Algorithm != k.method.Alg() {
		return VerificationKey{}, ErrUnexpectedAlgorithm
	}

	return k, nil
}

func validateKeyID(id string) error {
	if exceedsLimit(id, maxKeyIDLength) {
		return fmt.Errorf(
			"%w: key id exceeds %d bytes",
			ErrInvalidKeyID,
			maxKeyIDLength,
		)
	}

	return nil
}

func verificationKeyMaterial(key any) (any, error) {
	if key == nil {
		return nil, fmt.Errorf(
			"%w: key is nil",
			ErrInvalidKey,
		)
	}

	signer, ok := key.(crypto.Signer)
	if !ok {
		// Symmetric and custom signing methods may use the same material for
		// signing and verification.
		return key, nil
	}

	publicKey := signer.Public()
	if publicKey == nil {
		return nil, fmt.Errorf(
			"%w: signer returned nil public key",
			ErrInvalidKey,
		)
	}

	return publicKey, nil
}

func (k SigningKey) validate() error {
	if k.method == nil {
		return fmt.Errorf(
			"%w: signing method is nil",
			ErrInvalidKey,
		)
	}

	hasLocalKey := k.key != nil
	hasExternalSigner := k.sign != nil

	switch {
	case !hasLocalKey && !hasExternalSigner:
		return fmt.Errorf(
			"%w: signing backend is missing",
			ErrInvalidKey,
		)

	case hasLocalKey && hasExternalSigner:
		return fmt.Errorf(
			"%w: multiple signing backends are configured",
			ErrInvalidKey,
		)
	}

	if k.verification.method == nil ||
		k.verification.key == nil {
		return fmt.Errorf(
			"%w: verification key is uninitialized",
			ErrInvalidKey,
		)
	}

	if k.id != k.verification.id {
		return fmt.Errorf(
			"%w: signing and verification key ids differ: %q and %q",
			ErrInvalidKey,
			k.id,
			k.verification.id,
		)
	}

	signingAlgorithm := k.method.Alg()
	verificationAlgorithm := k.verification.method.Alg()

	if signingAlgorithm != verificationAlgorithm {
		return fmt.Errorf(
			"%w: signing and verification algorithms differ: %q and %q",
			ErrInvalidKey,
			signingAlgorithm,
			verificationAlgorithm,
		)
	}

	return nil
}

func (k SigningKey) signInput(ctx context.Context, input string) ([]byte, error) {
	if k.sign == nil {
		return k.method.Sign(input, k.key)
	}

	return k.sign(ctx, []byte(input))
}
