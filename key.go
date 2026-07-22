package xjwt

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"fmt"
	"unicode"
	"unicode/utf8"

	"github.com/golang-jwt/jwt/v5"
)

const minimumRSAKeyBits = 2048

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
// HMAC and Ed25519 keys are copied. RSA and ECDSA keys are retained and must
// not be modified while the returned SigningKey is in use.
func NewSigningKey(
	id string,
	method jwt.SigningMethod,
	key any,
) (SigningKey, error) {
	if err := validateKeyID(id); err != nil {
		return SigningKey{}, err
	}
	if method == nil {
		return SigningKey{}, fmt.Errorf("%w: signing method is nil", ErrInvalidKey)
	}

	normalized, publicKey, err := validateSigningKey(method, key)
	if err != nil {
		return SigningKey{}, err
	}

	verification, err := NewVerificationKey(id, method, publicKey)
	if err != nil {
		return SigningKey{}, err
	}

	return SigningKey{
		id:           id,
		method:       method,
		key:          normalized,
		verification: verification,
	}, nil
}

// NewExternalSigningKey creates a context-aware signing key for KMS, Vault or
// another remote signing service.
//
// The public key is retained for RSA and ECDSA and must not be modified while
// the returned SigningKey is in use. Ed25519 public keys are copied.
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
		return SigningKey{}, fmt.Errorf("%w: signing method is nil", ErrInvalidKey)
	}
	if sign == nil {
		return SigningKey{}, fmt.Errorf("%w: sign function is nil", ErrInvalidKey)
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

func (k SigningKey) ID() string {
	return k.id
}

func (k SigningKey) Method() jwt.SigningMethod {
	return k.method
}

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
// HMAC and Ed25519 keys are copied. RSA and ECDSA keys are retained and must
// not be modified while the returned VerificationKey is in use.
func NewVerificationKey(
	id string,
	method jwt.SigningMethod,
	key any,
) (VerificationKey, error) {
	if err := validateKeyID(id); err != nil {
		return VerificationKey{}, err
	}
	if method == nil {
		return VerificationKey{}, fmt.Errorf("%w: signing method is nil", ErrInvalidKey)
	}

	normalized, err := validateVerificationKey(method, key)
	if err != nil {
		return VerificationKey{}, err
	}

	return VerificationKey{
		id:     id,
		method: method,
		key:    normalized,
	}, nil
}

func (k VerificationKey) ID() string {
	return k.id
}

func (k VerificationKey) Method() jwt.SigningMethod {
	return k.method
}

// Key returns the verification key material.
//
// HMAC and Ed25519 keys are copied. RSA, ECDSA and custom key objects are
// returned as-is and must be treated as immutable.
func (k VerificationKey) Key() any {
	switch key := k.key.(type) {
	case []byte:
		return bytes.Clone(key)
	case ed25519.PublicKey:
		return ed25519.PublicKey(bytes.Clone(key))
	default:
		return key
	}
}

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
	if len(id) > maxKeyIDLength {
		return fmt.Errorf(
			"%w: key id is too long",
			ErrInvalidKeyID,
		)
	}

	if !utf8.ValidString(id) {
		return fmt.Errorf(
			"%w: key id is not valid UTF-8",
			ErrInvalidKeyID,
		)
	}

	for _, r := range id {
		if !unicode.IsPrint(r) {
			return fmt.Errorf(
				"%w: key id contains non-printable characters",
				ErrInvalidKeyID,
			)
		}
	}

	return nil
}

func validateSigningKey(method jwt.SigningMethod, key any) (any, any, error) {
	if method == nil {
		return nil, nil, fmt.Errorf(
			"%w: signing method is nil",
			ErrInvalidKey,
		)
	}

	if key == nil {
		return nil, nil, fmt.Errorf(
			"%w: key is nil",
			ErrInvalidKey,
		)
	}

	switch method := method.(type) {
	case *jwt.SigningMethodHMAC:
		if err := validateHash(method.Alg(), method.Hash); err != nil {
			return nil, nil, err
		}

		secret, ok := key.([]byte)
		if !ok {
			return nil, nil, fmt.Errorf(
				"%w: %s requires []byte",
				ErrInvalidKey,
				method.Alg(),
			)
		}

		minSize := method.Hash.Size()
		if len(secret) < minSize {
			return nil, nil, fmt.Errorf(
				"%w: %s requires at least %d bytes",
				ErrInvalidKey,
				method.Alg(),
				minSize,
			)
		}

		signingKey := bytes.Clone(secret)

		// NewVerificationKey will create its own copy.
		return signingKey, signingKey, nil

	case *jwt.SigningMethodRSA:
		if err := validateHash(method.Alg(), method.Hash); err != nil {
			return nil, nil, err
		}

		if err := validateRSAPrivateKey(method.Alg(), key); err != nil {
			return nil, nil, err
		}

	case *jwt.SigningMethodRSAPSS:
		if err := validateHash(method.Alg(), method.Hash); err != nil {
			return nil, nil, err
		}

		if err := validateRSAPrivateKey(method.Alg(), key); err != nil {
			return nil, nil, err
		}

	case *jwt.SigningMethodECDSA:
		if err := validateHash(method.Alg(), method.Hash); err != nil {
			return nil, nil, err
		}

		privateKey, ok := key.(*ecdsa.PrivateKey)
		if !ok || privateKey == nil {
			return nil, nil, fmt.Errorf(
				"%w: %s requires *ecdsa.PrivateKey",
				ErrInvalidKey,
				method.Alg(),
			)
		}

		if privateKey.Curve == nil {
			return nil, nil, fmt.Errorf(
				"%w: ECDSA curve is nil",
				ErrInvalidKey,
			)
		}

		params := privateKey.Params()
		if params == nil ||
			params.BitSize != method.CurveBits {
			return nil, nil, fmt.Errorf(
				"%w: ECDSA curve does not match %s",
				ErrInvalidKey,
				method.Alg(),
			)
		}

		raw, err := privateKey.Bytes()
		if err != nil {
			return nil, nil, fmt.Errorf(
				"%w: invalid ECDSA private key: %w",
				ErrInvalidKey,
				err,
			)
		}
		clear(raw)

	case *jwt.SigningMethodEd25519:
		privateKey, ok := key.(ed25519.PrivateKey)
		if !ok ||
			len(privateKey) != ed25519.PrivateKeySize {
			return nil, nil, fmt.Errorf(
				"%w: %s requires ed25519.PrivateKey",
				ErrInvalidKey,
				method.Alg(),
			)
		}

		cloned := ed25519.PrivateKey(
			bytes.Clone(privateKey),
		)

		expected := ed25519.NewKeyFromSeed(
			cloned.Seed(),
		)
		if !bytes.Equal(cloned, expected) {
			return nil, nil, fmt.Errorf(
				"%w: inconsistent Ed25519 private key",
				ErrInvalidKey,
			)
		}

		key = cloned

	default:
		// Custom signing methods own their key contract.
		if signer, ok := key.(crypto.Signer); ok {
			publicKey := signer.Public()
			if publicKey == nil {
				return nil, nil, fmt.Errorf(
					"%w: signer returned nil public key",
					ErrInvalidKey,
				)
			}

			return key, publicKey, nil
		}

		return key, key, nil
	}

	signer, ok := key.(crypto.Signer)
	if !ok {
		return nil, nil, fmt.Errorf(
			"%w: %s key does not implement crypto.Signer",
			ErrInvalidKey,
			method.Alg(),
		)
	}

	publicKey := signer.Public()
	if publicKey == nil {
		return nil, nil, fmt.Errorf(
			"%w: signer returned nil public key",
			ErrInvalidKey,
		)
	}

	return key, publicKey, nil
}

func validateRSAPrivateKey(algorithm string, key any) error {
	privateKey, ok := key.(*rsa.PrivateKey)
	if !ok || privateKey == nil {
		return fmt.Errorf(
			"%w: %s requires *rsa.PrivateKey",
			ErrInvalidKey,
			algorithm,
		)
	}

	if privateKey.N == nil ||
		privateKey.N.Sign() <= 0 ||
		privateKey.N.BitLen() < minimumRSAKeyBits {
		return fmt.Errorf(
			"%w: RSA key must be at least %d bits",
			ErrInvalidKey,
			minimumRSAKeyBits,
		)
	}

	if err := privateKey.Validate(); err != nil {
		return fmt.Errorf(
			"%w: RSA private key validation failed: %w",
			ErrInvalidKey,
			err,
		)
	}

	return nil
}

func validateVerificationKey(method jwt.SigningMethod, key any) (any, error) {
	if method == nil {
		return nil, fmt.Errorf(
			"%w: signing method is nil",
			ErrInvalidKey,
		)
	}

	if key == nil {
		return nil, fmt.Errorf(
			"%w: key is nil",
			ErrInvalidKey,
		)
	}

	switch method := method.(type) {
	case *jwt.SigningMethodHMAC:
		if err := validateHash(method.Alg(), method.Hash); err != nil {
			return nil, err
		}

		secret, ok := key.([]byte)
		if !ok {
			return nil, fmt.Errorf(
				"%w: %s requires []byte",
				ErrInvalidKey,
				method.Alg(),
			)
		}

		minSize := method.Hash.Size()
		if len(secret) < minSize {
			return nil, fmt.Errorf(
				"%w: %s requires at least %d bytes",
				ErrInvalidKey,
				method.Alg(),
				minSize,
			)
		}

		return bytes.Clone(secret), nil

	case *jwt.SigningMethodRSA:
		if err := validateHash(method.Alg(), method.Hash); err != nil {
			return nil, err
		}

		return validateRSAPublicKey(method.Alg(), key)

	case *jwt.SigningMethodRSAPSS:
		if err := validateHash(method.Alg(), method.Hash); err != nil {
			return nil, err
		}

		return validateRSAPublicKey(method.Alg(), key)

	case *jwt.SigningMethodECDSA:
		if err := validateHash(method.Alg(), method.Hash); err != nil {
			return nil, err
		}

		publicKey, ok := key.(*ecdsa.PublicKey)
		if !ok || publicKey == nil {
			return nil, fmt.Errorf(
				"%w: %s requires *ecdsa.PublicKey",
				ErrInvalidKey,
				method.Alg(),
			)
		}

		if publicKey.Curve == nil {
			return nil, fmt.Errorf(
				"%w: ECDSA curve is nil",
				ErrInvalidKey,
			)
		}

		params := publicKey.Params()
		if params == nil ||
			params.BitSize != method.CurveBits {
			return nil, fmt.Errorf(
				"%w: ECDSA curve does not match %s",
				ErrInvalidKey,
				method.Alg(),
			)
		}

		if _, err := publicKey.Bytes(); err != nil {
			return nil, fmt.Errorf(
				"%w: invalid ECDSA public key: %w",
				ErrInvalidKey,
				err,
			)
		}

		return publicKey, nil

	case *jwt.SigningMethodEd25519:
		publicKey, ok := key.(ed25519.PublicKey)
		if !ok ||
			len(publicKey) != ed25519.PublicKeySize {
			return nil, fmt.Errorf(
				"%w: %s requires ed25519.PublicKey",
				ErrInvalidKey,
				method.Alg(),
			)
		}

		return ed25519.PublicKey(
			bytes.Clone(publicKey),
		), nil

	default:
		// Custom signing methods own their key contract.
		return key, nil
	}
}

func validateRSAPublicKey(algorithm string, key any) (*rsa.PublicKey, error) {
	publicKey, ok := key.(*rsa.PublicKey)
	if !ok || publicKey == nil {
		return nil, fmt.Errorf(
			"%w: %s requires *rsa.PublicKey",
			ErrInvalidKey,
			algorithm,
		)
	}

	if publicKey.N == nil ||
		publicKey.N.Sign() <= 0 ||
		publicKey.N.BitLen() < minimumRSAKeyBits ||
		publicKey.E < 3 ||
		publicKey.E%2 == 0 {
		return nil, fmt.Errorf(
			"%w: invalid RSA public key for %s",
			ErrInvalidKey,
			algorithm,
		)
	}

	return publicKey, nil
}

func validateHash(algorithm string, hash crypto.Hash) error {
	if hash == 0 || !hash.Available() {
		return fmt.Errorf(
			"%w: hash is unavailable for %s",
			ErrInvalidKey,
			algorithm,
		)
	}

	return nil
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
