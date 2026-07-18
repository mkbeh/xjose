package xjwt

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"math/big"
)

const minimumRSAKeyBits = 2048

// SignFunc performs a context-aware external signing operation.
//
// For hash-based algorithms, data is the digest of the JWS signing input and
// opts.HashFunc identifies its hash. For Ed25519, data is the original JWS
// signing input and opts.HashFunc returns zero. The returned signature must use
// the native crypto.Signer representation: RSA and Ed25519 return raw bytes,
// while ECDSA returns an ASN.1 DER sequence containing r and s. xjwt converts
// native signatures to the JOSE representation.
type SignFunc func(ctx context.Context, data []byte, opts crypto.SignerOpts) ([]byte, error)

type signOperation func(ctx context.Context, signingInput []byte) ([]byte, error)

// SigningKey binds one signing backend to exactly one JWS algorithm.
// SigningKey values are immutable after construction and safe for concurrent
// use when the supplied crypto.Signer or SignFunc is safe for concurrent use.
type SigningKey struct {
	id           string
	algorithm    Algorithm
	verification VerificationKey
	sign         signOperation
}

// NewHMACSigningKey creates a symmetric HMAC signing key. The secret is copied.
func NewHMACSigningKey(id string, algorithm Algorithm, secret []byte) (SigningKey, error) {
	if err := validateKeyID(id); err != nil {
		return SigningKey{}, err
	}
	spec, err := algorithm.spec()
	if err != nil {
		return SigningKey{}, err
	}
	if spec.family != familyHMAC {
		return SigningKey{}, fmt.Errorf("%w: %s is not an HMAC algorithm", ErrInvalidKey, algorithm)
	}
	minimum := algorithm.minimumHMACKeySize()
	if len(secret) < minimum {
		return SigningKey{}, fmt.Errorf("%w: %s requires at least %d key bytes", ErrInvalidKey, algorithm, minimum)
	}
	key := bytes.Clone(secret)
	verification := VerificationKey{
		id:        id,
		algorithm: algorithm,
		value:     bytes.Clone(key),
	}

	return SigningKey{
		id:           id,
		algorithm:    algorithm,
		verification: verification,
		sign: func(ctx context.Context, signingInput []byte) ([]byte, error) {
			if err := ctx.Err(); err != nil {
				return nil, err
			}
			return signHMAC(spec, key, signingInput), nil
		},
	}, nil
}

// NewAsymmetricSigningKey creates a signing key backed by crypto.Signer. It
// supports local private keys and opaque HSM/TPM/PKCS#11-backed keys.
//
// crypto.Signer has no context-aware method; cancellation is checked before
// and after the Sign call. Use NewExternalSigningKey for network signers that
// need context propagation.
func NewAsymmetricSigningKey(id string, algorithm Algorithm, signer crypto.Signer) (SigningKey, error) {
	if err := validateKeyID(id); err != nil {
		return SigningKey{}, err
	}
	if signer == nil {
		return SigningKey{}, fmt.Errorf("%w: crypto signer is nil", ErrInvalidKey)
	}
	spec, err := algorithm.spec()
	if err != nil {
		return SigningKey{}, err
	}
	if spec.family == familyHMAC {
		return SigningKey{}, fmt.Errorf("%w: %s requires NewHMACSigningKey", ErrInvalidKey, algorithm)
	}
	normalizedSigner, publicKey, err := normalizeCryptoSigner(algorithm, signer)
	if err != nil {
		return SigningKey{}, err
	}
	verification := VerificationKey{
		id:        id,
		algorithm: algorithm,
		value:     publicKey,
	}

	return SigningKey{
		id:           id,
		algorithm:    algorithm,
		verification: verification,
		sign: newAsymmetricSignOperation(algorithm, publicKey,
			func(_ context.Context, data []byte, opts crypto.SignerOpts) ([]byte, error) {
				return normalizedSigner.Sign(rand.Reader, data, opts)
			}),
	}, nil
}

// NewExternalSigningKey creates a context-aware signing key for KMS, Vault, or
// another remote signing service. Construction validates only the public key
// and callback; it never performs a remote probe. Each returned signature is
// verified against the configured public key before Sign returns a token.
func NewExternalSigningKey(
	id string,
	algorithm Algorithm,
	publicKey crypto.PublicKey,
	sign SignFunc,
) (SigningKey, error) {
	if err := validateKeyID(id); err != nil {
		return SigningKey{}, err
	}
	if sign == nil {
		return SigningKey{}, fmt.Errorf("%w: external sign function is nil", ErrInvalidKey)
	}
	spec, err := algorithm.spec()
	if err != nil {
		return SigningKey{}, err
	}
	if spec.family == familyHMAC {
		return SigningKey{}, fmt.Errorf("%w: external signing requires an asymmetric algorithm", ErrInvalidKey)
	}
	normalizedPublicKey, err := normalizePublicKey(algorithm, publicKey)
	if err != nil {
		return SigningKey{}, err
	}
	verification := VerificationKey{
		id:        id,
		algorithm: algorithm,
		value:     normalizedPublicKey,
	}
	signOperation := newAsymmetricSignOperation(algorithm, normalizedPublicKey, sign)

	return SigningKey{
		id:           id,
		algorithm:    algorithm,
		verification: verification,
		sign: func(ctx context.Context, signingInput []byte) ([]byte, error) {
			signature, err := signOperation(ctx, signingInput)
			if err != nil {
				return nil, err
			}
			if err := verifySignature(algorithm, verification, signingInput, signature); err != nil {
				return nil, fmt.Errorf(
					"%w: external signer returned a signature that does not match the configured public key",
					ErrInvalidSignature,
				)
			}
			return signature, nil
		},
	}, nil
}

// ID returns the optional JOSE key identifier.
func (k SigningKey) ID() string { return k.id }

// Algorithm returns the algorithm to which this key is bound.
func (k SigningKey) Algorithm() Algorithm { return k.algorithm }

// VerificationKey returns a copy of the verification material corresponding to
// this signing key.
func (k SigningKey) VerificationKey() VerificationKey { return k.verification.clone() }

// VerificationKey binds verification material to exactly one JWS algorithm.
type VerificationKey struct {
	id        string
	algorithm Algorithm
	value     any
}

// NewHMACVerificationKey creates a symmetric HMAC verification key. The secret
// is copied.
func NewHMACVerificationKey(id string, algorithm Algorithm, secret []byte) (VerificationKey, error) {
	if err := validateKeyID(id); err != nil {
		return VerificationKey{}, err
	}
	spec, err := algorithm.spec()
	if err != nil {
		return VerificationKey{}, err
	}
	if spec.family != familyHMAC {
		return VerificationKey{}, fmt.Errorf("%w: %s is not an HMAC algorithm", ErrInvalidKey, algorithm)
	}
	minimum := algorithm.minimumHMACKeySize()
	if len(secret) < minimum {
		return VerificationKey{}, fmt.Errorf("%w: %s requires at least %d key bytes", ErrInvalidKey, algorithm, minimum)
	}
	return VerificationKey{
		id:        id,
		algorithm: algorithm,
		value:     bytes.Clone(secret),
	}, nil
}

// NewVerificationKey creates an asymmetric verification key.
func NewVerificationKey(id string, algorithm Algorithm, publicKey crypto.PublicKey) (VerificationKey, error) {
	if err := validateKeyID(id); err != nil {
		return VerificationKey{}, err
	}
	spec, err := algorithm.spec()
	if err != nil {
		return VerificationKey{}, err
	}
	if spec.family == familyHMAC {
		return VerificationKey{}, fmt.Errorf("%w: %s requires NewHMACVerificationKey", ErrInvalidKey, algorithm)
	}
	normalized, err := normalizePublicKey(algorithm, publicKey)
	if err != nil {
		return VerificationKey{}, err
	}
	return VerificationKey{
		id:        id,
		algorithm: algorithm,
		value:     normalized,
	}, nil
}

// ID returns the optional JOSE key identifier.
func (k VerificationKey) ID() string { return k.id }

// Algorithm returns the algorithm to which this key is bound.
func (k VerificationKey) Algorithm() Algorithm { return k.algorithm }

// PublicKey returns a copy of the asymmetric public key. HMAC verification
// keys have no public key and return ErrInvalidKey.
func (k VerificationKey) PublicKey() (crypto.PublicKey, error) {
	if k.value == nil {
		return nil, fmt.Errorf("%w: verification key is not initialized", ErrInvalidKey)
	}
	if _, ok := k.value.([]byte); ok {
		return nil, fmt.Errorf("%w: HMAC verification keys do not have a public key", ErrInvalidKey)
	}

	return cloneVerificationValue(k.value), nil
}

func (k VerificationKey) clone() VerificationKey {
	return VerificationKey{
		id:        k.id,
		algorithm: k.algorithm,
		value:     cloneVerificationValue(k.value),
	}
}

func normalizeCryptoSigner(algorithm Algorithm, signer crypto.Signer) (crypto.Signer, any, error) {
	switch key := signer.(type) {
	case *rsa.PrivateKey:
		if key == nil || key.N == nil || key.N.BitLen() < minimumRSAKeyBits {
			return nil, nil, fmt.Errorf("%w: RSA private key must contain at least %d bits", ErrInvalidKey, minimumRSAKeyBits)
		}
		if err := key.Validate(); err != nil {
			return nil, nil, fmt.Errorf("%w: validate RSA private key: %w", ErrInvalidKey, err)
		}
	case *ecdsa.PrivateKey:
		if !validECDSAPrivateKey(algorithm, key) {
			return nil, nil, fmt.Errorf("%w: %s requires a valid matching ECDSA private key", ErrInvalidKey, algorithm)
		}
	case ed25519.PrivateKey:
		if len(key) != ed25519.PrivateKeySize {
			return nil, nil, fmt.Errorf("%w: Ed25519 requires a %d-byte private key", ErrInvalidKey, ed25519.PrivateKeySize)
		}
		derived := ed25519.NewKeyFromSeed(key.Seed())
		if !bytes.Equal(key, derived) {
			return nil, nil, fmt.Errorf("%w: Ed25519 private key is inconsistent with its seed", ErrInvalidKey)
		}
		signer = ed25519.PrivateKey(bytes.Clone(key))
	}
	publicKey := signer.Public()
	normalizedPublicKey, err := normalizePublicKey(algorithm, publicKey)
	if err != nil {
		return nil, nil, err
	}
	return signer, normalizedPublicKey, nil
}

func normalizePublicKey(algorithm Algorithm, value any) (any, error) {
	spec, err := algorithm.spec()
	if err != nil {
		return nil, err
	}
	switch spec.family {
	case familyRSA, familyRSAPSS:
		key, ok := value.(*rsa.PublicKey)
		if !ok || !validRSAPublicKey(key) {
			return nil, fmt.Errorf(
				"%w: %s requires a valid RSA public key of at least %d bits",
				ErrInvalidKey,
				algorithm,
				minimumRSAKeyBits,
			)
		}
		return cloneRSAPublicKey(key), nil
	case familyECDSA:
		key, ok := value.(*ecdsa.PublicKey)
		if !ok || !validECDSAPublicKey(algorithm, key) {
			return nil, fmt.Errorf("%w: %s requires a valid matching ECDSA public key", ErrInvalidKey, algorithm)
		}
		return cloneECDSAPublicKey(key), nil
	case familyEd25519:
		key, ok := value.(ed25519.PublicKey)
		if !ok || len(key) != ed25519.PublicKeySize {
			return nil, fmt.Errorf("%w: Ed25519 requires a %d-byte public key", ErrInvalidKey, ed25519.PublicKeySize)
		}
		return ed25519.PublicKey(bytes.Clone(key)), nil
	default:
		return nil, fmt.Errorf("%w: %s requires symmetric key material", ErrInvalidKey, algorithm)
	}
}

func cloneVerificationValue(value any) any {
	switch key := value.(type) {
	case []byte:
		return bytes.Clone(key)
	case *rsa.PublicKey:
		return cloneRSAPublicKey(key)
	case *ecdsa.PublicKey:
		return cloneECDSAPublicKey(key)
	case ed25519.PublicKey:
		return ed25519.PublicKey(bytes.Clone(key))
	default:
		return value
	}
}

func cloneRSAPublicKey(key *rsa.PublicKey) *rsa.PublicKey {
	if key == nil {
		return nil
	}
	return &rsa.PublicKey{
		N: new(big.Int).Set(key.N),
		E: key.E,
	}
}

func cloneECDSAPublicKey(key *ecdsa.PublicKey) *ecdsa.PublicKey {
	if key == nil {
		return nil
	}
	return &ecdsa.PublicKey{
		Curve: key.Curve,
		X:     new(big.Int).Set(key.X),
		Y:     new(big.Int).Set(key.Y),
	}
}

func validRSAPublicKey(key *rsa.PublicKey) bool {
	return key != nil &&
		key.N != nil &&
		key.N.Sign() > 0 &&
		key.N.Bit(0) == 1 &&
		key.N.BitLen() >= minimumRSAKeyBits &&
		key.E >= 3 &&
		key.E <= 1<<31-1 &&
		key.E%2 == 1
}

func validECDSAPrivateKey(algorithm Algorithm, key *ecdsa.PrivateKey) bool {
	if key == nil || key.D == nil || !validECDSAPublicKey(algorithm, &key.PublicKey) {
		return false
	}
	params := key.Curve.Params()
	if key.D.Sign() <= 0 || key.D.Cmp(params.N) >= 0 {
		return false
	}
	x, y := key.Curve.ScalarBaseMult(key.D.Bytes())
	return x.Cmp(key.X) == 0 && y.Cmp(key.Y) == 0
}

func validECDSAPublicKey(algorithm Algorithm, key *ecdsa.PublicKey) bool {
	if key == nil || key.Curve == nil || key.X == nil || key.Y == nil {
		return false
	}
	spec, err := algorithm.spec()
	if err != nil || spec.family != familyECDSA || key.Curve != spec.curve {
		return false
	}
	return key.Curve.IsOnCurve(key.X, key.Y)
}
