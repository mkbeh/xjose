package xjwt

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"encoding/asn1"
	"fmt"
	"math/big"

	"github.com/golang-jwt/jwt/v5"
)

const minimumRSAKeyBits = 2048

// SignFunc performs a context-aware external signing operation. For hash-based
// methods data is the digest. For Ed25519 data is the original signing input.
type SignFunc func(ctx context.Context, data []byte, opts crypto.SignerOpts) ([]byte, error)

type SigningKey struct {
	id           string
	method       jwt.SigningMethod
	key          any
	verification VerificationKey
}

// NewSigningKey creates a local signing key using an upstream signing method.
func NewSigningKey(id string, method jwt.SigningMethod, key any) (SigningKey, error) {
	if err := validateKeyID(id); err != nil {
		return SigningKey{}, err
	}
	if method == nil {
		return SigningKey{}, fmt.Errorf("%w: signing method is nil", ErrInvalidKey)
	}
	normalized, public, err := validateSigningKey(method, key)
	if err != nil {
		return SigningKey{}, err
	}
	verification, err := NewVerificationKey(id, method, public)
	if err != nil {
		return SigningKey{}, err
	}
	return SigningKey{id: id, method: method, key: normalized, verification: verification}, nil
}

// NewExternalSigningKey creates a context-aware signing key for KMS, Vault or
// another remote signing service.
func NewExternalSigningKey(id string, method jwt.SigningMethod, publicKey crypto.PublicKey, sign SignFunc) (SigningKey, error) {
	if sign == nil {
		return SigningKey{}, fmt.Errorf("%w: sign function is nil", ErrInvalidKey)
	}
	vk, err := NewVerificationKey(id, method, publicKey)
	if err != nil {
		return SigningKey{}, err
	}
	external := &externalMethod{base: method, publicKey: vk.key, sign: sign}
	return SigningKey{id: id, method: external, key: externalKey{}, verification: vk}, nil
}

func (k SigningKey) ID() string                       { return k.id }
func (k SigningKey) Method() jwt.SigningMethod        { return k.method }
func (k SigningKey) VerificationKey() VerificationKey { return k.verification.clone() }

// VerificationKey binds key material to one upstream signing method.
type VerificationKey struct {
	id     string
	method jwt.SigningMethod
	key    any
}

func NewVerificationKey(id string, method jwt.SigningMethod, key any) (VerificationKey, error) {
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
	return VerificationKey{id: id, method: method, key: normalized}, nil
}

func (k VerificationKey) ID() string                { return k.id }
func (k VerificationKey) Method() jwt.SigningMethod { return k.method }
func (k VerificationKey) Key() any                  { return cloneKey(k.key) }
func (k VerificationKey) Resolve(_ context.Context, h Header) (VerificationKey, error) {
	if k.method == nil || k.key == nil {
		return VerificationKey{}, fmt.Errorf("%w: uninitialized verification key", ErrInvalidKey)
	}
	if k.id == "" && h.KeyID != "" {
		return VerificationKey{}, ErrUnknownKey
	}
	if k.id != "" && h.KeyID == "" {
		return VerificationKey{}, ErrMissingKeyID
	}
	if k.id != "" && h.KeyID != k.id {
		return VerificationKey{}, ErrUnknownKey
	}
	if h.Algorithm != k.method.Alg() {
		return VerificationKey{}, ErrUnexpectedAlgorithm
	}
	return k.clone(), nil
}
func (k VerificationKey) clone() VerificationKey {
	return VerificationKey{id: k.id, method: k.method, key: cloneKey(k.key)}
}

func validateKeyID(id string) error {
	if len(id) > 256 {
		return fmt.Errorf("%w: key id is too long", ErrInvalidKeyID)
	}
	for _, r := range id {
		if r < 0x20 || r == 0x7f {
			return fmt.Errorf("%w: key id contains control characters", ErrInvalidKeyID)
		}
	}
	return nil
}

func validateSigningKey(method jwt.SigningMethod, key any) (any, any, error) {
	switch m := method.(type) {
	case *jwt.SigningMethodHMAC:
		secret, ok := key.([]byte)
		if !ok {
			return nil, nil, fmt.Errorf("%w: %s requires []byte", ErrInvalidKey, m.Alg())
		}
		min := m.Hash.Size()
		if len(secret) < min {
			return nil, nil, fmt.Errorf("%w: %s requires at least %d bytes", ErrInvalidKey, m.Alg(), min)
		}
		c := bytes.Clone(secret)
		return c, bytes.Clone(c), nil
	case *jwt.SigningMethodRSA, *jwt.SigningMethodRSAPSS:
		priv, ok := key.(*rsa.PrivateKey)
		if !ok || priv == nil {
			return nil, nil, fmt.Errorf("%w: %s requires *rsa.PrivateKey", ErrInvalidKey, method.Alg())
		}
		if priv.N.BitLen() < minimumRSAKeyBits {
			return nil, nil, fmt.Errorf("%w: RSA key must be at least %d bits", ErrInvalidKey, minimumRSAKeyBits)
		}
		if err := priv.Validate(); err != nil {
			return nil, nil, fmt.Errorf("%w: %v", ErrInvalidKey, err)
		}
		return priv, &priv.PublicKey, nil
	case *jwt.SigningMethodECDSA:
		priv, ok := key.(*ecdsa.PrivateKey)
		if !ok || priv == nil {
			return nil, nil, fmt.Errorf("%w: %s requires *ecdsa.PrivateKey", ErrInvalidKey, m.Alg())
		}
		if priv.Curve.Params().BitSize != m.CurveBits || !priv.Curve.IsOnCurve(priv.X, priv.Y) {
			return nil, nil, fmt.Errorf("%w: ECDSA curve does not match %s", ErrInvalidKey, m.Alg())
		}
		return priv, &priv.PublicKey, nil
	case *jwt.SigningMethodEd25519:
		priv, ok := key.(ed25519.PrivateKey)
		if !ok || len(priv) != ed25519.PrivateKeySize {
			return nil, nil, fmt.Errorf("%w: %s requires ed25519.PrivateKey", ErrInvalidKey, m.Alg())
		}
		c := bytes.Clone(priv)
		return ed25519.PrivateKey(c), ed25519.PublicKey(bytes.Clone(priv.Public().(ed25519.PublicKey))), nil
	default:
		// Upstream/custom methods own their key contract.
		if key == nil {
			return nil, nil, fmt.Errorf("%w: key is nil", ErrInvalidKey)
		}
		if signer, ok := key.(crypto.Signer); ok {
			return key, signer.Public(), nil
		}
		return key, key, nil
	}
}

func validateVerificationKey(method jwt.SigningMethod, key any) (any, error) {
	switch m := method.(type) {
	case *jwt.SigningMethodHMAC:
		secret, ok := key.([]byte)
		if !ok {
			return nil, fmt.Errorf("%w: %s requires []byte", ErrInvalidKey, m.Alg())
		}
		if len(secret) < m.Hash.Size() {
			return nil, fmt.Errorf("%w: %s requires at least %d bytes", ErrInvalidKey, m.Alg(), m.Hash.Size())
		}
		return bytes.Clone(secret), nil
	case *jwt.SigningMethodRSA, *jwt.SigningMethodRSAPSS:
		pub, ok := key.(*rsa.PublicKey)
		if !ok || pub == nil || pub.N == nil || pub.N.BitLen() < minimumRSAKeyBits || pub.E < 3 {
			return nil, fmt.Errorf("%w: invalid RSA public key", ErrInvalidKey)
		}
		return &rsa.PublicKey{N: new(big.Int).Set(pub.N), E: pub.E}, nil
	case *jwt.SigningMethodECDSA:
		pub, ok := key.(*ecdsa.PublicKey)
		if !ok || pub == nil || pub.Curve.Params().BitSize != m.CurveBits || !pub.Curve.IsOnCurve(pub.X, pub.Y) {
			return nil, fmt.Errorf("%w: invalid ECDSA public key for %s", ErrInvalidKey, m.Alg())
		}
		return &ecdsa.PublicKey{Curve: pub.Curve, X: new(big.Int).Set(pub.X), Y: new(big.Int).Set(pub.Y)}, nil
	case *jwt.SigningMethodEd25519:
		pub, ok := key.(ed25519.PublicKey)
		if !ok || len(pub) != ed25519.PublicKeySize {
			return nil, fmt.Errorf("%w: invalid Ed25519 public key", ErrInvalidKey)
		}
		return ed25519.PublicKey(bytes.Clone(pub)), nil
	default:
		if key == nil {
			return nil, fmt.Errorf("%w: key is nil", ErrInvalidKey)
		}
		return key, nil
	}
}

func cloneKey(key any) any {
	switch k := key.(type) {
	case []byte:
		return bytes.Clone(k)
	case ed25519.PublicKey:
		return ed25519.PublicKey(bytes.Clone(k))
	case *rsa.PublicKey:
		return &rsa.PublicKey{N: new(big.Int).Set(k.N), E: k.E}
	case *ecdsa.PublicKey:
		return &ecdsa.PublicKey{Curve: k.Curve, X: new(big.Int).Set(k.X), Y: new(big.Int).Set(k.Y)}
	default:
		return key
	}
}

type externalKey struct{}
type externalMethod struct {
	base      jwt.SigningMethod
	publicKey any
	sign      SignFunc
}

func (m *externalMethod) Alg() string { return m.base.Alg() }
func (m *externalMethod) Verify(s string, sig []byte, key any) error {
	return m.base.Verify(s, sig, key)
}
func (m *externalMethod) Sign(signingString string, _ any) ([]byte, error) {
	return nil, fmt.Errorf("%w: external method requires Signer.Sign context", ErrSign)
}
func (m *externalMethod) signWithContext(ctx context.Context, input string) ([]byte, error) {
	data, opts, normalize, err := externalInput(m.base, []byte(input))
	if err != nil {
		return nil, err
	}
	raw, err := m.sign(ctx, data, opts)
	if err != nil {
		return nil, err
	}
	sig, err := normalize(raw)
	if err != nil {
		return nil, err
	}
	if err := m.base.Verify(input, sig, m.publicKey); err != nil {
		return nil, fmt.Errorf("%w: external signature does not match public key", ErrInvalidSignature)
	}
	return sig, nil
}
func externalInput(method jwt.SigningMethod, input []byte) ([]byte, crypto.SignerOpts, func([]byte) ([]byte, error), error) {
	identity := func(b []byte) ([]byte, error) { return b, nil }
	switch m := method.(type) {
	case *jwt.SigningMethodRSA:
		d := digest(m.Hash, input)
		return d, m.Hash, identity, nil
	case *jwt.SigningMethodRSAPSS:
		d := digest(m.Hash, input)
		return d, &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash, Hash: m.Hash}, identity, nil
	case *jwt.SigningMethodECDSA:
		d := digest(m.Hash, input)
		return d, m.Hash, func(der []byte) ([]byte, error) {
			var rs struct{ R, S *big.Int }
			if _, err := asn1.Unmarshal(der, &rs); err != nil || rs.R == nil || rs.S == nil {
				return nil, fmt.Errorf("%w: invalid ECDSA signature", ErrInvalidSignature)
			}
			size := m.CurveBits / 8
			if m.CurveBits%8 != 0 {
				size++
			}
			out := make([]byte, size*2)
			rs.R.FillBytes(out[:size])
			rs.S.FillBytes(out[size:])
			return out, nil
		}, nil
	case *jwt.SigningMethodEd25519:
		return bytes.Clone(input), crypto.Hash(0), identity, nil
	default:
		return nil, nil, nil, fmt.Errorf("%w: external signing is not supported for %s", ErrInvalidKey, method.Alg())
	}
}
func digest(h crypto.Hash, data []byte) []byte { x := h.New(); _, _ = x.Write(data); return x.Sum(nil) }
