package xjwt

import (
	"crypto"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/sha512"
	"fmt"
	"hash"
)

// Algorithm identifies a supported JWS signature algorithm.
type Algorithm string

const (
	HS256 Algorithm = "HS256"
	HS384 Algorithm = "HS384"
	HS512 Algorithm = "HS512"

	RS256 Algorithm = "RS256"
	RS384 Algorithm = "RS384"
	RS512 Algorithm = "RS512"

	PS256 Algorithm = "PS256"
	PS384 Algorithm = "PS384"
	PS512 Algorithm = "PS512"

	ES256 Algorithm = "ES256"
	ES384 Algorithm = "ES384"
	ES512 Algorithm = "ES512"

	Ed25519 Algorithm = "Ed25519"
)

// String returns the JOSE algorithm identifier.
func (a Algorithm) String() string { return string(a) }

// ParseAlgorithm parses a supported JOSE algorithm identifier.
func ParseAlgorithm(value string) (Algorithm, error) {
	algorithm := Algorithm(value)
	if _, err := algorithm.spec(); err != nil {
		return "", err
	}

	return algorithm, nil
}

// IsSupported reports whether the algorithm is supported by xjwt.
func (a Algorithm) IsSupported() bool {
	_, err := a.spec()

	return err == nil
}

type algorithmFamily uint8

const (
	familyHMAC algorithmFamily = iota + 1
	familyRSA
	familyRSAPSS
	familyECDSA
	familyEd25519
)

type algorithmSpec struct {
	family  algorithmFamily
	hash    crypto.Hash
	newHash func() hash.Hash
	curve   elliptic.Curve
}

func (a Algorithm) spec() (algorithmSpec, error) {
	switch a {
	case HS256:
		return algorithmSpec{family: familyHMAC, hash: crypto.SHA256, newHash: sha256.New}, nil
	case HS384:
		return algorithmSpec{family: familyHMAC, hash: crypto.SHA384, newHash: sha512.New384}, nil
	case HS512:
		return algorithmSpec{family: familyHMAC, hash: crypto.SHA512, newHash: sha512.New}, nil
	case RS256:
		return algorithmSpec{family: familyRSA, hash: crypto.SHA256, newHash: sha256.New}, nil
	case RS384:
		return algorithmSpec{family: familyRSA, hash: crypto.SHA384, newHash: sha512.New384}, nil
	case RS512:
		return algorithmSpec{family: familyRSA, hash: crypto.SHA512, newHash: sha512.New}, nil
	case PS256:
		return algorithmSpec{family: familyRSAPSS, hash: crypto.SHA256, newHash: sha256.New}, nil
	case PS384:
		return algorithmSpec{family: familyRSAPSS, hash: crypto.SHA384, newHash: sha512.New384}, nil
	case PS512:
		return algorithmSpec{family: familyRSAPSS, hash: crypto.SHA512, newHash: sha512.New}, nil
	case ES256:
		return algorithmSpec{family: familyECDSA, hash: crypto.SHA256, newHash: sha256.New, curve: elliptic.P256()}, nil
	case ES384:
		return algorithmSpec{family: familyECDSA, hash: crypto.SHA384, newHash: sha512.New384, curve: elliptic.P384()}, nil
	case ES512:
		return algorithmSpec{family: familyECDSA, hash: crypto.SHA512, newHash: sha512.New, curve: elliptic.P521()}, nil
	case Ed25519:
		return algorithmSpec{family: familyEd25519}, nil
	default:
		return algorithmSpec{}, fmt.Errorf("%w: %q", ErrInvalidAlgorithm, a)
	}
}

func (a Algorithm) minimumHMACKeySize() int {
	switch a {
	case HS256:
		return 32
	case HS384:
		return 48
	case HS512:
		return 64
	default:
		return 0
	}
}

func (s algorithmSpec) digest(message []byte) []byte {
	h := s.newHash()
	_, _ = h.Write(message)
	return h.Sum(nil)
}
