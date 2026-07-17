package xjwt

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/rsa"
	"crypto/subtle"
	"encoding/asn1"
	"fmt"
	"math/big"
)

func newAsymmetricSignOperation(algorithm Algorithm, publicKey any, sign SignFunc) signOperation {
	return func(ctx context.Context, signingInput []byte) ([]byte, error) {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		data, opts, err := signerInput(algorithm, signingInput)
		if err != nil {
			return nil, err
		}
		nativeSignature, err := sign(ctx, data, opts)
		if err != nil {
			return nil, err
		}
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		return normalizeNativeSignature(algorithm, publicKey, nativeSignature)
	}
}

func signerInput(algorithm Algorithm, signingInput []byte) ([]byte, crypto.SignerOpts, error) {
	spec, err := algorithm.spec()
	if err != nil {
		return nil, nil, err
	}
	if spec.family == familyHMAC {
		return nil, nil, fmt.Errorf("%w: HMAC does not use crypto.Signer", ErrInvalidKey)
	}
	if spec.family == familyEd25519 {
		return append([]byte(nil), signingInput...), crypto.Hash(0), nil
	}
	digest := spec.digest(signingInput)
	if spec.family == familyRSAPSS {
		return digest, &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash, Hash: spec.hash}, nil
	}
	return digest, spec.hash, nil
}

func normalizeNativeSignature(algorithm Algorithm, publicKey any, signature []byte) ([]byte, error) {
	spec, err := algorithm.spec()
	if err != nil {
		return nil, err
	}
	switch spec.family {
	case familyRSA, familyRSAPSS:
		key := publicKey.(*rsa.PublicKey)
		expectedSize := (key.N.BitLen() + 7) / 8
		if len(signature) != expectedSize {
			return nil, fmt.Errorf(
				"%w: RSA signature has %d bytes, expected %d",
				ErrInvalidSignature,
				len(signature),
				expectedSize,
			)
		}
		return append([]byte(nil), signature...), nil
	case familyECDSA:
		key := publicKey.(*ecdsa.PublicKey)
		var values struct{ R, S *big.Int }
		rest, err := asn1.Unmarshal(signature, &values)
		if err != nil || len(rest) != 0 || values.R == nil || values.S == nil {
			return nil, fmt.Errorf("%w: invalid ECDSA ASN.1 signature", ErrInvalidSignature)
		}
		if values.R.Sign() <= 0 || values.S.Sign() <= 0 ||
			values.R.Cmp(key.Params().N) >= 0 || values.S.Cmp(key.Params().N) >= 0 {
			return nil, fmt.Errorf("%w: ECDSA signature values are out of range", ErrInvalidSignature)
		}
		width := (key.Params().BitSize + 7) / 8
		joseSignature := make([]byte, 2*width)
		values.R.FillBytes(joseSignature[:width])
		values.S.FillBytes(joseSignature[width:])
		return joseSignature, nil
	case familyEd25519:
		if len(signature) != ed25519.SignatureSize {
			return nil, fmt.Errorf(
				"%w: Ed25519 signature has %d bytes, expected %d",
				ErrInvalidSignature,
				len(signature),
				ed25519.SignatureSize,
			)
		}
		return append([]byte(nil), signature...), nil
	default:
		return nil, fmt.Errorf("%w: unsupported native signature for %s", ErrInvalidAlgorithm, algorithm)
	}
}

func expectedSignatureSize(algorithm Algorithm, key VerificationKey) (int, error) {
	spec, err := algorithm.spec()
	if err != nil {
		return 0, err
	}

	switch spec.family {
	case familyHMAC:
		return spec.newHash().Size(), nil
	case familyRSA, familyRSAPSS:
		publicKey := key.value.(*rsa.PublicKey)
		return (publicKey.N.BitLen() + 7) / 8, nil
	case familyECDSA:
		publicKey := key.value.(*ecdsa.PublicKey)
		width := (publicKey.Params().BitSize + 7) / 8
		return 2 * width, nil
	case familyEd25519:
		return ed25519.SignatureSize, nil
	default:
		return 0, ErrInvalidAlgorithm
	}
}

func signHMAC(spec algorithmSpec, secret, signingInput []byte) []byte {
	mac := hmac.New(spec.newHash, secret)
	_, _ = mac.Write(signingInput)
	return mac.Sum(nil)
}

func verifySignature(algorithm Algorithm, key VerificationKey, signingInput, signature []byte) error {
	spec, err := algorithm.spec()
	if err != nil {
		return err
	}
	switch spec.family {
	case familyHMAC:
		expected := signHMAC(spec, key.value.([]byte), signingInput)
		if subtle.ConstantTimeCompare(expected, signature) != 1 {
			return ErrInvalidSignature
		}
		return nil
	case familyRSA:
		publicKey := key.value.(*rsa.PublicKey)
		if len(signature) != (publicKey.N.BitLen()+7)/8 {
			return ErrInvalidSignature
		}
		if err := rsa.VerifyPKCS1v15(publicKey, spec.hash, spec.digest(signingInput), signature); err != nil {
			return ErrInvalidSignature
		}
		return nil
	case familyRSAPSS:
		publicKey := key.value.(*rsa.PublicKey)
		if len(signature) != (publicKey.N.BitLen()+7)/8 {
			return ErrInvalidSignature
		}
		if err := rsa.VerifyPSS(publicKey, spec.hash, spec.digest(signingInput), signature,
			&rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash, Hash: spec.hash}); err != nil {
			return ErrInvalidSignature
		}
		return nil
	case familyECDSA:
		publicKey := key.value.(*ecdsa.PublicKey)
		width := (publicKey.Params().BitSize + 7) / 8
		if len(signature) != 2*width {
			return ErrInvalidSignature
		}
		r := new(big.Int).SetBytes(signature[:width])
		s := new(big.Int).SetBytes(signature[width:])
		if r.Sign() <= 0 || s.Sign() <= 0 || r.Cmp(publicKey.Params().N) >= 0 || s.Cmp(publicKey.Params().N) >= 0 {
			return ErrInvalidSignature
		}
		if !ecdsa.Verify(publicKey, spec.digest(signingInput), r, s) {
			return ErrInvalidSignature
		}
		return nil
	case familyEd25519:
		publicKey := key.value.(ed25519.PublicKey)
		if len(signature) != ed25519.SignatureSize || !ed25519.Verify(publicKey, signingInput, signature) {
			return ErrInvalidSignature
		}
		return nil
	default:
		return ErrInvalidAlgorithm
	}
}
