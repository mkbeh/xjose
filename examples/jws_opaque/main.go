package main

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"fmt"
	"log"

	"github.com/go-jose/go-jose/v4"
	"github.com/mkbeh/xjose/jws"
)

const (
	keyID       = "opaque-signing-2026-07"
	tokenType   = "example+jws"
	contentType = "application/json"
	rsaKeyBits  = 2048
)

// opaqueSigner simulates a signing key managed by an external service.
//
// The private key is hidden behind jose.OpaqueSigner. A production adapter
// could delegate SignPayload to KMS, Vault, an HSM, or PKCS#11.
type opaqueSigner struct {
	privateKey *rsa.PrivateKey
	publicKey  jose.JSONWebKey
}

var _ jose.OpaqueSigner = (*opaqueSigner)(nil)

func newOpaqueSigner(
	privateKey *rsa.PrivateKey,
	keyID string,
) *opaqueSigner {
	return &opaqueSigner{
		privateKey: privateKey,
		publicKey: jose.JSONWebKey{
			Key:       &privateKey.PublicKey,
			KeyID:     keyID,
			Algorithm: string(jose.PS256),
			Use:       "sig",
		},
	}
}

// Public returns the public key and current trusted key identity.
func (signer *opaqueSigner) Public() *jose.JSONWebKey {
	return &signer.publicKey
}

// Algs returns the signature algorithms supported by the signer.
func (*opaqueSigner) Algs() []jose.SignatureAlgorithm {
	return []jose.SignatureAlgorithm{
		jose.PS256,
	}
}

// SignPayload signs the JWS Signing Input produced by go-jose.
func (signer *opaqueSigner) SignPayload(
	payload []byte,
	algorithm jose.SignatureAlgorithm,
) ([]byte, error) {
	if algorithm != jose.PS256 {
		return nil, fmt.Errorf(
			"unsupported signature algorithm %q",
			algorithm,
		)
	}

	digest := sha256.Sum256(payload)

	return rsa.SignPSS(
		rand.Reader,
		signer.privateKey,
		crypto.SHA256,
		digest[:],
		&rsa.PSSOptions{
			SaltLength: rsa.PSSSaltLengthEqualsHash,
			Hash:       crypto.SHA256,
		},
	)
}

func main() {
	privateKey, err := rsa.GenerateKey(rand.Reader, rsaKeyBits)
	if err != nil {
		log.Fatalf("generate RSA key: %v", err)
	}

	opaque := newOpaqueSigner(privateKey, keyID)

	// Pass the opaque signer directly. The protected kid header is obtained
	// from opaque.Public(), so SigningKey.KeyID remains empty.
	signer, err := jws.NewSigner(
		jws.SigningKey{
			Algorithm: jose.PS256,
			Key:       opaque,
		},
		jws.WithType(tokenType),
		jws.WithContentType(contentType),
	)
	if err != nil {
		log.Fatalf("create signer: %v", err)
	}

	// Verification uses trusted public key material independently from the
	// private signing operation.
	verifier, err := jws.NewVerifier(
		opaque.Public(),
		[]jose.SignatureAlgorithm{
			jose.PS256,
		},
		jws.WithType(tokenType),
		jws.WithContentType(contentType),
	)
	if err != nil {
		log.Fatalf("create verifier: %v", err)
	}

	payload := []byte(
		`{"document_id":"document-123","status":"approved"}`,
	)

	raw, err := signer.Sign(payload)
	if err != nil {
		log.Fatalf("sign payload: %v", err)
	}

	verified, err := verifier.VerifyMessage(
		context.Background(),
		raw,
	)
	if err != nil {
		log.Fatalf("verify JWS: %v", err)
	}

	fmt.Printf("serialized: %s\n", raw)
	fmt.Printf("verified payload: %s\n", verified.Payload)
	fmt.Printf("verified key ID: %s\n", verified.KeyID)
	fmt.Printf("algorithm: %s\n", verified.Header.Algorithm)
}
