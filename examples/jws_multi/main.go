package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"log"

	"github.com/go-jose/go-jose/v4"
	"github.com/mkbeh/xjose/jws"
)

const (
	issuerKeyID   = "issuer-signing-2026-07"
	approvalKeyID = "approval-signing-2026-07"
	tokenType     = "example+jws"
	contentType   = "application/json"
)

type trustedVerificationKey struct {
	algorithm jose.SignatureAlgorithm
	key       any
}

type verificationKeyResolver map[string]trustedVerificationKey

func (resolver verificationKeyResolver) Resolve(
	ctx context.Context,
	header jws.Header,
) (jws.ResolvedKey, error) {
	if err := ctx.Err(); err != nil {
		return jws.ResolvedKey{}, err
	}

	trusted, exists := resolver[header.KeyID]
	if !exists || trusted.algorithm != header.Algorithm {
		return jws.ResolvedKey{}, fmt.Errorf(
			"%w: key ID %q",
			jws.ErrKeyNotFound,
			header.KeyID,
		)
	}

	return jws.ResolvedKey{
		KeyID: header.KeyID,
		Key:   trusted.key,
	}, nil
}

func main() {
	if err := run(); err != nil {
		log.Fatal(err)
	}
}

func run() error {
	issuerPrivateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return fmt.Errorf("generate issuer RSA key: %w", err)
	}

	approvalPublicKey, approvalPrivateKey, err :=
		ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return fmt.Errorf("generate approval Ed25519 key: %w", err)
	}

	// Sign the same payload independently as the issuer and approver.
	signer, err := jws.NewMultiSigner(
		[]jws.SigningKey{
			{
				Algorithm: jose.PS256,
				KeyID:     issuerKeyID,
				Key:       issuerPrivateKey,
			},
			{
				Algorithm: jose.EdDSA,
				KeyID:     approvalKeyID,
				Key:       approvalPrivateKey,
			},
		},
		jws.WithType(tokenType),
		jws.WithContentType(contentType),
	)
	if err != nil {
		return fmt.Errorf("create multi-signer: %w", err)
	}

	resolver := verificationKeyResolver{
		issuerKeyID: {
			algorithm: jose.PS256,
			key:       &issuerPrivateKey.PublicKey,
		},
		approvalKeyID: {
			algorithm: jose.EdDSA,
			key:       approvalPublicKey,
		},
	}

	// Accept the JWS only when both trusted signer identities are verified.
	verifier, err := jws.NewMultiVerifierWithResolver(
		resolver,
		[]jose.SignatureAlgorithm{
			jose.PS256,
			jose.EdDSA,
		},
		jws.WithType(tokenType),
		jws.WithContentType(contentType),
		jws.WithSignaturePolicy(
			jws.RequireKeyIDs(
				issuerKeyID,
				approvalKeyID,
			),
		),
	)
	if err != nil {
		return fmt.Errorf("create multi-verifier: %w", err)
	}

	payload := []byte(
		`{"document_id":"document-123","operation":"approve"}`,
	)

	raw, err := signer.Sign(payload)
	if err != nil {
		return fmt.Errorf("sign JWS: %w", err)
	}

	verified, err := verifier.VerifyMessage(
		context.Background(),
		raw,
	)
	if err != nil {
		return fmt.Errorf("verify JWS: %w", err)
	}

	fmt.Println("General JWS JSON")
	fmt.Printf("serialized:\n%s\n", formatJSON(raw))
	fmt.Printf("verified payload: %s\n", verified.Payload)
	fmt.Printf(
		"verified signatures: %d\n",
		len(verified.Signatures),
	)

	for _, signature := range verified.Signatures {
		if !signature.Valid() {
			continue
		}

		fmt.Printf(
			"signature %d: %s (%s)\n",
			signature.Index,
			signature.KeyID,
			signature.Header.Algorithm,
		)
	}

	fmt.Println("policy: required key IDs satisfied")

	return nil
}

func formatJSON(raw string) string {
	var formatted bytes.Buffer
	if err := json.Indent(
		&formatted,
		[]byte(raw),
		"",
		"  ",
	); err != nil {
		return raw
	}

	return formatted.String()
}
