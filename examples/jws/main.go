package main

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"log"

	"github.com/go-jose/go-jose/v4"
	"github.com/mkbeh/xjose/jws"
)

const (
	keyID       = "signing-2026-07"
	tokenType   = "example+jws"
	contentType = "application/json"
)

func main() {
	if err := run(); err != nil {
		log.Fatal(err)
	}
}

func run() error {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return fmt.Errorf("generate RSA key: %w", err)
	}

	signer, err := jws.NewSigner(
		jws.SigningKey{
			Algorithm: jose.PS256,
			KeyID:     keyID,
			Key:       privateKey,
		},
		jws.WithType(tokenType),
		jws.WithContentType(contentType),
	)
	if err != nil {
		return fmt.Errorf("create signer: %w", err)
	}

	verificationKey := jose.JSONWebKey{
		Key:       &privateKey.PublicKey,
		KeyID:     keyID,
		Algorithm: string(jose.PS256),
		Use:       "sig",
	}

	verifier, err := jws.NewVerifier(
		verificationKey,
		[]jose.SignatureAlgorithm{
			jose.PS256,
		},
		jws.WithType(tokenType),
		jws.WithContentType(contentType),
	)
	if err != nil {
		return fmt.Errorf("create verifier: %w", err)
	}

	ctx := context.Background()

	if err := runCompact(ctx, signer, verifier); err != nil {
		return err
	}
	if err := runDetached(ctx, signer, verifier); err != nil {
		return err
	}

	return nil
}

func runCompact(
	ctx context.Context,
	signer *jws.Signer,
	verifier *jws.Verifier,
) error {
	payload := []byte(
		`{"document_id":"document-123","status":"approved"}`,
	)

	raw, err := signer.Sign(payload)
	if err != nil {
		return fmt.Errorf("sign compact JWS: %w", err)
	}

	verified, err := verifier.VerifyMessage(ctx, raw)
	if err != nil {
		return fmt.Errorf("verify compact JWS: %w", err)
	}

	fmt.Println("Compact JWS")
	fmt.Printf("serialized: %s\n", raw)
	printVerified(verified)

	return nil
}

func runDetached(
	ctx context.Context,
	signer *jws.Signer,
	verifier *jws.Verifier,
) error {
	documentBytes := []byte(
		`{"document_id":"document-456","status":"pending"}`,
	)

	raw, err := signer.SignDetached(documentBytes)
	if err != nil {
		return fmt.Errorf("sign detached JWS: %w", err)
	}

	verified, err := verifier.VerifyDetached(
		ctx,
		raw,
		documentBytes,
	)
	if err != nil {
		return fmt.Errorf("verify detached JWS: %w", err)
	}

	fmt.Println()
	fmt.Println("Detached JWS")
	fmt.Printf("serialized: %s\n", raw)
	printVerified(verified)

	return nil
}

func printVerified(verified jws.Verified) {
	fmt.Printf("verified payload: %s\n", verified.Payload)
	fmt.Printf("verified key ID: %s\n", verified.KeyID)
	fmt.Printf("protected algorithm: %s\n", verified.Header.Algorithm)
	fmt.Printf("protected type: %s\n", verified.Header.Type)
	fmt.Printf(
		"protected content type: %s\n",
		verified.Header.ContentType,
	)
}
