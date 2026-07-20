package main

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"log"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/mkbeh/xjwt"
	"github.com/mkbeh/xjwt/jwks"
)

type AccessClaims struct {
	UserID string `json:"user_id"`

	jwt.RegisteredClaims
}

func main() {
	ctx := context.Background()

	// Generate an old and a current RSA key to demonstrate verification-key
	// rotation through one JWKS document.
	oldPrivateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		log.Fatalf("generate old RSA key: %v", err)
	}

	currentPrivateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		log.Fatalf("generate current RSA key: %v", err)
	}

	oldVerificationKey, err := xjwt.NewVerificationKey(
		"rsa-2026-06",
		jwt.SigningMethodRS256,
		&oldPrivateKey.PublicKey,
	)
	if err != nil {
		log.Fatalf("create old verification key: %v", err)
	}

	currentSigningKey, err := xjwt.NewSigningKey(
		"rsa-2026-07",
		jwt.SigningMethodRS256,
		currentPrivateKey,
	)
	if err != nil {
		log.Fatalf("create current signing key: %v", err)
	}

	verificationKeys, err := xjwt.NewStaticKeySet(
		oldVerificationKey,
		currentSigningKey.VerificationKey(),
	)
	if err != nil {
		log.Fatalf("create verification key set: %v", err)
	}

	// Export the public verification keys as a JWKS document.
	publicKeySet, err := jwks.FromStaticKeySet(verificationKeys)
	if err != nil {
		log.Fatalf("export JWKS: %v", err)
	}

	document, err := json.MarshalIndent(publicKeySet, "", "  ")
	if err != nil {
		log.Fatalf("marshal JWKS: %v", err)
	}

	// Parse the document received from a trusted configuration source. The
	// parsed set implements xjwt.KeyResolver and performs lookup by kid + alg.
	parsedKeySet, err := jwks.Parse(
		document,
		jwt.SigningMethodRS256,
	)
	if err != nil {
		log.Fatalf("parse JWKS: %v", err)
	}

	signer, err := xjwt.NewSigner(
		currentSigningKey,
		xjwt.WithType("access+jwt"),
	)
	if err != nil {
		log.Fatalf("create signer: %v", err)
	}

	verifier, err := xjwt.NewVerifier(
		func() *AccessClaims {
			return new(AccessClaims)
		},
		parsedKeySet,
		xjwt.WithMethods(jwt.SigningMethodRS256),
		xjwt.WithIssuer("https://auth.example.com"),
		xjwt.WithAudience("orders-api"),
		xjwt.WithType("access+jwt"),
		xjwt.RequireIssuedAt(),
	)
	if err != nil {
		log.Fatalf("create verifier: %v", err)
	}

	now := time.Now()

	token, err := signer.Sign(ctx, &AccessClaims{
		UserID: "user-123",
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    "https://auth.example.com",
			Subject:   "user-123",
			Audience:  jwt.ClaimStrings{"orders-api"},
			ExpiresAt: jwt.NewNumericDate(now.Add(15 * time.Minute)),
			IssuedAt:  jwt.NewNumericDate(now),
			ID:        "token-123",
		},
	})
	if err != nil {
		log.Fatalf("sign JWT: %v", err)
	}

	verified, err := verifier.VerifyToken(ctx, token)
	if err != nil {
		log.Fatalf("verify JWT: %v", err)
	}

	fmt.Printf("JWKS:\n%s\n\n", document)
	fmt.Printf("verified user: %s\n", verified.Claims.UserID)
	fmt.Printf("verified key ID: %s\n", verified.Header.KeyID)
	fmt.Printf("verified algorithm: %s\n", verified.Header.Algorithm)
}
