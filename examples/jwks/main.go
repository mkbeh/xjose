package main

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"log"
	"time"

	gojwt "github.com/golang-jwt/jwt/v5"
	"github.com/mkbeh/xjose/jwks"
	"github.com/mkbeh/xjose/jwt"
)

const (
	issuer        = "https://auth.example.com"
	audience      = "orders-api"
	tokenType     = "access+jwt"
	tokenLifetime = 15 * time.Minute
	rsaKeyBits    = 2048

	previousKeyID = "rsa-signing-2026-06"
	currentKeyID  = "rsa-signing-2026-07"
)

type AccessClaims struct {
	UserID string `json:"user_id"`

	gojwt.RegisteredClaims
}

func main() {
	ctx := context.Background()

	// Keep the previous public key available while issuing with the current key.
	previousPrivateKey := generateRSAKey("previous")
	currentPrivateKey := generateRSAKey("current")

	previousVerificationKey, err := jwt.NewVerificationKey(
		previousKeyID,
		gojwt.SigningMethodPS256,
		&previousPrivateKey.PublicKey,
	)
	if err != nil {
		log.Fatalf("create previous verification key: %v", err)
	}

	currentSigningKey, err := jwt.NewSigningKey(
		currentKeyID,
		gojwt.SigningMethodPS256,
		currentPrivateKey,
	)
	if err != nil {
		log.Fatalf("create current signing key: %v", err)
	}

	verificationKeySet, err := jwt.NewStaticKeySet(
		previousVerificationKey,
		currentSigningKey.VerificationKey(),
	)
	if err != nil {
		log.Fatalf("create verification key set: %v", err)
	}

	// Export public verification keys as JWKS and parse the published document.
	publicKeySet, err := jwks.FromStaticKeySet(verificationKeySet)
	if err != nil {
		log.Fatalf("export JWKS: %v", err)
	}

	jwksJSON, err := json.MarshalIndent(publicKeySet, "", "  ")
	if err != nil {
		log.Fatalf("marshal JWKS: %v", err)
	}

	parsedKeySet, err := jwks.Parse(jwksJSON)
	if err != nil {
		log.Fatalf("parse JWKS: %v", err)
	}

	signer, err := jwt.NewSigner(
		currentSigningKey,
		jwt.WithType(tokenType),
	)
	if err != nil {
		log.Fatalf("create signer: %v", err)
	}

	verifier, err := jwt.NewVerifier(
		parsedKeySet,
		jwt.WithMethods(gojwt.SigningMethodPS256),
		jwt.WithIssuer(issuer),
		jwt.WithAudience(audience),
		jwt.WithType(tokenType),
		jwt.RequireIssuedAt(),
		jwt.WithMaxLifetime(tokenLifetime),
	)
	if err != nil {
		log.Fatalf("create verifier: %v", err)
	}

	// Issue with the current key; the verifier selects its public key by kid.
	now := time.Now().UTC()
	rawToken, err := signer.Sign(
		ctx,
		&AccessClaims{
			UserID: "user-123",
			RegisteredClaims: gojwt.RegisteredClaims{
				Issuer:    issuer,
				Subject:   "user-123",
				Audience:  gojwt.ClaimStrings{audience},
				ExpiresAt: gojwt.NewNumericDate(now.Add(tokenLifetime)),
				IssuedAt:  gojwt.NewNumericDate(now),
				ID:        "token-123",
			},
		},
	)
	if err != nil {
		log.Fatalf("sign token: %v", err)
	}

	verifiedClaims := new(AccessClaims)
	header, err := verifier.VerifyToken(
		ctx,
		rawToken,
		verifiedClaims,
	)
	if err != nil {
		log.Fatalf("verify token: %v", err)
	}

	fmt.Printf("JWKS:\n%s\n\n", jwksJSON)
	fmt.Printf("token: %s\n", rawToken)
	fmt.Printf("verified user: %s\n", verifiedClaims.UserID)
	fmt.Printf("verified key ID: %s\n", header.KeyID)
	fmt.Printf("verified algorithm: %s\n", header.Algorithm)
}

func generateRSAKey(name string) *rsa.PrivateKey {
	privateKey, err := rsa.GenerateKey(rand.Reader, rsaKeyBits)
	if err != nil {
		log.Fatalf("generate %s RSA key: %v", name, err)
	}

	return privateKey
}
