package main

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"log"
	"time"

	gojwt "github.com/golang-jwt/jwt/v5"
	"github.com/mkbeh/xjose/jwt"
)

const (
	issuer        = "https://auth.example.com"
	audience      = "example-api"
	keyID         = "rsa-2026-07"
	tokenType     = "access+jwt"
	tokenLifetime = 15 * time.Minute
	rsaKeyBits    = 2048
)

type AccessClaims struct {
	Permissions []string `json:"permissions"`

	gojwt.RegisteredClaims
}

func main() {
	ctx := context.Background()

	// The issuer keeps the private key; verifiers receive only the public key.
	privateKey, err := rsa.GenerateKey(rand.Reader, rsaKeyBits)
	if err != nil {
		log.Fatalf("generate RSA key: %v", err)
	}

	signingKey, err := jwt.NewSigningKey(
		keyID,
		gojwt.SigningMethodPS256,
		privateKey,
	)
	if err != nil {
		log.Fatalf("create signing key: %v", err)
	}

	signer, err := jwt.NewSigner(
		signingKey,
		jwt.WithType(tokenType),
	)
	if err != nil {
		log.Fatalf("create signer: %v", err)
	}

	// Issue a short-lived access token with typed custom claims.
	now := time.Now().UTC()
	claims := &AccessClaims{
		Permissions: []string{
			"orders:read",
			"orders:write",
		},
		RegisteredClaims: gojwt.RegisteredClaims{
			Issuer:    issuer,
			Subject:   "service-123",
			Audience:  gojwt.ClaimStrings{audience},
			ExpiresAt: gojwt.NewNumericDate(now.Add(tokenLifetime)),
			IssuedAt:  gojwt.NewNumericDate(now),
			ID:        "token-456",
		},
	}

	rawToken, err := signer.Sign(ctx, claims)
	if err != nil {
		log.Fatalf("sign token: %v", err)
	}

	// Build a verifier from public key material only.
	verificationKey, err := jwt.NewVerificationKey(
		keyID,
		gojwt.SigningMethodPS256,
		&privateKey.PublicKey,
	)
	if err != nil {
		log.Fatalf("create verification key: %v", err)
	}

	keySet, err := jwt.NewStaticKeySet(verificationKey)
	if err != nil {
		log.Fatalf("create verification key set: %v", err)
	}

	verifier, err := jwt.NewVerifier(
		keySet,
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

	verifiedClaims := new(AccessClaims)
	header, err := verifier.VerifyToken(
		ctx,
		rawToken,
		verifiedClaims,
	)
	if err != nil {
		log.Fatalf("verify token: %v", err)
	}

	fmt.Printf("token: %s\n", rawToken)
	fmt.Printf("algorithm: %s\n", header.Algorithm)
	fmt.Printf("key ID: %s\n", header.KeyID)
	fmt.Printf("subject: %s\n", verifiedClaims.Subject)
	fmt.Printf(
		"permissions: %v\n",
		verifiedClaims.Permissions,
	)
}
