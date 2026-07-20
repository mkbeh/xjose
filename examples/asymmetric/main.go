package main

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"log"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/mkbeh/xjwt"
)

const (
	issuer   = "https://auth.example.com"
	audience = "example-api"
)

type AccessClaims struct {
	Permissions []string `json:"permissions"`

	jwt.RegisteredClaims
}

func main() {
	ctx := context.Background()

	// The issuing service keeps the private key; verifiers need only the public key.
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		log.Fatalf("generate RSA key: %v", err)
	}

	signingKey, err := xjwt.NewSigningKey(
		"rsa-2026-07",
		jwt.SigningMethodPS256,
		privateKey,
	)
	if err != nil {
		log.Fatalf("create signing key: %v", err)
	}

	signer, err := xjwt.NewSigner(
		signingKey,
		xjwt.WithType("access+jwt"),
	)
	if err != nil {
		log.Fatalf("create signer: %v", err)
	}

	now := time.Now()
	claims := &AccessClaims{
		Permissions: []string{"orders:read", "orders:write"},
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    issuer,
			Subject:   "service-123",
			Audience:  jwt.ClaimStrings{audience},
			ExpiresAt: jwt.NewNumericDate(now.Add(15 * time.Minute)),
			IssuedAt:  jwt.NewNumericDate(now),
			ID:        "token-456",
		},
	}

	rawToken, err := signer.Sign(ctx, claims)
	if err != nil {
		log.Fatalf("sign token: %v", err)
	}

	verificationKey, err := xjwt.NewVerificationKey(
		"rsa-2026-07",
		jwt.SigningMethodPS256,
		&privateKey.PublicKey,
	)
	if err != nil {
		log.Fatalf("create verification key: %v", err)
	}

	keySet, err := xjwt.NewStaticKeySet(verificationKey)
	if err != nil {
		log.Fatalf("create key set: %v", err)
	}

	verifier, err := xjwt.NewVerifier(
		func() *AccessClaims {
			return new(AccessClaims)
		},
		keySet,
		xjwt.WithMethods(jwt.SigningMethodPS256),
		xjwt.WithIssuer(issuer),
		xjwt.WithAudience(audience),
		xjwt.WithType("access+jwt"),
		xjwt.RequireIssuedAt(),
		xjwt.WithMaxLifetime(15*time.Minute),
	)
	if err != nil {
		log.Fatalf("create verifier: %v", err)
	}

	verified, err := verifier.VerifyToken(ctx, rawToken)
	if err != nil {
		log.Fatalf("verify token: %v", err)
	}

	fmt.Printf("token: %s\n", rawToken)
	fmt.Printf("algorithm: %s\n", verified.Header.Algorithm)
	fmt.Printf("key ID: %s\n", verified.Header.KeyID)
	fmt.Printf("subject: %s\n", verified.Claims.Subject)
	fmt.Printf("permissions: %v\n", verified.Claims.Permissions)
}
