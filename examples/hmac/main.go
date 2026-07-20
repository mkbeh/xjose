package main

import (
	"context"
	"crypto/rand"
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
	Role string `json:"role"`

	jwt.RegisteredClaims
}

func main() {
	ctx := context.Background()

	// Generate a 256-bit secret. In production, load it from a secret manager.
	secret := make([]byte, 32)
	if _, err := rand.Read(secret); err != nil {
		log.Fatalf("generate HMAC secret: %v", err)
	}

	signingKey, err := xjwt.NewSigningKey(
		"hmac-2026-07",
		jwt.SigningMethodHS256,
		secret,
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
		Role: "admin",
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    issuer,
			Subject:   "user-123",
			Audience:  jwt.ClaimStrings{audience},
			ExpiresAt: jwt.NewNumericDate(now.Add(15 * time.Minute)),
			IssuedAt:  jwt.NewNumericDate(now),
			ID:        "token-123",
		},
	}

	rawToken, err := signer.Sign(ctx, claims)
	if err != nil {
		log.Fatalf("sign token: %v", err)
	}

	verifier, err := xjwt.NewVerifier(
		func() *AccessClaims {
			return new(AccessClaims)
		},
		signingKey.VerificationKey(),
		xjwt.WithMethods(jwt.SigningMethodHS256),
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
	fmt.Printf("role: %s\n", verified.Claims.Role)
}
