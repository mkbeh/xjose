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
	issuer        = "https://auth.example.com"
	audience      = "example-api"
	keyID         = "hmac-2026-07"
	tokenType     = "access+jwt"
	tokenLifetime = 15 * time.Minute
)

type AccessClaims struct {
	Role string `json:"role"`

	jwt.RegisteredClaims
}

func main() {
	ctx := context.Background()

	// HMAC uses the same secret to sign and verify tokens.
	secret := make([]byte, 32)
	if _, err := rand.Read(secret); err != nil {
		log.Fatalf("generate HMAC secret: %v", err)
	}

	signingKey, err := xjwt.NewSigningKey(
		keyID,
		jwt.SigningMethodHS256,
		secret,
	)
	if err != nil {
		log.Fatalf("create signing key: %v", err)
	}

	signer, err := xjwt.NewSigner(
		signingKey,
		xjwt.WithType(tokenType),
	)
	if err != nil {
		log.Fatalf("create signer: %v", err)
	}

	// Issue a short-lived access token with typed custom claims.
	now := time.Now().UTC()
	claims := &AccessClaims{
		Role: "admin",
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    issuer,
			Subject:   "user-123",
			Audience:  jwt.ClaimStrings{audience},
			ExpiresAt: jwt.NewNumericDate(now.Add(tokenLifetime)),
			IssuedAt:  jwt.NewNumericDate(now),
			ID:        "token-123",
		},
	}

	rawToken, err := signer.Sign(ctx, claims)
	if err != nil {
		log.Fatalf("sign token: %v", err)
	}

	// Verify the signature and enforce the expected token policy.
	verifier, err := xjwt.NewVerifier(
		signingKey.VerificationKey(),
		xjwt.WithMethods(jwt.SigningMethodHS256),
		xjwt.WithIssuer(issuer),
		xjwt.WithAudience(audience),
		xjwt.WithType(tokenType),
		xjwt.RequireIssuedAt(),
		xjwt.WithMaxLifetime(tokenLifetime),
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
	fmt.Printf("role: %s\n", verifiedClaims.Role)
}
