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

	// Generate two key pairs to demonstrate verification-key rotation.
	oldPrivateKey, err := rsa.GenerateKey(
		rand.Reader,
		2048,
	)
	if err != nil {
		log.Fatalf("generate old RSA key: %v", err)
	}

	currentPrivateKey, err := rsa.GenerateKey(
		rand.Reader,
		2048,
	)
	if err != nil {
		log.Fatalf("generate current RSA key: %v", err)
	}

	oldVerificationKey, err := xjwt.NewVerificationKey(
		"rsa-2026-06",
		jwt.SigningMethodRS256,
		&oldPrivateKey.PublicKey,
	)
	if err != nil {
		log.Fatalf(
			"create old verification key: %v",
			err,
		)
	}

	currentSigningKey, err := xjwt.NewSigningKey(
		"rsa-2026-07",
		jwt.SigningMethodRS256,
		currentPrivateKey,
	)
	if err != nil {
		log.Fatalf(
			"create current signing key: %v",
			err,
		)
	}

	verificationKeySet, err := xjwt.NewStaticKeySet(
		oldVerificationKey,
		currentSigningKey.VerificationKey(),
	)
	if err != nil {
		log.Fatalf(
			"create verification key set: %v",
			err,
		)
	}

	// Export both public verification keys as a JWKS document.
	publicKeySet, err := jwks.FromStaticKeySet(
		verificationKeySet,
	)
	if err != nil {
		log.Fatalf("export JWKS: %v", err)
	}

	jwksJSON, err := json.MarshalIndent(
		publicKeySet,
		"",
		"  ",
	)
	if err != nil {
		log.Fatalf("marshal JWKS: %v", err)
	}

	// Parse a JWKS document received from a trusted source. Parsing only loads
	// the published public keys; the verifier defines the allowed algorithms.
	parsedKeySet, err := jwks.Parse(jwksJSON)
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
		parsedKeySet,
		xjwt.WithMethods(
			jwt.SigningMethodRS256,
		),
		xjwt.WithIssuer(
			"https://auth.example.com",
		),
		xjwt.WithAudience("orders-api"),
		xjwt.WithType("access+jwt"),
		xjwt.RequireIssuedAt(),
	)
	if err != nil {
		log.Fatalf("create verifier: %v", err)
	}

	now := time.Now()

	token, err := signer.Sign(
		ctx,
		&AccessClaims{
			UserID: "user-123",
			RegisteredClaims: jwt.RegisteredClaims{
				Issuer:  "https://auth.example.com",
				Subject: "user-123",
				Audience: jwt.ClaimStrings{
					"orders-api",
				},
				ExpiresAt: jwt.NewNumericDate(
					now.Add(15 * time.Minute),
				),
				IssuedAt: jwt.NewNumericDate(now),
				ID:       "token-123",
			},
		},
	)
	if err != nil {
		log.Fatalf("sign JWT: %v", err)
	}

	claims := new(AccessClaims)

	header, err := verifier.VerifyToken(
		ctx,
		token,
		claims,
	)
	if err != nil {
		log.Fatalf("verify JWT: %v", err)
	}

	fmt.Printf("JWKS:\n%s\n\n", jwksJSON)
	fmt.Printf("verified user: %s\n", claims.UserID)
	fmt.Printf("verified key ID: %s\n", header.KeyID)
	fmt.Printf(
		"verified algorithm: %s\n",
		header.Algorithm,
	)
}
