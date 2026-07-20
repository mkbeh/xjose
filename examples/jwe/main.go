package main

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"log"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/golang-jwt/jwt/v5"
	"github.com/mkbeh/xjwt"
	"github.com/mkbeh/xjwt/jwe"
)

type AccessClaims struct {
	UserID string   `json:"user_id"`
	Scopes []string `json:"scopes"`

	jwt.RegisteredClaims
}

func main() {
	ctx := context.Background()

	// 1. Create a signing key and a verifier for the inner JWT.
	signingPrivateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		log.Fatalf("generate signing key: %v", err)
	}

	signingKey, err := xjwt.NewSigningKey(
		"signing-2026-07",
		jwt.SigningMethodPS256,
		signingPrivateKey,
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

	jwtVerifier, err := xjwt.NewVerifier(
		func() *AccessClaims {
			return new(AccessClaims)
		},
		signingKey.VerificationKey(),
		xjwt.WithMethods(jwt.SigningMethodPS256),
		xjwt.WithIssuer("https://auth.example.com"),
		xjwt.WithAudience("orders-api"),
		xjwt.WithType("access+jwt"),
		xjwt.RequireIssuedAt(),
		xjwt.WithMaxLifetime(15*time.Minute),
	)
	if err != nil {
		log.Fatalf("create JWT verifier: %v", err)
	}

	// 2. Create a separate RSA key for JWE encryption and decryption.
	encryptionPrivateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		log.Fatalf("generate encryption key: %v", err)
	}

	encrypter, err := jwe.NewEncrypter(
		jose.Recipient{
			Algorithm: jose.RSA_OAEP_256,
			Key:       &encryptionPrivateKey.PublicKey,
			KeyID:     "encryption-2026-07",
		},
		jose.A256GCM,
	)
	if err != nil {
		log.Fatalf("create JWE encrypter: %v", err)
	}

	decrypter, err := jwe.NewDecrypter(
		encryptionPrivateKey,
		[]jose.KeyAlgorithm{
			jose.RSA_OAEP_256,
		},
		[]jose.ContentEncryption{
			jose.A256GCM,
		},
	)
	if err != nil {
		log.Fatalf("create JWE decrypter: %v", err)
	}

	issuer, err := jwe.NewIssuer(signer, encrypter)
	if err != nil {
		log.Fatalf("create nested JWT issuer: %v", err)
	}

	verifier, err := jwe.NewVerifier(decrypter, jwtVerifier)
	if err != nil {
		log.Fatalf("create nested JWT verifier: %v", err)
	}

	// 3. Sign the claims and encrypt the resulting compact JWT.
	now := time.Now()

	token, err := issuer.Issue(ctx, &AccessClaims{
		UserID: "user-123",
		Scopes: []string{
			"orders:read",
			"orders:write",
		},
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
		log.Fatalf("issue encrypted JWT: %v", err)
	}

	// 4. Decrypt the JWE, verify the inner JWT signature and validate its claims.
	verified, err := verifier.VerifyToken(ctx, token)
	if err != nil {
		log.Fatalf("verify encrypted JWT: %v", err)
	}

	fmt.Printf("encrypted JWT: %s\n\n", token)
	fmt.Printf("verified user: %s\n", verified.JWT.Claims.UserID)
	fmt.Printf("verified scopes: %v\n", verified.JWT.Claims.Scopes)
	fmt.Printf("JWE algorithm: %s\n", verified.JWEHeader.Algorithm)
	fmt.Printf("JWE key ID: %s\n", verified.JWEHeader.KeyID)
	fmt.Printf("JWT algorithm: %s\n", verified.JWT.Header.Algorithm)
	fmt.Printf("JWT key ID: %s\n", verified.JWT.Header.KeyID)
}
