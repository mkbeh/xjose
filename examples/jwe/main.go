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

const (
	issuer   = "https://auth.example.com"
	audience = "orders-api"
)

type AccessClaims struct {
	UserID string   `json:"user_id"`
	Scopes []string `json:"scopes"`

	jwt.RegisteredClaims
}

func main() {
	ctx := context.Background()

	// Create the signing components for the inner JWT.
	signingPrivateKey, err := rsa.GenerateKey(
		rand.Reader,
		2048,
	)
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
		signingKey.VerificationKey(),
		xjwt.WithMethods(
			jwt.SigningMethodPS256,
		),
		xjwt.WithIssuer(issuer),
		xjwt.WithAudience(audience),
		xjwt.WithType("access+jwt"),
		xjwt.RequireIssuedAt(),
		xjwt.WithMaxLifetime(
			15*time.Minute,
		),
	)
	if err != nil {
		log.Fatalf("create JWT verifier: %v", err)
	}

	// Create separate encryption components for the outer JWE.
	encryptionPrivateKey, err := rsa.GenerateKey(
		rand.Reader,
		2048,
	)
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
		jwe.WithContentType("JWT"),
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

	nestedIssuer, err := jwe.NewNestedIssuer(
		signer,
		encrypter,
	)
	if err != nil {
		log.Fatalf("create nested JWT issuer: %v", err)
	}

	nestedVerifier, err := jwe.NewNestedVerifier(
		decrypter,
		jwtVerifier,
	)
	if err != nil {
		log.Fatalf("create nested JWT verifier: %v", err)
	}

	// Sign the claims and encrypt the resulting compact JWT.
	now := time.Now()

	token, err := nestedIssuer.Issue(
		ctx,
		&AccessClaims{
			UserID: "user-123",
			Scopes: []string{
				"orders:read",
				"orders:write",
			},
			RegisteredClaims: jwt.RegisteredClaims{
				Issuer:  issuer,
				Subject: "user-123",
				Audience: jwt.ClaimStrings{
					audience,
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
		log.Fatalf("issue nested JWT: %v", err)
	}

	// Decrypt the outer JWE and verify the inner JWT.
	claims := new(AccessClaims)

	verified, err := nestedVerifier.VerifyToken(
		ctx,
		token,
		claims,
	)
	if err != nil {
		log.Fatalf("verify nested JWT: %v", err)
	}

	fmt.Printf("nested JWT: %s\n\n", token)
	fmt.Printf("verified user: %s\n", claims.UserID)
	fmt.Printf("verified scopes: %v\n", claims.Scopes)
	fmt.Printf(
		"JWE key algorithm: %s\n",
		verified.JWEHeader.Algorithm,
	)
	fmt.Printf(
		"JWE content encryption: %s\n",
		verified.JWEHeader.Encryption,
	)
	fmt.Printf(
		"JWE key ID: %s\n",
		verified.JWEHeader.KeyID,
	)
	fmt.Printf(
		"JWE content type: %s\n",
		verified.JWEHeader.ContentType,
	)
	fmt.Printf(
		"JWT algorithm: %s\n",
		verified.JWTHeader.Algorithm,
	)
	fmt.Printf(
		"JWT key ID: %s\n",
		verified.JWTHeader.KeyID,
	)
}
