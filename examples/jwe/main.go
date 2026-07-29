package main

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"log"
	"time"

	"github.com/go-jose/go-jose/v4"
	gojwt "github.com/golang-jwt/jwt/v5"
	"github.com/mkbeh/xjose/jwe"
	"github.com/mkbeh/xjose/jwt"
)

const (
	issuer        = "https://auth.example.com"
	audience      = "orders-api"
	tokenType     = "access+jwt"
	tokenLifetime = 15 * time.Minute
	rsaKeyBits    = 2048

	signingKeyID    = "signing-2026-07"
	encryptionKeyID = "encryption-2026-07"
)

type AccessClaims struct {
	UserID string   `json:"user_id"`
	Scopes []string `json:"scopes"`

	gojwt.RegisteredClaims
}

func main() {
	ctx := context.Background()

	// Create the signing and verification components for the inner JWT.
	signingPrivateKey := generateRSAKey("signing")

	signingKey, err := jwt.NewSigningKey(
		signingKeyID,
		gojwt.SigningMethodPS256,
		signingPrivateKey,
	)
	if err != nil {
		log.Fatalf("create signing key: %v", err)
	}

	signer, err := jwt.NewSigner(
		signingKey,
		jwt.WithType(tokenType),
	)
	if err != nil {
		log.Fatalf("create JWT signer: %v", err)
	}

	jwtVerifier, err := jwt.NewVerifier(
		signingKey.VerificationKey(),
		jwt.WithMethods(gojwt.SigningMethodPS256),
		jwt.WithIssuer(issuer),
		jwt.WithAudience(audience),
		jwt.WithType(tokenType),
		jwt.RequireIssuedAt(),
		jwt.WithMaxLifetime(tokenLifetime),
	)
	if err != nil {
		log.Fatalf("create JWT verifier: %v", err)
	}

	// Create separate encryption and decryption components for the outer JWE.
	encryptionPrivateKey := generateRSAKey("encryption")

	encrypter, err := jwe.NewEncrypter(
		jose.Recipient{
			Algorithm: jose.RSA_OAEP_256,
			Key:       &encryptionPrivateKey.PublicKey,
			KeyID:     encryptionKeyID,
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

	// Sign the claims, then encrypt the resulting compact JWT.
	now := time.Now().UTC()
	rawToken, err := nestedIssuer.Issue(
		ctx,
		&AccessClaims{
			UserID: "user-123",
			Scopes: []string{
				"orders:read",
				"orders:write",
			},
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
		log.Fatalf("issue nested JWT: %v", err)
	}

	// Decrypt the outer JWE, then verify the inner JWT.
	verifiedClaims := new(AccessClaims)
	verified, err := nestedVerifier.VerifyToken(
		ctx,
		rawToken,
		verifiedClaims,
	)
	if err != nil {
		log.Fatalf("verify nested JWT: %v", err)
	}

	fmt.Printf("nested JWT: %s\n\n", rawToken)
	fmt.Printf("verified user: %s\n", verifiedClaims.UserID)
	fmt.Printf("verified scopes: %v\n", verifiedClaims.Scopes)
	fmt.Printf("JWE key algorithm: %s\n", verified.JWEHeader.Algorithm)
	fmt.Printf(
		"JWE content encryption: %s\n",
		verified.JWEHeader.Encryption,
	)
	fmt.Printf("JWE key ID: %s\n", verified.JWEHeader.KeyID)
	fmt.Printf(
		"JWE content type: %s\n",
		verified.JWEHeader.ContentType,
	)
	fmt.Printf("JWT algorithm: %s\n", verified.JWTHeader.Algorithm)
	fmt.Printf("JWT key ID: %s\n", verified.JWTHeader.KeyID)
}

func generateRSAKey(name string) *rsa.PrivateKey {
	privateKey, err := rsa.GenerateKey(rand.Reader, rsaKeyBits)
	if err != nil {
		log.Fatalf("generate %s RSA key: %v", name, err)
	}

	return privateKey
}
