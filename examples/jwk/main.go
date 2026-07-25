package main

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"log"

	gojwt "github.com/golang-jwt/jwt/v5"
	"github.com/mkbeh/xjose/jwk"
	"github.com/mkbeh/xjose/jwt"
)

const (
	keyID      = "rsa-signing-2026-07"
	rsaKeyBits = 2048
)

func main() {
	// Create public verification key material for the example.
	privateKey, err := rsa.GenerateKey(rand.Reader, rsaKeyBits)
	if err != nil {
		log.Fatalf("generate RSA key: %v", err)
	}

	verificationKey, err := jwt.NewVerificationKey(
		keyID,
		gojwt.SigningMethodPS256,
		&privateKey.PublicKey,
	)
	if err != nil {
		log.Fatalf("create verification key: %v", err)
	}

	// Export the verification key as a public JWK and calculate its thumbprint.
	publicJWK, err := jwk.FromVerificationKey(verificationKey)
	if err != nil {
		log.Fatalf("export public JWK: %v", err)
	}

	thumbprint, err := jwk.ThumbprintID(publicJWK)
	if err != nil {
		log.Fatalf("calculate JWK thumbprint: %v", err)
	}

	jwkJSON, err := json.MarshalIndent(publicJWK, "", "  ")
	if err != nil {
		log.Fatalf("marshal public JWK: %v", err)
	}

	// Parse the serialized JWK and convert it back to an xjwt verification key.
	parsedJWK, err := jwk.Parse(jwkJSON)
	if err != nil {
		log.Fatalf("parse public JWK: %v", err)
	}

	parsedVerificationKey, err := jwk.ToVerificationKey(
		parsedJWK,
		gojwt.SigningMethodPS256,
	)
	if err != nil {
		log.Fatalf("convert JWK to verification key: %v", err)
	}

	fmt.Printf("JWK:\n%s\n\n", jwkJSON)
	fmt.Printf("thumbprint: %s\n", thumbprint)
	fmt.Printf("key ID: %s\n", parsedVerificationKey.ID())
	fmt.Printf(
		"algorithm: %s\n",
		parsedVerificationKey.Method().Alg(),
	)
}
