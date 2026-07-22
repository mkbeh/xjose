package main

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"log"

	"github.com/golang-jwt/jwt/v5"
	"github.com/mkbeh/xjwt"
	"github.com/mkbeh/xjwt/jwk"
)

func main() {
	// Generate a key pair for the example. Production verifiers normally load
	// a trusted public key or JWK from configuration or a key-management system.
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		log.Fatalf("generate RSA key: %v", err)
	}

	verificationKey, err := xjwt.NewVerificationKey(
		"rsa-2026-07",
		jwt.SigningMethodRS256,
		&privateKey.PublicKey,
	)
	if err != nil {
		log.Fatalf("create verification key: %v", err)
	}

	// Export the verification key as a public JWK.
	publicJWK, err := jwk.FromVerificationKey(verificationKey)
	if err != nil {
		log.Fatalf("export JWK: %v", err)
	}

	jwkJSON, err := json.MarshalIndent(publicJWK, "", "  ")
	if err != nil {
		log.Fatalf("marshal JWK: %v", err)
	}

	// Calculate the RFC 7638 SHA-256 thumbprint.
	thumbprint, err := jwk.ThumbprintID(publicJWK)
	if err != nil {
		log.Fatalf("calculate JWK thumbprint: %v", err)
	}

	// Parse the serialized JWK and convert it back to an xjwt verification key.
	parsedJWK, err := jwk.Parse(jwkJSON)
	if err != nil {
		log.Fatalf("parse JWK: %v", err)
	}

	parsedVerificationKey, err := jwk.ToVerificationKey(
		parsedJWK,
		jwt.SigningMethodRS256,
	)
	if err != nil {
		log.Fatalf("create verification key from JWK: %v", err)
	}

	fmt.Printf("JWK:\n%s\n", jwkJSON)
	fmt.Printf("thumbprint: %s\n", thumbprint)
	fmt.Printf("key ID: %s\n", parsedVerificationKey.ID())
	fmt.Printf(
		"algorithm: %s\n",
		parsedVerificationKey.Method().Alg(),
	)
}
