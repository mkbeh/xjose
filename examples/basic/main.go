package main

import (
	"context"
	"fmt"
	"log"
	"time"

	jwtv5 "github.com/golang-jwt/jwt/v5"
	"github.com/mkbeh/xjwt"
)

type accessClaims struct {
	UserID string `json:"user_id"`
	jwtv5.RegisteredClaims
}

func main() {
	key, err := xjwt.NewHMACSigningKey(
		"2026-07",
		xjwt.HS256,
		[]byte("0123456789abcdef0123456789abcdef"),
	)
	if err != nil {
		log.Fatal(err)
	}

	signer, err := xjwt.NewSigner(key, xjwt.WithType("access+jwt"))
	if err != nil {
		log.Fatal(err)
	}

	now := time.Now()
	compact, err := signer.Sign(context.Background(), &accessClaims{
		UserID: "user-123",
		RegisteredClaims: jwtv5.RegisteredClaims{
			Issuer:    "https://auth.example.com",
			Audience:  jwtv5.ClaimStrings{"orders-api"},
			ExpiresAt: jwtv5.NewNumericDate(now.Add(15 * time.Minute)),
		},
	})
	if err != nil {
		log.Fatal(err)
	}

	verifier, err := xjwt.NewVerifier(
		func() *accessClaims { return new(accessClaims) },
		key.VerificationKey(),
		xjwt.WithAlgorithms(xjwt.HS256),
		xjwt.WithType("access+jwt"),
		xjwt.WithIssuer("https://auth.example.com"),
		xjwt.WithAudience("orders-api"),
	)
	if err != nil {
		log.Fatal(err)
	}

	claims, err := verifier.Verify(context.Background(), compact)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println(claims.UserID)
}
