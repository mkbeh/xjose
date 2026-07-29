package doctests_test

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	gojwt "github.com/golang-jwt/jwt/v5"
	"github.com/mkbeh/xjose/jwk"
	"github.com/mkbeh/xjose/jwt"
)

type jwkSetAccessClaims struct {
	Role string `json:"role"`
	gojwt.RegisteredClaims
}

func Example_jwkSetJWTResolver() {
	ctx := context.Background()
	now := testTime()

	// Deterministic key material keeps the example reproducible.
	// Generate or load keys securely in production.
	_, privateKey := testEd25519Key(0x32)

	signingKey := must(jwt.NewSigningKey(
		"signing-key",
		gojwt.SigningMethodEdDSA,
		privateKey,
	))

	verificationKeys := must(jwt.NewStaticKeySet(
		signingKey.VerificationKey(),
	))
	published := must(jwk.FromStaticKeySet(verificationKeys))
	data := must(json.Marshal(published))
	parsed := must(jwk.ParseSet(data))

	signer := must(jwt.NewSigner(
		signingKey,
		jwt.WithType("access+jwt"),
	))

	raw := must(signer.Sign(ctx, &jwkSetAccessClaims{
		Role: "reader",
		RegisteredClaims: gojwt.RegisteredClaims{
			Issuer:    "https://auth.example.com",
			Subject:   "user-123",
			Audience:  gojwt.ClaimStrings{"orders-api"},
			ExpiresAt: gojwt.NewNumericDate(now.Add(15 * time.Minute)),
			IssuedAt:  gojwt.NewNumericDate(now),
		},
	}))

	// A validated JWKS set implements jwt.KeyResolver directly.
	verifier := must(jwt.NewVerifier(
		parsed,
		jwt.WithMethods(gojwt.SigningMethodEdDSA),
		jwt.WithIssuer("https://auth.example.com"),
		jwt.WithAudience("orders-api"),
		jwt.WithType("access+jwt"),
		jwt.RequireIssuedAt(),
		jwt.WithMaxLifetime(15*time.Minute),
		jwt.WithClock(func() time.Time { return now.Add(time.Minute) }),
	))

	claims := new(jwkSetAccessClaims)
	header := must(verifier.VerifyToken(ctx, raw, claims))

	fmt.Println(claims.Subject)
	fmt.Println(claims.Role)
	fmt.Println(header.KeyID)
	fmt.Println(len(parsed.Keys()))

	// Output:
	// user-123
	// reader
	// signing-key
	// 1
}
