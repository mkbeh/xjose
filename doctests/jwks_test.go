package doctests_test

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	gojwt "github.com/golang-jwt/jwt/v5"
	"github.com/mkbeh/xjose/jwks"
	"github.com/mkbeh/xjose/jwt"
)

type jwksAccessClaims struct {
	Role string `json:"role"`
	gojwt.RegisteredClaims
}

func Example_jwksJWTResolver() {
	ctx := context.Background()
	now := testTime()
	_, privateKey := testEd25519Key(0x32)

	signingKey := must(jwt.NewSigningKey(
		"signing-key",
		gojwt.SigningMethodEdDSA,
		privateKey,
	))

	verificationKeys := must(jwt.NewStaticKeySet(
		signingKey.VerificationKey(),
	))
	published := must(jwks.FromStaticKeySet(verificationKeys))
	data := must(json.Marshal(published))
	parsed := must(jwks.Parse(data))

	signer := must(jwt.NewSigner(
		signingKey,
		jwt.WithType("access+jwt"),
	))

	raw := must(signer.Sign(ctx, &jwksAccessClaims{
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

	claims := new(jwksAccessClaims)
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
