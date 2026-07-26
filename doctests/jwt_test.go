package doctests_test

import (
	"bytes"
	"context"
	"fmt"
	"time"

	gojwt "github.com/golang-jwt/jwt/v5"
	"github.com/mkbeh/xjose/jwt"
)

type jwtAccessClaims struct {
	Role string `json:"role"`
	gojwt.RegisteredClaims
}

func Example_jwtHMAC() {
	ctx := context.Background()
	now := testTime()

	// Bind trusted key material to the only accepted signing method.
	signingKey := must(jwt.NewSigningKey(
		"hmac-signing-key",
		gojwt.SigningMethodHS256,
		bytes.Repeat([]byte{0x41}, 32),
	))

	signer := must(jwt.NewSigner(
		signingKey,
		jwt.WithType("access+jwt"),
	))

	raw := must(signer.Sign(ctx, &jwtAccessClaims{
		Role: "admin",
		RegisteredClaims: gojwt.RegisteredClaims{
			Issuer:    "https://auth.example.com",
			Subject:   "user-123",
			Audience:  gojwt.ClaimStrings{"orders-api"},
			ExpiresAt: gojwt.NewNumericDate(now.Add(15 * time.Minute)),
			IssuedAt:  gojwt.NewNumericDate(now),
		},
	}))

	// Configure verification independently from the untrusted token header.
	verifier := must(jwt.NewVerifier(
		signingKey.VerificationKey(),
		jwt.WithMethods(gojwt.SigningMethodHS256),
		jwt.WithIssuer("https://auth.example.com"),
		jwt.WithAudience("orders-api"),
		jwt.WithType("access+jwt"),
		jwt.RequireIssuedAt(),
		jwt.WithMaxLifetime(15*time.Minute),
		jwt.WithClock(func() time.Time { return now.Add(time.Minute) }),
	))

	claims := new(jwtAccessClaims)
	header := must(verifier.VerifyToken(ctx, raw, claims))

	fmt.Println(claims.Subject)
	fmt.Println(claims.Role)
	fmt.Println(header.KeyID)

	// Output:
	// user-123
	// admin
	// hmac-signing-key
}
