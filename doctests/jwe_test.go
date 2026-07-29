package doctests_test

import (
	"bytes"
	"context"
	"fmt"
	"time"

	"github.com/go-jose/go-jose/v4"
	gojwt "github.com/golang-jwt/jwt/v5"
	"github.com/mkbeh/xjose/jwe"
	"github.com/mkbeh/xjose/jwt"
)

func Example_jweCompact() {
	ctx := context.Background()

	// Deterministic key material keeps the example reproducible.
	// Generate or load keys securely in production.
	key := bytes.Repeat([]byte{0x71}, 32)

	encrypter := must(jwe.NewEncrypter(
		jose.Recipient{
			Algorithm: jose.DIRECT,
			Key:       key,
			KeyID:     "content-encryption-key",
		},
		jose.A256GCM,
		jwe.WithType("document+jwe"),
		jwe.WithContentType("text/plain"),
	))

	raw := must(encrypter.Encrypt([]byte("confidential document")))

	decrypter := must(jwe.NewDecrypter(
		key,
		[]jose.KeyAlgorithm{jose.DIRECT},
		[]jose.ContentEncryption{jose.A256GCM},
		jwe.WithType("document+jwe"),
		jwe.WithContentType("text/plain"),
	))

	decrypted := must(decrypter.DecryptToken(ctx, raw))

	fmt.Println(string(decrypted.Plaintext))
	fmt.Println(decrypted.Header.Algorithm)
	fmt.Println(decrypted.Header.Encryption)
	fmt.Println(decrypted.Header.KeyID)

	// Output:
	// confidential document
	// dir
	// A256GCM
	// content-encryption-key
}

func Example_jweMultipleRecipients() {
	ctx := context.Background()

	// Deterministic key material keeps the example reproducible.
	// Generate or load keys securely in production.
	ordersKey := bytes.Repeat([]byte{0x72}, 32)
	billingKey := bytes.Repeat([]byte{0x73}, 32)

	// Additional authenticated data is integrity-protected but not encrypted.
	authData := []byte("tenant=acme;order=order-123")

	encrypter := must(jwe.NewMultiEncrypter(
		[]jose.Recipient{
			{
				Algorithm: jose.A256KW,
				Key:       ordersKey,
				KeyID:     "orders",
			},
			{
				Algorithm: jose.A256KW,
				Key:       billingKey,
				KeyID:     "billing",
			},
		},
		jose.A256GCM,
		jwe.WithType("order+jwe"),
		jwe.WithContentType("application/json"),
	))

	raw := must(encrypter.EncryptWithAuthData(
		[]byte(`{"order_id":"order-123"}`),
		authData,
	))

	decrypter := must(jwe.NewMultiDecrypter(
		billingKey,
		[]jose.KeyAlgorithm{jose.A256KW},
		[]jose.ContentEncryption{jose.A256GCM},
		jwe.WithType("order+jwe"),
		jwe.WithContentType("application/json"),
	))

	decrypted := must(decrypter.DecryptToken(ctx, raw))

	fmt.Println(decrypted.RecipientIndex)
	fmt.Println(decrypted.Header.KeyID)
	fmt.Println(string(decrypted.Plaintext))
	fmt.Println(string(decrypted.AuthData))

	// Output:
	// 1
	// billing
	// {"order_id":"order-123"}
	// tenant=acme;order=order-123
}

type nestedAccessClaims struct {
	Scope string `json:"scope"`
	gojwt.RegisteredClaims
}

func Example_jweNestedJWT() {
	ctx := context.Background()
	now := testTime()

	// Deterministic key material keeps the example reproducible.
	// Generate or load keys securely in production.
	signingKey := must(jwt.NewSigningKey(
		"jwt-signing-key",
		gojwt.SigningMethodHS256,
		bytes.Repeat([]byte{0x74}, 32),
	))
	jwtSigner := must(jwt.NewSigner(
		signingKey,
		jwt.WithType("access+jwt"),
	))
	jwtVerifier := must(jwt.NewVerifier(
		signingKey.VerificationKey(),
		jwt.WithMethods(gojwt.SigningMethodHS256),
		jwt.WithIssuer("https://auth.example.com"),
		jwt.WithAudience("orders-api"),
		jwt.WithType("access+jwt"),
		jwt.RequireIssuedAt(),
		jwt.WithMaxLifetime(15*time.Minute),
		jwt.WithClock(func() time.Time { return now.Add(time.Minute) }),
	))

	encryptionKey := bytes.Repeat([]byte{0x75}, 32)
	encrypter := must(jwe.NewEncrypter(
		jose.Recipient{
			Algorithm: jose.DIRECT,
			Key:       encryptionKey,
			KeyID:     "jwe-encryption-key",
		},
		jose.A256GCM,
		jwe.WithType("JWE"),
		jwe.WithContentType("JWT"),
	))
	decrypter := must(jwe.NewDecrypter(
		encryptionKey,
		[]jose.KeyAlgorithm{jose.DIRECT},
		[]jose.ContentEncryption{jose.A256GCM},
		jwe.WithType("JWE"),
		jwe.WithContentType("JWT"),
	))

	issuer := must(jwe.NewNestedIssuer(jwtSigner, encrypter))
	verifier := must(jwe.NewNestedVerifier(decrypter, jwtVerifier))

	raw := must(issuer.Issue(ctx, &nestedAccessClaims{
		Scope: "orders:read",
		RegisteredClaims: gojwt.RegisteredClaims{
			Issuer:    "https://auth.example.com",
			Subject:   "user-123",
			Audience:  gojwt.ClaimStrings{"orders-api"},
			ExpiresAt: gojwt.NewNumericDate(now.Add(15 * time.Minute)),
			IssuedAt:  gojwt.NewNumericDate(now),
		},
	}))

	claims := new(nestedAccessClaims)
	verified := must(verifier.VerifyToken(ctx, raw, claims))

	fmt.Println(claims.Subject)
	fmt.Println(claims.Scope)
	fmt.Println(verified.JWTHeader.KeyID)
	fmt.Println(verified.JWEHeader.KeyID)
	fmt.Println(verified.JWEHeader.ContentType)

	// Output:
	// user-123
	// orders:read
	// jwt-signing-key
	// jwe-encryption-key
	// JWT
}
