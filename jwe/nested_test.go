package jwe

import (
	"testing"
	"time"

	gojwt "github.com/golang-jwt/jwt/v5"
	"github.com/mkbeh/xjose/jwt"
)

type nestedTestClaims struct {
	Scope string `json:"scope"`
	gojwt.RegisteredClaims
}

func newNestedJWTSignerAndVerifier(
	t *testing.T,
	secret []byte,
) (*jwt.Signer, *jwt.Verifier) {
	t.Helper()

	key, err := jwt.NewSigningKey(
		"signing-key",
		gojwt.SigningMethodHS256,
		secret,
	)
	requireNoError(t, err)

	signer, err := jwt.NewSigner(key)
	requireNoError(t, err)
	verifier, err := jwt.NewVerifier(
		key.VerificationKey(),
		jwt.WithMethods(gojwt.SigningMethodHS256),
	)
	requireNoError(t, err)

	return signer, verifier
}

func newNestedJWEComponents(
	t *testing.T,
	key []byte,
) (*Encrypter, *Decrypter) {
	t.Helper()

	encrypter := newDirectEncrypter(
		t,
		key,
		WithType("JWE"),
		WithContentType(nestedJWTContentType),
		WithHeader("outer", "header"),
	)
	decrypter := newDirectDecrypter(
		t,
		key,
		WithType("JWE"),
		WithContentType(nestedJWTContentType),
	)

	return encrypter, decrypter
}

func TestNestedJWTSignEncryptDecryptVerify(t *testing.T) {
	jwtSigner, jwtVerifier := newNestedJWTSignerAndVerifier(t, testBytes(32, 81))
	jweEncrypter, jweDecrypter := newNestedJWEComponents(t, testBytes(32, 82))

	issuer, err := NewNestedIssuer(jwtSigner, jweEncrypter)
	requireNoError(t, err)
	verifier, err := NewNestedVerifier(jweDecrypter, jwtVerifier)
	requireNoError(t, err)

	claims := &nestedTestClaims{
		Scope: "orders:read",
		RegisteredClaims: gojwt.RegisteredClaims{
			Subject:   "user-123",
			ExpiresAt: gojwt.NewNumericDate(time.Now().Add(time.Hour)),
		},
	}
	raw, err := issuer.Issue(testContext(), claims)
	requireNoError(t, err)
	if len(compactParts(t, raw)) != 5 {
		t.Fatal("nested token is not compact JWE")
	}

	var got nestedTestClaims
	headers, err := verifier.VerifyToken(testContext(), raw, &got)
	requireNoError(t, err)
	if got.Subject != "user-123" || got.Scope != "orders:read" {
		t.Fatalf("claims = %#v", got)
	}
	if headers.JWEHeader.ContentType != nestedJWTContentType ||
		headers.JWEHeader.ExtraHeaders["outer"] != "header" {
		t.Fatalf("JWE header = %#v", headers.JWEHeader)
	}
	if headers.JWTHeader.Algorithm != gojwt.SigningMethodHS256.Alg() ||
		headers.JWTHeader.KeyID != "signing-key" ||
		headers.JWTHeader.Type != "JWT" {
		t.Fatalf("JWT header = %#v", headers.JWTHeader)
	}

	var verified nestedTestClaims
	requireNoError(t, verifier.Verify(testContext(), raw, &verified))
}

func TestNewNestedIssuerRejectsInvalidConfiguration(t *testing.T) {
	signer, _ := newNestedJWTSignerAndVerifier(t, testBytes(32, 83))
	validEncrypter, _ := newNestedJWEComponents(t, testBytes(32, 84))
	encrypterWithoutContentType := newDirectEncrypter(t, testBytes(32, 84))
	encrypterWithWrongContentType := newDirectEncrypter(
		t,
		testBytes(32, 84),
		WithContentType("application/json"),
	)

	tests := []struct {
		name      string
		signer    *jwt.Signer
		encrypter *Encrypter
	}{
		{name: "nil signer", encrypter: validEncrypter},
		{name: "nil encrypter", signer: signer},
		{name: "missing content type", signer: signer, encrypter: encrypterWithoutContentType},
		{name: "wrong content type", signer: signer, encrypter: encrypterWithWrongContentType},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := NewNestedIssuer(test.signer, test.encrypter)
			requireErrorIs(t, err, ErrInvalidConfig)
		})
	}
}

func TestNewNestedVerifierRejectsInvalidConfiguration(t *testing.T) {
	_, jwtVerifier := newNestedJWTSignerAndVerifier(t, testBytes(32, 85))
	_, validDecrypter := newNestedJWEComponents(t, testBytes(32, 86))
	wrongDecrypter := newDirectDecrypter(
		t,
		testBytes(32, 86),
		WithContentType("application/json"),
	)

	tests := []struct {
		name      string
		decrypter *Decrypter
		verifier  *jwt.Verifier
	}{
		{name: "nil decrypter", verifier: jwtVerifier},
		{name: "nil verifier", decrypter: validDecrypter},
		{name: "wrong content type", decrypter: wrongDecrypter, verifier: jwtVerifier},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := NewNestedVerifier(test.decrypter, test.verifier)
			requireErrorIs(t, err, ErrInvalidConfig)
		})
	}
}

func TestNestedIssuerAndVerifierZeroValues(t *testing.T) {
	claims := &nestedTestClaims{RegisteredClaims: gojwt.RegisteredClaims{
		ExpiresAt: gojwt.NewNumericDate(time.Now().Add(time.Hour)),
	}}

	var nilIssuer *NestedIssuer
	_, err := nilIssuer.Issue(testContext(), claims)
	requireErrorIs(t, err, ErrInvalidConfig)
	var zeroIssuer NestedIssuer
	_, err = zeroIssuer.Issue(testContext(), claims)
	requireErrorIs(t, err, ErrInvalidConfig)

	var nilVerifier *NestedVerifier
	_, err = nilVerifier.VerifyToken(testContext(), "token", &nestedTestClaims{})
	requireErrorIs(t, err, ErrInvalidConfig)
	var zeroVerifier NestedVerifier
	_, err = zeroVerifier.VerifyToken(testContext(), "token", &nestedTestClaims{})
	requireErrorIs(t, err, ErrInvalidConfig)
}

func TestNestedVerifierRequiresAuthenticatedJWTContentType(t *testing.T) {
	jwtSigner, jwtVerifier := newNestedJWTSignerAndVerifier(t, testBytes(32, 87))
	key := testBytes(32, 88)
	encrypter := newDirectEncrypter(t, key)
	decrypter := newDirectDecrypter(t, key)
	verifier, err := NewNestedVerifier(decrypter, jwtVerifier)
	requireNoError(t, err)

	claims := &nestedTestClaims{RegisteredClaims: gojwt.RegisteredClaims{
		ExpiresAt: gojwt.NewNumericDate(time.Now().Add(time.Hour)),
	}}
	signed, err := jwtSigner.Sign(testContext(), claims)
	requireNoError(t, err)
	raw, err := encrypter.Encrypt([]byte(signed))
	requireNoError(t, err)

	_, err = verifier.VerifyToken(testContext(), raw, &nestedTestClaims{})
	requireErrorIs(t, err, ErrUnexpectedContentType)
}

func TestNestedVerifierRejectsInvalidOuterAndInnerTokens(t *testing.T) {
	jwtSigner, _ := newNestedJWTSignerAndVerifier(t, testBytes(32, 89))
	_, wrongJWTVerifier := newNestedJWTSignerAndVerifier(t, testBytes(32, 90))
	jweEncrypter, jweDecrypter := newNestedJWEComponents(t, testBytes(32, 91))
	issuer, err := NewNestedIssuer(jwtSigner, jweEncrypter)
	requireNoError(t, err)
	verifier, err := NewNestedVerifier(jweDecrypter, wrongJWTVerifier)
	requireNoError(t, err)

	claims := &nestedTestClaims{RegisteredClaims: gojwt.RegisteredClaims{
		ExpiresAt: gojwt.NewNumericDate(time.Now().Add(time.Hour)),
	}}
	raw, err := issuer.Issue(testContext(), claims)
	requireNoError(t, err)

	_, err = verifier.VerifyToken(testContext(), raw, &nestedTestClaims{})
	requireErrorIs(t, err, jwt.ErrInvalidSignature)

	tampered := tamperCompactPart(t, raw, 4)
	_, err = verifier.VerifyToken(testContext(), tampered, &nestedTestClaims{})
	requireErrorIs(t, err, ErrDecrypt)
}

func TestNestedContextAndClaimsErrorsPropagate(t *testing.T) {
	jwtSigner, jwtVerifier := newNestedJWTSignerAndVerifier(t, testBytes(32, 92))
	jweEncrypter, jweDecrypter := newNestedJWEComponents(t, testBytes(32, 93))
	issuer, err := NewNestedIssuer(jwtSigner, jweEncrypter)
	requireNoError(t, err)
	verifier, err := NewNestedVerifier(jweDecrypter, jwtVerifier)
	requireNoError(t, err)

	_, err = issuer.Issue(nil, &nestedTestClaims{})
	requireErrorIs(t, err, jwt.ErrInvalidConfig)

	claims := &nestedTestClaims{RegisteredClaims: gojwt.RegisteredClaims{
		ExpiresAt: gojwt.NewNumericDate(time.Now().Add(time.Hour)),
	}}
	raw, err := issuer.Issue(testContext(), claims)
	requireNoError(t, err)
	_, err = verifier.VerifyToken(testContext(), raw, nil)
	requireErrorIs(t, err, jwt.ErrInvalidClaims)
}

func TestNestedIssuerPropagatesSigningAndEncryptionFailures(t *testing.T) {
	jwtSigner, _ := newNestedJWTSignerAndVerifier(t, testBytes(32, 94))
	jweKey := testBytes(32, 95)

	validEncrypter := newDirectEncrypter(
		t,
		jweKey,
		WithContentType(nestedJWTContentType),
	)
	issuer, err := NewNestedIssuer(jwtSigner, validEncrypter)
	requireNoError(t, err)
	_, err = issuer.Issue(testContext(), nil)
	requireErrorIs(t, err, jwt.ErrInvalidClaims)

	limitedEncrypter := newDirectEncrypter(
		t,
		jweKey,
		WithContentType(nestedJWTContentType),
		WithMaxPlaintextSize(1),
	)
	issuer, err = NewNestedIssuer(jwtSigner, limitedEncrypter)
	requireNoError(t, err)
	claims := &nestedTestClaims{RegisteredClaims: gojwt.RegisteredClaims{
		ExpiresAt: gojwt.NewNumericDate(time.Now().Add(time.Hour)),
	}}
	_, err = issuer.Issue(testContext(), claims)
	requireErrorIs(t, err, ErrPlaintextTooLarge)
}
