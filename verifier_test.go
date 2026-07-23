package xjwt

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

func TestVerifierVerifyToken(t *testing.T) {
	signer := newHMACSigner(t, "signing-key", WithType("access+jwt"))
	verifier := newHMACVerifier(
		t,
		"signing-key",
		WithType("access+jwt"),
		WithIssuer(testIssuer),
		WithAudience(testAudience),
		WithSubject(testSubject),
		RequireIssuedAt(),
		WithMaxLifetime(10*time.Minute),
		WithMaxTokenAge(10*time.Minute),
	)

	raw, err := signer.Sign(testContext(), validTestClaims())
	requireNoError(t, err)

	claims := new(testClaims)
	header, err := verifier.VerifyToken(testContext(), raw, claims)
	requireNoError(t, err)

	if header.Algorithm != jwt.SigningMethodHS256.Alg() {
		t.Fatalf("algorithm = %q, want %q", header.Algorithm, jwt.SigningMethodHS256.Alg())
	}
	if header.KeyID != "signing-key" {
		t.Fatalf("key ID = %q, want %q", header.KeyID, "signing-key")
	}
	if header.Type != "access+jwt" {
		t.Fatalf("type = %q, want %q", header.Type, "access+jwt")
	}
	if claims.Subject != testSubject || claims.Role != "reader" {
		t.Fatalf("claims = %+v", claims)
	}
}

func TestVerifierRejectsInvalidTokens(t *testing.T) {
	validClaims := validTestClaims()
	validHeaders := map[string]any{
		headerParamKeyID: "signing-key",
		headerParamType:  "access+jwt",
	}
	validRaw := signJWT(t, jwt.SigningMethodHS256, testHMACSecret(), validClaims, validHeaders)

	expiredClaims := validTestClaims()
	expiredClaims.ExpiresAt = jwt.NewNumericDate(testNow.Add(-time.Second))

	futureClaims := validTestClaims()
	futureClaims.NotBefore = jwt.NewNumericDate(testNow.Add(time.Minute))

	missingExpiration := validTestClaims()
	missingExpiration.ExpiresAt = nil

	otherSecret := testHMACSecret()
	otherSecret[0] ^= 0xff

	tests := []struct {
		name     string
		raw      string
		verifier func(*testing.T) *Verifier
		target   error
	}{
		{
			name:     "missing token",
			raw:      "",
			verifier: strictTestVerifier,
			target:   ErrMissingToken,
		},
		{
			name:     "malformed token",
			raw:      "not-a-jwt",
			verifier: strictTestVerifier,
			target:   ErrMalformedToken,
		},
		{
			name:     "invalid signature",
			raw:      signJWT(t, jwt.SigningMethodHS256, otherSecret, validClaims, validHeaders),
			verifier: strictTestVerifier,
			target:   ErrInvalidSignature,
		},
		{
			name:     "expired token",
			raw:      signJWT(t, jwt.SigningMethodHS256, testHMACSecret(), expiredClaims, validHeaders),
			verifier: strictTestVerifier,
			target:   ErrExpiredToken,
		},
		{
			name:     "not valid yet",
			raw:      signJWT(t, jwt.SigningMethodHS256, testHMACSecret(), futureClaims, validHeaders),
			verifier: strictTestVerifier,
			target:   ErrNotYetValid,
		},
		{
			name:     "missing expiration",
			raw:      signJWT(t, jwt.SigningMethodHS256, testHMACSecret(), missingExpiration, validHeaders),
			verifier: strictTestVerifier,
			target:   ErrInvalidClaims,
		},
		{
			name: "unexpected type",
			raw: signJWT(t, jwt.SigningMethodHS256, testHMACSecret(), validClaims, map[string]any{
				headerParamKeyID: "signing-key",
				headerParamType:  "other+jwt",
			}),
			verifier: strictTestVerifier,
			target:   ErrUnexpectedType,
		},
		{
			name: "critical header",
			raw: signJWT(t, jwt.SigningMethodHS256, testHMACSecret(), validClaims, map[string]any{
				headerParamKeyID:    "signing-key",
				headerParamType:     "access+jwt",
				headerParamCritical: []string{"custom"},
			}),
			verifier: strictTestVerifier,
			target:   ErrMalformedToken,
		},
		{
			name: "unencoded payload header",
			raw: signJWT(t, jwt.SigningMethodHS256, testHMACSecret(), validClaims, map[string]any{
				headerParamKeyID:  "signing-key",
				headerParamType:   "access+jwt",
				headerParamBase64: false,
			}),
			verifier: strictTestVerifier,
			target:   ErrMalformedToken,
		},
		{
			name: "invalid issuer",
			raw: func() string {
				claims := validTestClaims()
				claims.Issuer = "https://other.example.com"
				return signJWT(t, jwt.SigningMethodHS256, testHMACSecret(), claims, validHeaders)
			}(),
			verifier: strictTestVerifier,
			target:   ErrInvalidClaims,
		},
		{
			name: "invalid audience",
			raw: func() string {
				claims := validTestClaims()
				claims.Audience = jwt.ClaimStrings{"other-api"}
				return signJWT(t, jwt.SigningMethodHS256, testHMACSecret(), claims, validHeaders)
			}(),
			verifier: strictTestVerifier,
			target:   ErrInvalidClaims,
		},
		{
			name: "invalid subject",
			raw: func() string {
				claims := validTestClaims()
				claims.Subject = "other-user"
				return signJWT(t, jwt.SigningMethodHS256, testHMACSecret(), claims, validHeaders)
			}(),
			verifier: strictTestVerifier,
			target:   ErrInvalidClaims,
		},
		{
			name: "token too large",
			raw:  validRaw,
			verifier: func(t *testing.T) *Verifier {
				return newHMACVerifier(t, "signing-key", WithMaxTokenSize(len(validRaw)-1))
			},
			target: ErrTokenTooLarge,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			claims := new(testClaims)
			err := test.verifier(t).Verify(testContext(), test.raw, claims)
			requireErrorIs(t, err, test.target)
		})
	}
}

func TestVerifierLifetimePolicies(t *testing.T) {
	tests := []struct {
		name    string
		claims  *testClaims
		options []VerifierOption
		target  error
	}{
		{
			name: "missing iat",
			claims: func() *testClaims {
				claims := validTestClaims()
				claims.IssuedAt = nil
				return claims
			}(),
			options: []VerifierOption{RequireIssuedAt()},
			target:  ErrInvalidLifetime,
		},
		{
			name: "iat in future",
			claims: func() *testClaims {
				claims := validTestClaims()
				claims.IssuedAt = jwt.NewNumericDate(testNow.Add(time.Minute))
				return claims
			}(),
			options: []VerifierOption{ValidateIssuedAt()},
			target:  ErrIssuedInFuture,
		},
		{
			name: "token too old",
			claims: func() *testClaims {
				claims := validTestClaims()
				claims.IssuedAt = jwt.NewNumericDate(testNow.Add(-20 * time.Minute))
				return claims
			}(),
			options: []VerifierOption{WithMaxTokenAge(10 * time.Minute)},
			target:  ErrInvalidLifetime,
		},
		{
			name: "lifetime too long",
			claims: func() *testClaims {
				claims := validTestClaims()
				claims.ExpiresAt = jwt.NewNumericDate(testNow.Add(30 * time.Minute))
				return claims
			}(),
			options: []VerifierOption{WithMaxLifetime(10 * time.Minute)},
			target:  ErrInvalidLifetime,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			raw := signJWT(t, jwt.SigningMethodHS256, testHMACSecret(), test.claims, map[string]any{
				headerParamKeyID: "signing-key",
			})
			verifier := newHMACVerifier(t, "signing-key", test.options...)
			err := verifier.Verify(testContext(), raw, new(testClaims))
			requireErrorIs(t, err, test.target)
		})
	}

	claimsWithoutExpiration := validTestClaims()
	claimsWithoutExpiration.ExpiresAt = nil
	raw := signJWT(t, jwt.SigningMethodHS256, testHMACSecret(), claimsWithoutExpiration, map[string]any{
		headerParamKeyID: "signing-key",
	})
	verifier := newHMACVerifier(t, "signing-key", AllowMissingExpiration())
	requireNoError(t, verifier.Verify(testContext(), raw, new(testClaims)))
}

func TestVerifierResolverContract(t *testing.T) {
	signer := newHMACSigner(t, "signing-key", WithType("access+jwt"))
	raw, err := signer.Sign(testContext(), validTestClaims())
	requireNoError(t, err)

	verificationKey, err := NewVerificationKey("signing-key", jwt.SigningMethodHS256, testHMACSecret())
	requireNoError(t, err)
	var resolvedHeader Header
	resolver := KeyResolverFunc(func(_ context.Context, header Header) (VerificationKey, error) {
		resolvedHeader = header
		return verificationKey, nil
	})
	verifier, err := NewVerifier(
		resolver,
		WithMethods(jwt.SigningMethodHS256),
		WithClock(func() time.Time { return testNow }),
		WithType("access+jwt"),
	)
	requireNoError(t, err)

	requireNoError(t, verifier.Verify(testContext(), raw, new(testClaims)))
	if resolvedHeader.KeyID != "signing-key" || resolvedHeader.Type != "access+jwt" {
		t.Fatalf("resolver header = %+v", resolvedHeader)
	}

	resolverError := errors.New("resolver unavailable")
	failedVerifier, err := NewVerifier(
		KeyResolverFunc(func(context.Context, Header) (VerificationKey, error) {
			return VerificationKey{}, resolverError
		}),
		WithMethods(jwt.SigningMethodHS256),
		WithClock(func() time.Time { return testNow }),
	)
	requireNoError(t, err)
	err = failedVerifier.Verify(testContext(), raw, new(testClaims))
	requireErrorIs(t, err, resolverError)

	uninitializedVerifier, err := NewVerifier(
		KeyResolverFunc(func(context.Context, Header) (VerificationKey, error) {
			return VerificationKey{}, nil
		}),
		WithMethods(jwt.SigningMethodHS256),
		WithClock(func() time.Time { return testNow }),
	)
	requireNoError(t, err)
	err = uninitializedVerifier.Verify(testContext(), raw, new(testClaims))
	requireErrorIs(t, err, ErrInvalidKey)
}

func TestVerifierRejectsInvalidInput(t *testing.T) {
	verifier := newHMACVerifier(t, "")
	raw := signJWT(t, jwt.SigningMethodHS256, testHMACSecret(), validTestClaims(), nil)

	var nilVerifier *Verifier
	err := nilVerifier.Verify(testContext(), raw, new(testClaims))
	requireErrorIs(t, err, ErrInvalidConfig)

	err = verifier.Verify(nil, raw, new(testClaims))
	requireErrorIs(t, err, ErrInvalidConfig)

	err = verifier.Verify(testContext(), raw, nil)
	requireErrorIs(t, err, ErrInvalidClaims)
}

func strictTestVerifier(t *testing.T) *Verifier {
	t.Helper()
	return newHMACVerifier(
		t,
		"signing-key",
		WithType("access+jwt"),
		WithIssuer(testIssuer),
		WithAudience(testAudience),
		WithSubject(testSubject),
	)
}
