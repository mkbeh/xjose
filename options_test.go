package xjwt

import (
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

func TestSignerOptionsRejectInvalidValues(t *testing.T) {
	key, err := NewSigningKey("", jwt.SigningMethodHS256, testHMACSecret())
	requireNoError(t, err)

	var nilOption SignerOption
	tests := []struct {
		name   string
		option SignerOption
	}{
		{name: "nil option", option: nilOption},
		{name: "empty type", option: WithType("")},
		{name: "invalid max token size", option: WithMaxTokenSize(0)},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := NewSigner(key, test.option)
			requireErrorIs(t, err, ErrInvalidConfig)
		})
	}
}

func TestVerifierOptionsRejectInvalidValues(t *testing.T) {
	key, err := NewVerificationKey("", jwt.SigningMethodHS256, testHMACSecret())
	requireNoError(t, err)

	var nilOption VerifierOption
	tests := []struct {
		name    string
		options []VerifierOption
	}{
		{name: "nil option", options: []VerifierOption{nilOption}},
		{name: "empty methods", options: []VerifierOption{WithMethods()}},
		{name: "nil method", options: []VerifierOption{WithMethods(nil)}},
		{name: "duplicate method", options: []VerifierOption{WithMethods(jwt.SigningMethodHS256, jwt.SigningMethodHS256)}},
		{name: "empty type", options: []VerifierOption{WithMethods(jwt.SigningMethodHS256), WithType("")}},
		{name: "invalid max token size", options: []VerifierOption{WithMethods(jwt.SigningMethodHS256), WithMaxTokenSize(0)}},
		{name: "empty issuer", options: []VerifierOption{WithMethods(jwt.SigningMethodHS256), WithIssuer("")}},
		{name: "empty audience", options: []VerifierOption{WithMethods(jwt.SigningMethodHS256), WithAudience()}},
		{name: "duplicate audience", options: []VerifierOption{WithMethods(jwt.SigningMethodHS256), WithAudience("api", "api")}},
		{name: "empty subject", options: []VerifierOption{WithMethods(jwt.SigningMethodHS256), WithSubject("")}},
		{name: "negative leeway", options: []VerifierOption{WithMethods(jwt.SigningMethodHS256), WithLeeway(-time.Second)}},
		{name: "nil clock", options: []VerifierOption{WithMethods(jwt.SigningMethodHS256), WithClock(nil)}},
		{name: "invalid max lifetime", options: []VerifierOption{WithMethods(jwt.SigningMethodHS256), WithMaxLifetime(0)}},
		{name: "invalid max token age", options: []VerifierOption{WithMethods(jwt.SigningMethodHS256), WithMaxTokenAge(0)}},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := NewVerifier(key, test.options...)
			requireErrorIs(t, err, ErrInvalidConfig)
		})
	}

	_, err = NewVerifier(nil, WithMethods(jwt.SigningMethodHS256))
	requireErrorIs(t, err, ErrInvalidConfig)

	_, err = NewVerifier(key)
	requireErrorIs(t, err, ErrInvalidConfig)
}

func TestAudienceModes(t *testing.T) {
	raw := signJWT(t, jwt.SigningMethodHS256, testHMACSecret(), validTestClaims(), nil)

	anyAudience := newHMACVerifier(
		t,
		"",
		WithAudience(testAudience, "admin-api"),
	)
	requireNoError(t, anyAudience.Verify(testContext(), raw, new(testClaims)))

	allAudiences := newHMACVerifier(
		t,
		"",
		WithAllAudiences(testAudience, "admin-api"),
	)
	err := allAudiences.Verify(testContext(), raw, new(testClaims))
	requireErrorIs(t, err, ErrInvalidClaims)
}

func TestRequireNotBefore(t *testing.T) {
	claims := validTestClaims()
	claims.NotBefore = nil
	raw := signJWT(t, jwt.SigningMethodHS256, testHMACSecret(), claims, nil)

	verifier := newHMACVerifier(t, "", RequireNotBefore())
	err := verifier.Verify(testContext(), raw, new(testClaims))
	requireErrorIs(t, err, ErrInvalidClaims)
}
