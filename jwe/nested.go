package jwe

import (
	"context"
	"fmt"

	"github.com/golang-jwt/jwt/v5"
	"github.com/mkbeh/xjwt"
)

const nestedJWTContentType = "JWT"

// NestedIssuer signs a JWT and encrypts the resulting compact token as JWE.
type NestedIssuer struct {
	signer    *xjwt.Signer
	encrypter *Encrypter
}

// NewNestedIssuer creates a sign-then-encrypt JWT issuer.
//
// The encrypter must be configured with cty=JWT.
func NewNestedIssuer(
	signer *xjwt.Signer,
	encrypter *Encrypter,
) (*NestedIssuer, error) {
	if signer == nil {
		return nil, fmt.Errorf(
			"%w: signer is required",
			ErrInvalidConfig,
		)
	}

	if encrypter == nil {
		return nil, fmt.Errorf(
			"%w: encrypter is required",
			ErrInvalidConfig,
		)
	}

	if encrypter.config.cty != nestedJWTContentType {
		return nil, fmt.Errorf(
			"%w: encrypter content type must be %q",
			ErrInvalidConfig,
			nestedJWTContentType,
		)
	}

	return &NestedIssuer{
		signer:    signer,
		encrypter: encrypter,
	}, nil
}

// Issue signs claims as a compact JWT and encrypts it as a nested compact JWE.
func (issuer *NestedIssuer) Issue(ctx context.Context, claims jwt.Claims) (string, error) {
	if issuer == nil ||
		issuer.signer == nil ||
		issuer.encrypter == nil {
		return "", fmt.Errorf(
			"%w: nested issuer is uninitialized",
			ErrInvalidConfig,
		)
	}

	signedJWT, err := issuer.signer.Sign(ctx, claims)
	if err != nil {
		return "", fmt.Errorf(
			"sign nested JWT: %w",
			err,
		)
	}

	encryptedJWT, err := issuer.encrypter.Encrypt([]byte(signedJWT))
	if err != nil {
		return "", fmt.Errorf(
			"encrypt nested JWT: %w",
			err,
		)
	}

	return encryptedJWT, nil
}

// VerifiedToken contains authenticated outer JWE and inner JWT headers.
//
// Claims are decoded into the value passed to NestedVerifier.VerifyToken.
type VerifiedToken struct {
	JWEHeader Header
	JWTHeader xjwt.Header
}

// NestedVerifier decrypts an outer JWE and verifies the nested signed JWT.
type NestedVerifier struct {
	decrypter *Decrypter
	verifier  *xjwt.Verifier
}

// NewNestedVerifier creates a decrypt-then-verify nested JWT verifier.
func NewNestedVerifier(
	decrypter *Decrypter,
	verifier *xjwt.Verifier,
) (*NestedVerifier, error) {
	if decrypter == nil {
		return nil, fmt.Errorf(
			"%w: decrypter is required",
			ErrInvalidConfig,
		)
	}

	if verifier == nil {
		return nil, fmt.Errorf(
			"%w: JWT verifier is required",
			ErrInvalidConfig,
		)
	}

	if decrypter.config.cty != "" &&
		decrypter.config.cty != nestedJWTContentType {
		return nil, fmt.Errorf(
			"%w: decrypter content type must be %q",
			ErrInvalidConfig,
			nestedJWTContentType,
		)
	}

	return &NestedVerifier{
		decrypter: decrypter,
		verifier:  verifier,
	}, nil
}

// Verify decrypts and verifies a nested JWT.
func (verifier *NestedVerifier) Verify(
	ctx context.Context,
	raw string,
	claims jwt.Claims,
) error {
	_, err := verifier.VerifyToken(ctx, raw, claims)
	return err
}

// VerifyToken decrypts an outer compact JWE, requires cty=JWT, and verifies
// the nested compact JWT.
func (verifier *NestedVerifier) VerifyToken(
	ctx context.Context,
	raw string,
	claims jwt.Claims,
) (VerifiedToken, error) {
	if verifier == nil ||
		verifier.decrypter == nil ||
		verifier.verifier == nil {
		return VerifiedToken{}, fmt.Errorf(
			"%w: nested verifier is uninitialized",
			ErrInvalidConfig,
		)
	}

	decrypted, err := verifier.decrypter.DecryptToken(ctx, raw)
	if err != nil {
		return VerifiedToken{}, fmt.Errorf(
			"decrypt nested JWT: %w",
			err,
		)
	}

	// DecryptToken returns only after successful JWE authentication, so this
	// content-type value is now trusted.
	if decrypted.Header.ContentType != nestedJWTContentType {
		return VerifiedToken{}, fmt.Errorf(
			"%w: expected %q, got %q",
			ErrUnexpectedContentType,
			nestedJWTContentType,
			decrypted.Header.ContentType,
		)
	}

	jwtHeader, err := verifier.verifier.VerifyToken(ctx, string(decrypted.Plaintext), claims)
	if err != nil {
		return VerifiedToken{}, fmt.Errorf(
			"verify nested JWT: %w",
			err,
		)
	}

	return VerifiedToken{
		JWEHeader: decrypted.Header,
		JWTHeader: jwtHeader,
	}, nil
}
