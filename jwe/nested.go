package jwe

import (
	"context"
	"fmt"

	"github.com/golang-jwt/jwt/v5"
	"github.com/mkbeh/xjwt"
)

type Issuer struct {
	signer    *xjwt.Signer
	encrypter *Encrypter
}

func NewIssuer(signer *xjwt.Signer, encrypter *Encrypter) (*Issuer, error) {
	if signer == nil || encrypter == nil {
		return nil, fmt.Errorf("%w: signer and encrypter are required", ErrInvalidConfig)
	}
	return &Issuer{signer, encrypter}, nil
}
func (i *Issuer) Issue(ctx context.Context, claims jwt.Claims) (string, error) {
	signed, err := i.signer.Sign(ctx, claims)
	if err != nil {
		return "", err
	}
	return i.encrypter.encrypt(ctx, []byte(signed), "JWT")
}

type VerifiedToken[C jwt.Claims] struct {
	JWEHeader Header
	JWT       xjwt.VerifiedToken[C]
}
type Verifier[C jwt.Claims] struct {
	decrypter *Decrypter
	verifier  *xjwt.Verifier[C]
}

func NewVerifier[C jwt.Claims](decrypter *Decrypter, verifier *xjwt.Verifier[C]) (*Verifier[C], error) {
	if decrypter == nil || verifier == nil {
		return nil, fmt.Errorf("%w: decrypter and verifier are required", ErrInvalidConfig)
	}
	return &Verifier[C]{decrypter, verifier}, nil
}
func (v *Verifier[C]) Verify(ctx context.Context, raw string) (C, error) {
	t, err := v.VerifyToken(ctx, raw)
	return t.JWT.Claims, err
}
func (v *Verifier[C]) VerifyToken(ctx context.Context, raw string) (VerifiedToken[C], error) {
	var zero VerifiedToken[C]
	d, err := v.decrypter.DecryptToken(ctx, raw)
	if err != nil {
		return zero, err
	}
	if d.Header.ContentType != "JWT" {
		return zero, ErrUnexpectedContentType
	}
	inner, err := v.verifier.VerifyToken(ctx, string(d.Plaintext))
	if err != nil {
		return zero, err
	}
	return VerifiedToken[C]{JWEHeader: d.Header, JWT: inner}, nil
}
