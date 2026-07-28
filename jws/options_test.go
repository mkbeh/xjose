package jws

import (
	"bytes"
	"context"
	"testing"

	"github.com/go-jose/go-jose/v4"
)

func TestOptionsValidation(t *testing.T) {
	secret := bytes.Repeat([]byte{0xa1}, 32)

	tests := []struct {
		name    string
		options []Option
	}{
		{name: "nil option", options: []Option{nil}},
		{name: "invalid token size", options: []Option{WithMaxTokenSize(0)}},
		{name: "invalid payload size", options: []Option{WithMaxPayloadSize(0)}},
		{name: "invalid signature count", options: []Option{WithMaxSignatures(0)}},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := NewSigner(
				SigningKey{Algorithm: jose.HS256, Key: secret},
				test.options...,
			)
			requireErrorIs(t, err, ErrInvalidConfig)
		})
	}

	_, err := NewVerifier(
		secret,
		[]jose.SignatureAlgorithm{jose.HS256},
		WithHeader("custom", "value"),
	)
	requireErrorIs(t, err, ErrInvalidConfig)

	_, err = NewSigner(
		SigningKey{Algorithm: jose.HS256, Key: secret},
		WithSignaturePolicy(RequireAnySignature()),
	)
	requireErrorIs(t, err, ErrInvalidConfig)

	var nilPolicy SignaturePolicyFunc
	_, err = NewMultiVerifier(
		secret,
		[]jose.SignatureAlgorithm{jose.HS256},
		WithSignaturePolicy(nilPolicy),
	)
	requireErrorIs(t, err, ErrInvalidConfig)
}

func TestHeaderOptionsUseLastValue(t *testing.T) {
	secret := bytes.Repeat([]byte{0xa2}, 32)

	signer, err := NewSigner(
		SigningKey{Algorithm: jose.HS256, Key: secret},
		WithType("first+jws"),
		WithHeader(jose.HeaderType, "second+jws"),
		WithHeader("custom", "first"),
		WithHeader("custom", "second"),
	)
	requireNoError(t, err)

	raw, err := signer.Sign([]byte("payload"))
	requireNoError(t, err)

	object := parseCompact(t, raw, jose.HS256)
	protected := object.Signatures[0].Protected

	if got := protected.ExtraHeaders[jose.HeaderType]; got != "second+jws" {
		t.Fatalf("typ = %#v, want %q", got, "second+jws")
	}
	if got := protected.ExtraHeaders["custom"]; got != "second" {
		t.Fatalf("custom = %#v, want %q", got, "second")
	}
}

func TestTypeAndContentTypeRoundTripWithVerifier(t *testing.T) {
	secret := bytes.Repeat([]byte{0xa4}, 32)
	signer := newHMACSigner(
		t,
		secret,
		"headers",
		WithType(testType),
		WithContentType(testContentType),
	)
	verifier := newHMACVerifier(
		t,
		secret,
		"headers",
		WithType(testType),
		WithContentType(testContentType),
	)

	raw, err := signer.Sign([]byte("payload"))
	requireNoError(t, err)
	_, err = verifier.VerifyMessage(context.Background(), raw)
	requireNoError(t, err)
}
