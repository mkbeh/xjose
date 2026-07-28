package jws

import (
	"errors"
	"strings"
	"testing"

	jose "github.com/go-jose/go-jose/v4"
)

func TestProtectedHeaderParsing(t *testing.T) {
	header := jose.Header{
		Algorithm: string(jose.PS256),
		KeyID:     "key-1",
		Nonce:     "nonce-1",
		ExtraHeaders: map[jose.HeaderKey]any{
			jose.HeaderType:        "example+jws",
			jose.HeaderContentType: "application/json",
			"custom":               "value",
		},
	}

	parsed, err := parseProtectedHeader(header)
	requireNoError(t, err)
	if parsed.Algorithm != jose.PS256 || parsed.KeyID != "key-1" {
		t.Fatalf("parsed header = %#v", parsed)
	}
	if parsed.Type != "example+jws" || parsed.ContentType != "application/json" {
		t.Fatalf("parsed type/content type = %q/%q", parsed.Type, parsed.ContentType)
	}
	if parsed.Nonce != "nonce-1" {
		t.Fatalf("nonce = %q, want %q", parsed.Nonce, "nonce-1")
	}
	if parsed.ExtraHeaders["custom"] != "value" {
		t.Fatalf("custom header = %#v", parsed.ExtraHeaders["custom"])
	}
}

func TestProtectedHeaderRejectsMalformedOrUnsupportedValues(t *testing.T) {
	tests := []jose.Header{
		{},
		{
			Algorithm: string(jose.HS256),
			ExtraHeaders: map[jose.HeaderKey]any{
				jose.HeaderType: 123,
			},
		},
		{
			Algorithm: string(jose.HS256),
			ExtraHeaders: map[jose.HeaderKey]any{
				headerCritical: []string{"custom"},
			},
		},
		{
			Algorithm: string(jose.HS256),
			ExtraHeaders: map[jose.HeaderKey]any{
				headerBase64: false,
			},
		},
		{
			Algorithm: string(jose.HS256),
			KeyID:     strings.Repeat("k", maxKeyIDLength+1),
		},
	}

	for index, header := range tests {
		_, err := parseProtectedHeader(header)
		if !errors.Is(err, ErrMalformedToken) {
			t.Errorf("case %d error = %v, want ErrMalformedToken", index, err)
		}
	}
}
