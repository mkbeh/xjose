package jwe

import (
	"strings"
	"testing"

	"github.com/go-jose/go-jose/v4"
)

func TestParseHeader(t *testing.T) {
	extra := map[jose.HeaderKey]any{
		headerEncryption:         string(jose.A256GCM),
		headerCompression:        string(jose.DEFLATE),
		jose.HeaderType:          "JWE",
		jose.HeaderContentType:   "application/json",
		jose.HeaderKey("tenant"): "acme",
	}

	parsed, err := parseHeader(jose.Header{
		Algorithm:    string(jose.RSA_OAEP_256),
		KeyID:        "key-1",
		ExtraHeaders: extra,
	})
	requireNoError(t, err)

	if parsed.Algorithm != jose.RSA_OAEP_256 {
		t.Fatalf("algorithm = %q, want %q", parsed.Algorithm, jose.RSA_OAEP_256)
	}
	if parsed.Encryption != jose.A256GCM {
		t.Fatalf("encryption = %q, want %q", parsed.Encryption, jose.A256GCM)
	}
	if parsed.Compression != jose.DEFLATE {
		t.Fatalf("compression = %q, want %q", parsed.Compression, jose.DEFLATE)
	}
	if parsed.KeyID != "key-1" || parsed.Type != "JWE" || parsed.ContentType != "application/json" {
		t.Fatalf("parsed header = %#v", parsed)
	}
	if parsed.ExtraHeaders[jose.HeaderKey("tenant")] != "acme" {
		t.Fatalf("tenant header = %#v", parsed.ExtraHeaders[jose.HeaderKey("tenant")])
	}

	parsed.ExtraHeaders[jose.HeaderKey("tenant")] = "mutated"
	if extra[jose.HeaderKey("tenant")] != "acme" {
		t.Fatal("parseHeader did not clone the extra-header map")
	}
}

func TestParseHeaderRejectsMalformedHeaders(t *testing.T) {
	base := func() jose.Header {
		return jose.Header{
			Algorithm: string(jose.DIRECT),
			ExtraHeaders: map[jose.HeaderKey]any{
				headerEncryption: string(jose.A256GCM),
			},
		}
	}

	tests := []struct {
		name   string
		mutate func(*jose.Header)
	}{
		{
			name: "critical",
			mutate: func(header *jose.Header) {
				header.ExtraHeaders[headerCritical] = []string{"tenant"}
			},
		},
		{
			name: "missing algorithm",
			mutate: func(header *jose.Header) {
				header.Algorithm = ""
			},
		},
		{
			name: "long algorithm",
			mutate: func(header *jose.Header) {
				header.Algorithm = strings.Repeat("a", maxAlgorithmLength+1)
			},
		},
		{
			name: "missing encryption",
			mutate: func(header *jose.Header) {
				delete(header.ExtraHeaders, headerEncryption)
			},
		},
		{
			name: "non-string encryption",
			mutate: func(header *jose.Header) {
				header.ExtraHeaders[headerEncryption] = 1
			},
		},
		{
			name: "empty type",
			mutate: func(header *jose.Header) {
				header.ExtraHeaders[jose.HeaderType] = ""
			},
		},
		{
			name: "non-string content type",
			mutate: func(header *jose.Header) {
				header.ExtraHeaders[jose.HeaderContentType] = true
			},
		},
		{
			name: "control compression",
			mutate: func(header *jose.Header) {
				header.ExtraHeaders[headerCompression] = "DEF\n"
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			header := base()
			test.mutate(&header)

			_, err := parseHeader(header)
			requireErrorIs(t, err, ErrMalformedToken)
		})
	}
}

func TestParseMultiSharedHeaderAllowsMissingRecipientFields(t *testing.T) {
	parsed, err := parseMultiSharedHeader(jose.Header{
		ExtraHeaders: map[jose.HeaderKey]any{
			headerEncryption:         string(jose.A256GCM),
			jose.HeaderKey("keyset"): "2026-07",
		},
	})
	requireNoError(t, err)

	if parsed.Algorithm != "" || parsed.KeyID != "" {
		t.Fatalf("recipient fields unexpectedly present: %#v", parsed)
	}
	if parsed.Encryption != jose.A256GCM {
		t.Fatalf("encryption = %q, want %q", parsed.Encryption, jose.A256GCM)
	}
}

func TestCloneExtraHeaders(t *testing.T) {
	if cloneExtraHeaders(nil) != nil {
		t.Fatal("nil headers should clone to nil")
	}
	if cloneExtraHeaders(map[jose.HeaderKey]any{}) != nil {
		t.Fatal("empty headers should clone to nil")
	}

	original := map[jose.HeaderKey]any{"a": "b"}
	cloned := cloneExtraHeaders(original)
	cloned["a"] = "c"
	if original["a"] != "b" {
		t.Fatal("header map was not cloned")
	}
}

func TestParseMultiSharedHeaderRejectsMalformedHeaders(t *testing.T) {
	base := func() jose.Header {
		return jose.Header{ExtraHeaders: map[jose.HeaderKey]any{
			headerEncryption: string(jose.A256GCM),
		}}
	}

	tests := []struct {
		name   string
		mutate func(*jose.Header)
	}{
		{
			name: "missing encryption",
			mutate: func(header *jose.Header) {
				delete(header.ExtraHeaders, headerEncryption)
			},
		},
		{
			name: "non-string encryption",
			mutate: func(header *jose.Header) {
				header.ExtraHeaders[headerEncryption] = 1
			},
		},
		{
			name: "empty type",
			mutate: func(header *jose.Header) {
				header.ExtraHeaders[jose.HeaderType] = ""
			},
		},
		{
			name: "long content type",
			mutate: func(header *jose.Header) {
				header.ExtraHeaders[jose.HeaderContentType] = strings.Repeat("a", maxContentTypeLength+1)
			},
		},
		{
			name: "non-string compression",
			mutate: func(header *jose.Header) {
				header.ExtraHeaders[headerCompression] = true
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			header := base()
			test.mutate(&header)
			_, err := parseMultiSharedHeader(header)
			requireErrorIs(t, err, ErrMalformedToken)
		})
	}
}
