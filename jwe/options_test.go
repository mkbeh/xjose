package jwe

import (
	"errors"
	"strings"
	"testing"

	"github.com/go-jose/go-jose/v4"
)

func TestMakeConfigDefaults(t *testing.T) {
	config, err := makeConfig(nil)
	requireNoError(t, err)

	if config.typ != "" {
		t.Fatalf("typ = %q, want empty", config.typ)
	}
	if config.cty != "" {
		t.Fatalf("cty = %q, want empty", config.cty)
	}
	if config.compression != jose.NONE {
		t.Fatalf("compression = %q, want %q", config.compression, jose.NONE)
	}
	if config.maxTokenSize != DefaultMaxTokenSize {
		t.Fatalf("max token size = %d, want %d", config.maxTokenSize, DefaultMaxTokenSize)
	}
	if config.maxPlaintextSize != DefaultMaxPlaintextSize {
		t.Fatalf("max plaintext size = %d, want %d", config.maxPlaintextSize, DefaultMaxPlaintextSize)
	}
	if config.extraHeaders != nil {
		t.Fatalf("extra headers = %#v, want nil", config.extraHeaders)
	}
}

func TestMakeConfigAppliesOptions(t *testing.T) {
	config, err := makeConfig([]Option{
		WithType("JWE"),
		WithContentType("application/json"),
		WithCompression(jose.DEFLATE),
		WithMaxTokenSize(1234),
		WithMaxPlaintextSize(567),
		WithHeader(jose.HeaderKey("tenant"), "acme"),
		WithHeader(jose.HeaderKey("tenant"), "globex"),
	})
	requireNoError(t, err)

	if config.typ != "JWE" {
		t.Fatalf("typ = %q, want JWE", config.typ)
	}
	if config.cty != "application/json" {
		t.Fatalf("cty = %q, want application/json", config.cty)
	}
	if config.compression != jose.DEFLATE {
		t.Fatalf("compression = %q, want %q", config.compression, jose.DEFLATE)
	}
	if config.maxTokenSize != 1234 {
		t.Fatalf("max token size = %d, want 1234", config.maxTokenSize)
	}
	if config.maxPlaintextSize != 567 {
		t.Fatalf("max plaintext size = %d, want 567", config.maxPlaintextSize)
	}
	if got := config.extraHeaders[jose.HeaderKey("tenant")]; got != "globex" {
		t.Fatalf("tenant header = %#v, want globex", got)
	}
}

func TestMakeConfigRejectsInvalidOptions(t *testing.T) {
	invalidUTF8 := string([]byte{0xff})

	tests := []struct {
		name   string
		option Option
	}{
		{name: "nil option", option: nil},
		{name: "empty type", option: WithType("")},
		{name: "long type", option: WithType(strings.Repeat("a", maxTypeLength+1))},
		{name: "invalid UTF-8 type", option: WithType(invalidUTF8)},
		{name: "control type", option: WithType("JWE\n")},
		{name: "empty content type", option: WithContentType("")},
		{name: "long content type", option: WithContentType(strings.Repeat("a", maxContentTypeLength+1))},
		{name: "invalid UTF-8 content type", option: WithContentType(invalidUTF8)},
		{name: "control content type", option: WithContentType("application/json\r")},
		{name: "zero token size", option: WithMaxTokenSize(0)},
		{name: "negative token size", option: WithMaxTokenSize(-1)},
		{name: "zero plaintext size", option: WithMaxPlaintextSize(0)},
		{name: "negative plaintext size", option: WithMaxPlaintextSize(-1)},
		{name: "unsupported compression", option: WithCompression(jose.CompressionAlgorithm("GZIP"))},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := makeConfig([]Option{test.option})
			requireErrorIs(t, err, ErrInvalidConfig)
		})
	}
}

func TestValidateHeaderValueBoundaries(t *testing.T) {
	if err := validateHeaderValue(headerType, strings.Repeat("a", maxTypeLength), maxTypeLength); err != nil {
		t.Fatalf("boundary value rejected: %v", err)
	}

	for _, value := range []string{"", "ok\x00", string([]byte{0xff})} {
		if err := validateHeaderValue(headerType, value, maxTypeLength); err == nil {
			t.Fatalf("value %q unexpectedly accepted", value)
		}
	}
}

func TestErrorsAreDistinct(t *testing.T) {
	if errors.Is(ErrEncrypt, ErrDecrypt) {
		t.Fatal("ErrEncrypt unexpectedly matches ErrDecrypt")
	}
}
