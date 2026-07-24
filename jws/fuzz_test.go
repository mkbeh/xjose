package jws

import (
	"bytes"
	"context"
	"testing"

	jose "github.com/go-jose/go-jose/v4"
)

func FuzzVerifierVerifyMessage(f *testing.F) {
	secret := bytes.Repeat([]byte{0xc1}, 32)
	signer, err := NewSigner(
		SigningKey{
			Algorithm: jose.HS256,
			KeyID:     "fuzz-key",
			Key:       secret,
		},
		WithMaxTokenSize(4096),
		WithMaxPayloadSize(2048),
	)
	if err != nil {
		f.Fatal(err)
	}

	verifier, err := NewVerifier(
		jose.JSONWebKey{
			Key:       secret,
			KeyID:     "fuzz-key",
			Algorithm: string(jose.HS256),
			Use:       "sig",
		},
		[]jose.SignatureAlgorithm{jose.HS256},
		WithMaxTokenSize(4096),
		WithMaxPayloadSize(2048),
	)
	if err != nil {
		f.Fatal(err)
	}

	valid, err := signer.Sign([]byte("seed payload"))
	if err != nil {
		f.Fatal(err)
	}

	f.Add(valid)
	f.Add("")
	f.Add("not-a-jws")
	f.Add("a.b.c")

	f.Fuzz(func(t *testing.T, raw string) {
		_, _ = verifier.VerifyMessage(context.Background(), raw)
	})
}

func FuzzVerifierVerifyDetached(f *testing.F) {
	secret := bytes.Repeat([]byte{0xc2}, 32)
	signer, err := NewSigner(
		SigningKey{
			Algorithm: jose.HS256,
			Key:       secret,
		},
		WithMaxTokenSize(4096),
		WithMaxPayloadSize(2048),
	)
	if err != nil {
		f.Fatal(err)
	}

	verifier, err := NewVerifier(
		secret,
		[]jose.SignatureAlgorithm{jose.HS256},
		WithMaxTokenSize(4096),
		WithMaxPayloadSize(2048),
	)
	if err != nil {
		f.Fatal(err)
	}

	seedPayload := []byte("detached seed")
	valid, err := signer.SignDetached(seedPayload)
	if err != nil {
		f.Fatal(err)
	}

	f.Add(valid, seedPayload)
	f.Add("a..b", []byte("payload"))
	f.Add("", []byte{})

	f.Fuzz(func(t *testing.T, raw string, payload []byte) {
		_, _ = verifier.VerifyDetached(context.Background(), raw, payload)
	})
}

func FuzzMultiVerifierVerifyMessage(f *testing.F) {
	secret := bytes.Repeat([]byte{0xc3}, 64)

	signer, err := NewMultiSigner(
		[]SigningKey{
			{Algorithm: jose.HS256, Key: secret},
			{Algorithm: jose.HS512, Key: secret},
		},
		WithMaxTokenSize(8192),
		WithMaxPayloadSize(2048),
	)
	if err != nil {
		f.Fatal(err)
	}

	verifier, err := NewMultiVerifier(
		secret,
		[]jose.SignatureAlgorithm{jose.HS256, jose.HS512},
		WithSignaturePolicy(RequireAllProvidedSignatures()),
		WithMaxTokenSize(8192),
		WithMaxPayloadSize(2048),
		WithMaxSignatures(4),
	)
	if err != nil {
		f.Fatal(err)
	}

	valid, err := signer.Sign([]byte("multi seed"))
	if err != nil {
		f.Fatal(err)
	}

	f.Add(valid)
	f.Add("{}")
	f.Add(`{"payload":"","signatures":[]}`)
	f.Add("not-json")

	f.Fuzz(func(t *testing.T, raw string) {
		_, _ = verifier.VerifyMessage(context.Background(), raw)
	})
}

func FuzzHMACRoundTrip(f *testing.F) {
	secret := bytes.Repeat([]byte{0xc4}, 32)

	signer, err := NewSigner(
		SigningKey{
			Algorithm: jose.HS256,
			KeyID:     "round-trip",
			Key:       secret,
		},
		WithMaxTokenSize(16<<10),
		WithMaxPayloadSize(4096),
	)
	if err != nil {
		f.Fatal(err)
	}

	verifier, err := NewVerifier(
		jose.JSONWebKey{
			Key:       secret,
			KeyID:     "round-trip",
			Algorithm: string(jose.HS256),
			Use:       "sig",
		},
		[]jose.SignatureAlgorithm{jose.HS256},
		WithMaxTokenSize(16<<10),
		WithMaxPayloadSize(4096),
	)
	if err != nil {
		f.Fatal(err)
	}

	f.Add([]byte("payload"))
	f.Add([]byte{})
	f.Add([]byte{0x00, 0xff, 0x01})

	f.Fuzz(func(t *testing.T, payload []byte) {
		if len(payload) > 4096 {
			t.Skip()
		}

		raw, err := signer.Sign(payload)
		if err != nil {
			t.Fatalf("sign: %v", err)
		}

		verified, err := verifier.VerifyMessage(context.Background(), raw)
		if err != nil {
			t.Fatalf("verify: %v", err)
		}

		if !bytes.Equal(verified.Payload, payload) {
			t.Fatalf("payload = %x, want %x", verified.Payload, payload)
		}
	})
}

func FuzzHMACDetachedRoundTrip(f *testing.F) {
	secret := bytes.Repeat([]byte{0xc5}, 32)

	signer, err := NewSigner(
		SigningKey{
			Algorithm: jose.HS256,
			Key:       secret,
		},
		WithMaxTokenSize(16<<10),
		WithMaxPayloadSize(4096),
	)
	if err != nil {
		f.Fatal(err)
	}

	verifier, err := NewVerifier(
		secret,
		[]jose.SignatureAlgorithm{jose.HS256},
		WithMaxTokenSize(16<<10),
		WithMaxPayloadSize(4096),
	)
	if err != nil {
		f.Fatal(err)
	}

	f.Add([]byte("detached payload"))
	f.Add([]byte{})

	f.Fuzz(func(t *testing.T, payload []byte) {
		if len(payload) > 4096 {
			t.Skip()
		}

		raw, err := signer.SignDetached(payload)
		if err != nil {
			t.Fatalf("sign detached: %v", err)
		}

		verified, err := verifier.VerifyDetached(
			context.Background(),
			raw,
			payload,
		)
		if err != nil {
			t.Fatalf("verify detached: %v", err)
		}

		if !bytes.Equal(verified.Payload, payload) {
			t.Fatalf("payload = %x, want %x", verified.Payload, payload)
		}
	})
}

func FuzzMultiHMACRoundTrip(f *testing.F) {
	secret := bytes.Repeat([]byte{0xc6}, 64)

	signer, err := NewMultiSigner(
		[]SigningKey{
			{Algorithm: jose.HS256, Key: secret},
			{Algorithm: jose.HS512, Key: secret},
		},
		WithMaxTokenSize(32<<10),
		WithMaxPayloadSize(4096),
	)
	if err != nil {
		f.Fatal(err)
	}

	verifier, err := NewMultiVerifier(
		secret,
		[]jose.SignatureAlgorithm{jose.HS256, jose.HS512},
		WithSignaturePolicy(RequireAllProvidedSignatures()),
		WithMaxTokenSize(32<<10),
		WithMaxPayloadSize(4096),
		WithMaxSignatures(2),
	)
	if err != nil {
		f.Fatal(err)
	}

	f.Add([]byte("multi payload"))
	f.Add([]byte{})

	f.Fuzz(func(t *testing.T, payload []byte) {
		if len(payload) > 4096 {
			t.Skip()
		}

		raw, err := signer.Sign(payload)
		if err != nil {
			t.Fatalf("sign multi: %v", err)
		}

		verified, err := verifier.VerifyMessage(context.Background(), raw)
		if err != nil {
			t.Fatalf("verify multi: %v", err)
		}

		if !bytes.Equal(verified.Payload, payload) {
			t.Fatalf("payload = %x, want %x", verified.Payload, payload)
		}
		if len(verified.Signatures) != 2 {
			t.Fatalf("signature count = %d, want 2", len(verified.Signatures))
		}
	})
}
