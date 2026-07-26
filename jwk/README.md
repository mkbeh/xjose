# JWK

[![Go](https://github.com/mkbeh/xjose/actions/workflows/go.yml/badge.svg?branch=main)](https://github.com/mkbeh/xjose/actions/workflows/go.yml)
[![Go Reference](https://pkg.go.dev/badge/github.com/mkbeh/xjose/jwk.svg)](https://pkg.go.dev/github.com/mkbeh/xjose/jwk)
[![codecov](https://codecov.io/gh/mkbeh/xjose/branch/main/graph/badge.svg?flag=jwk)](https://codecov.io/gh/mkbeh/xjose)

Secure helpers for parsing, exporting, and identifying public JSON Web Keys (JWKs) in Go.

The `jwk` module builds on [go-jose](https://github.com/go-jose/go-jose) and integrates public JWKs with the
[`jwt`](../jwt) module. It adds public-key validation, typed conversion to and from `jwt.VerificationKey`, metadata
constraints, and stable RFC 7638 thumbprint identifiers.

The module works exclusively with public asymmetric keys. Private and symmetric key material is rejected by its
validated parsing and conversion functions.

For a complete runnable example, see the [examples](../examples) directory.

## Features

* **Public-key validation:** Reject private, symmetric, malformed, empty, or incomplete key material during validated
  JWK parsing.
* **JWT integration:** Convert public JWKs to and from algorithm-bound `jwt.VerificationKey` values.
* **Metadata constraints:** Validate compatible `alg` and signature `use` values when constructing a verification key.
* **RFC 7638 thumbprints:** Generate deterministic, Base64URL-encoded SHA-256 identifiers from public key material.
* **Standard interoperability:** Use the upstream `jose.JSONWebKey` representation with Go's `encoding/json` package.

## Installation

```shell
go get github.com/mkbeh/xjose/jwk
```

## Quick Start

This example converts an RSA public key into a public JWK document, calculates its deterministic RFC 7638 thumbprint,
and restores an algorithm-bound `jwt.VerificationKey`.

<!-- @formatter:off -->
```go
// Generate an RSA key for the example.
// Load public keys from trusted key distribution in production.
privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
if err != nil {
	log.Fatalf("generate RSA key: %v", err)
}

// Bind the public key to the expected JWT signing algorithm.
verificationKey, err := jwt.NewVerificationKey(
	"signing-2026-07",
	gojwt.SigningMethodPS256,
	&privateKey.PublicKey,
)
if err != nil {
	log.Fatalf("create verification key: %v", err)
}

// Export the verification key as a public JWK.
key, err := jwk.FromVerificationKey(verificationKey)
if err != nil {
	log.Fatalf("create JWK: %v", err)
}

data, err := json.Marshal(key)
if err != nil {
    log.Fatalf("serialize JWK: %v", err)
}

// Parse and validate the public JWK.
parsed, err := jwk.Parse(data)
if err != nil {
	log.Fatalf("parse JWK: %v", err)
}

// Calculate a stable RFC 7638 public-key thumbprint.
thumbprint, err := jwk.ThumbprintID(parsed)
if err != nil {
	log.Fatalf("calculate thumbprint: %v", err)
}

// Restore an algorithm-bound JWT verification key.
restored, err := jwk.ToVerificationKey(
	parsed,
	gojwt.SigningMethodPS256,
)
if err != nil {
	log.Fatalf("create verification key from JWK: %v", err)
}

log.Printf(
	"restored key %q with thumbprint %q",
	restored.ID(),
	thumbprint,
)
```

<!-- @formatter:on -->

> [!NOTE]
> Successful parsing establishes only that the JWK contains structurally valid public key material. It does not
> establish
> who published the key or whether it is trusted for a particular issuer or purpose. Obtain JWKs from an authenticated,
> integrity-protected source configured by the application.

## Parsing and Serialization

`jwk.Key` is an alias of the upstream `jose.JSONWebKey` type and can be serialized with Go's standard `encoding/json`
package:

```go
data, err := json.Marshal(key)
```

Use `jwk.Parse` when reading JWK documents from external or otherwise untrusted sources:

```go
key, err := jwk.Parse(data)
```

`Parse` validates that the document contains supported public asymmetric key material. It rejects malformed JSON, empty
keys, private keys, and symmetric secrets.

> [!IMPORTANT]
> Directly unmarshalling JSON into `jwk.Key` bypasses the module's public-key validation. Use `jwk.Parse` for externally
> supplied JWK documents.

Optional metadata such as `kid`, `alg`, and `use` is preserved during parsing. These fields constrain how a key may be
used, but do not establish trust by themselves. Compatibility with a specific signing method and verification purpose is
validated when the JWK is converted to `jwt.VerificationKey`.

## JWT Verification Integration

The module converts public JWKs to and from algorithm-bound verification keys used by the [`jwt`](../jwt) module.

### Exporting a Verification Key

Use `FromVerificationKey` to export an asymmetric `jwt.VerificationKey` as a public JWK:

```go
key, err := jwk.FromVerificationKey(verificationKey)
```

The resulting JWK contains:

* public key material only;
* `kid` derived from the verification key ID;
* `alg` derived from the bound signing method;
* `use` set to `"sig"`.

HMAC verification keys cannot be exported because their verification material is the shared secret itself, not a
separate public key.

### Creating a Verification Key

Use `ToVerificationKey` to bind a parsed public JWK to an expected signing method:

```go
verificationKey, err := jwk.ToVerificationKey(key, gojwt.SigningMethodPS256)
```

The signing method is supplied independently through trusted application configuration. The conversion validates that:

* the public key material is compatible with the selected signing method;
* `alg`, when present, matches the selected method;
* `use`, when present, permits signature verification.

The `kid`, `alg`, and `use` fields may be omitted. Missing metadata does not replace key validation or the explicit
algorithm selected by the application.

> [!IMPORTANT]
> Treat the JWK `alg` field as an optional constraint, not as an instruction to choose a verification algorithm. Always
> select the expected signing method through trusted configuration.

## Thumbprints

`ThumbprintID` calculates an RFC 7638 SHA-256 thumbprint and returns it as an unpadded Base64URL string:

```go
thumbprint, err := jwk.ThumbprintID(key)
```

The thumbprint is derived only from the canonical public key members. Metadata such as `kid`, `alg`, and `use` does not
affect the result, so different JWK representations of the same public key produce the same identifier.

Thumbprints are useful for:

* generating deterministic key IDs;
* detecting duplicate public keys;
* comparing key material across JWK documents and metadata changes.

> [!IMPORTANT]
> A matching thumbprint identifies the same public key material, but does not establish trust, ownership, issuer
> association, or authorization for a particular purpose. Validate the key source and intended usage independently.

## Security Considerations

The module validates public JWK structure and metadata compatibility, but the application remains responsible for the
overall key trust model:

* **Trust the key source:** A structurally valid JWK may still belong to an attacker. Accept keys only from
  application-configured sources delivered through authenticated and integrity-protected channels.
* **Keep secret material private:** Do not publish private or symmetric keys through public JWK distribution. The
  module's validated parsing and conversion functions intentionally reject both.
* **Select algorithms independently:** Choose allowed signing methods through trusted application configuration. Never
  derive the verification algorithm solely from an untrusted JWK `alg` value or token header.
* **Treat metadata as constraints:** `kid`, `alg`, and `use` can restrict key selection and usage, but do not establish
  trust, ownership, or authorization by themselves.
* **Do not trust thumbprints as identities:** An RFC 7638 thumbprint identifies public key material, not the
  organization, issuer, or purpose authorized to use that key.
* **Rotate keys safely:** Publish replacement verification keys before they are used for signing, and retain previous
  keys until all tokens or signatures that depend on them can no longer be accepted.

## License

Distributed under the repository's [MIT License](../LICENSE).