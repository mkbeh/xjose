# JWK

[![Go](https://github.com/mkbeh/xjose/actions/workflows/go.yml/badge.svg?branch=main)](https://github.com/mkbeh/xjose/actions/workflows/go.yml)
[![Go Reference](https://pkg.go.dev/badge/github.com/mkbeh/xjose/jwk.svg)](https://pkg.go.dev/github.com/mkbeh/xjose/jwk)
[![codecov](https://codecov.io/gh/mkbeh/xjose/branch/main/graph/badge.svg?flag=jwk)](https://codecov.io/gh/mkbeh/xjose)

Public JWK and JWK Set support for Go.

The `jwk` module builds on [go-jose](https://github.com/go-jose/go-jose) and integrates public JWKs with the
[`jwt`](../jwt) module. It supports parsing and validating public keys, converting between JWKs and algorithm-bound
`jwt.VerificationKey` values, deterministic JWK Set resolution, and RFC 7638 thumbprint identifiers.

For complete runnable workflows, see the [examples](../examples) directory.

## Features

* **JWK and JWK Set operations:** Parse, construct, inspect, and serialize individual public JWKs and standard
  `{"keys":[...]}` documents.
* **JWT integration:** Convert between public JWKs and algorithm-bound `jwt.VerificationKey` values, and use JWK Sets as
  `jwt.KeyResolver` implementations.
* **Key resolution:** Select named keys by protected `kid`, or use a single anonymous key for tokens without a key ID.
* **Public-key export:** Convert trusted verification keys into public JWKs and JWK Sets without exporting private or
  symmetric key material.
* **Metadata validation:** Enforce compatible JWK `alg` and `use` values when converting keys for signature
  verification.
* **RFC 7638 thumbprints:** Generate Base64URL-encoded SHA-256 thumbprints from public key material.
* **Key rotation:** Publish active and previous verification keys in the same JWK Set.

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
data, _ := json.Marshal(key)
```

Use `jwk.Parse` for externally supplied JWK documents:

```go
key, _ := jwk.Parse(data)
```

`Parse` decodes the document and validates that it contains supported public asymmetric key material. Malformed JSON,
empty or incomplete keys, private keys, and symmetric secrets are rejected.

> [!IMPORTANT]
> Directly unmarshalling JSON into `jwk.Key` bypasses the module's public-key validation. Use `jwk.Parse` for externally
> supplied documents.

Optional metadata such as `kid`, `alg`, and `use` is preserved during parsing but does not establish trust by itself.
When the JWK is converted to `jwt.VerificationKey`, its key material and metadata are validated against the signing
method selected through trusted application configuration.

## JWT Verification Integration

The module converts between public JWKs and algorithm-bound verification keys used by the [`jwt`](../jwt) module.

### Exporting a Verification Key

Use `FromVerificationKey` to export an asymmetric `jwt.VerificationKey` as a public JWK:

```go
key, _ := jwk.FromVerificationKey(verificationKey)
```

The resulting JWK contains:

* public key material only;
* `kid` copied from the verification key ID;
* `alg` derived from the bound signing method;
* `use` set to `"sig"`.

HMAC verification keys cannot be exported because their verification material is the shared secret rather than a
separate public key.

### Creating a Verification Key

Use `ToVerificationKey` to convert a public JWK into a verification key bound to an explicitly selected signing method:

<!-- @formatter:off -->
```go
verificationKey, _ := jwk.ToVerificationKey(
	key,
	gojwt.SigningMethodPS256,
)
```
<!-- @formatter:on -->

The signing method is supplied independently through trusted application configuration. The conversion verifies that:

* the public key material is compatible with the selected signing method;
* `alg`, when present, matches the selected method;
* `use`, when present, permits signature verification.

The `kid`, `alg`, and `use` fields are optional. When present, they are preserved or enforced as constraints; they do
not establish trust or select the verification algorithm.

> [!IMPORTANT]
> Treat the JWK `alg` field as an optional constraint, not as an instruction. Select the expected signing method through
> trusted application configuration.

## JWK Sets

A `Set` represents a validated JSON Web Key Set containing public asymmetric keys. It can be constructed from trusted
in-memory JWKs, parsed from a standard `{"keys":[...]}` document, serialized with `encoding/json`, or used directly as a
`jwt.KeyResolver`.

### Constructing a Set

Use `NewSet` when the public JWKs are already available in memory:

```go
set, _ := jwk.NewSet(currentKey, previousKey)
```

The set copies the JWK sequence. The key values stored in its entries must be treated as immutable after construction.

A set containing multiple keys requires every key to have a unique, non-empty `kid`. A single key may omit `kid`, in
which case it can resolve only tokens that also omit the key ID.

To export an existing `jwt.StaticKeySet` as public JWKs:

```go
set, _ := jwk.FromStaticKeySet(keySet)
```

Only asymmetric verification keys can be exported. HMAC keys are rejected because their verification material is the
shared secret itself.

### Parsing and Serialization

Use `ParseSet` when reading a JWK Set document from an external source:

```go
set, _ := jwk.ParseSet(data)
```

Parsing validates every key and rejects empty sets, private or symmetric key material, missing key IDs in multi-key
sets, and duplicate key IDs.

Use `ParseSetWithLimit` to place an explicit bound on the number of accepted keys:

```go
set, _ := jwk.ParseSetWithLimit(data, 100)
```

A validated set can be serialized with `encoding/json`:

```go
data, _ := json.Marshal(set)
```

`Keys` returns a shallow copy of the JWK sequence:

```go
keys := set.Keys()
```

The returned slice may be modified independently, but the JWK values it contains must continue to be treated as
immutable.

### JWT Key Resolution

`Set` implements `jwt.KeyResolver` and can be passed directly to `jwt.NewVerifier`:

<!-- @formatter:off -->
```go
set, _ := jwk.ParseSet(data)

verifier, _ := jwt.NewVerifier(
	set,
	jwt.WithMethods(gojwt.SigningMethodPS256),
)

claims := new(AccessClaims)
header, _ := verifier.VerifyToken(ctx, token, claims)
```
<!-- @formatter:on -->

For a named set, the protected JWT `kid` header must exactly match one of the set entries. Tokens with a missing or
unknown key ID are rejected.

A set containing one anonymous key accepts only tokens without `kid`. It does not use that key as a fallback for tokens
containing an unknown key ID.

After selecting a JWK, the resolver validates its `alg` and `use` metadata against the token algorithm and returns an
algorithm-bound `jwt.VerificationKey`.

> [!IMPORTANT]
> The token `kid` header is an untrusted lookup value. It selects a candidate only within the already trusted JWK Set;
> it must not determine the key source or be used as authenticated metadata before verification succeeds.

## Thumbprints

`ThumbprintID` computes an RFC 7638 SHA-256 thumbprint and returns it as an unpadded Base64URL-encoded string:

```go
thumbprint, _ := jwk.ThumbprintID(key)
```

The thumbprint is derived from the canonical public key members only. Metadata such as `kid`, `alg`, and `use` is
excluded, so JWKs containing the same public key material produce the same thumbprint regardless of metadata
differences.

Thumbprints can be used to:

* generate deterministic key identifiers;
* detect duplicate public keys;
* compare key material across JWK documents.

> [!IMPORTANT]
> A thumbprint identifies public key material, not its owner, issuer, source, or permitted usage. Authenticate the key
> source and apply the intended usage policy independently.

## Security Considerations

The module validates public key material and JWK metadata, but the application remains responsible for key provenance,
usage policy, and lifecycle management:

* **Authenticate key sources:** A structurally valid JWK may still be controlled by an attacker. Obtain keys only from
  application-configured sources delivered through authenticated and integrity-protected channels.
* **Protect secret key material:** Never publish private keys or symmetric secrets through public JWK distribution. The
  module rejects both during parsing, validation, and conversion.
* **Select algorithms independently:** Configure accepted signing methods through trusted application settings. Do not
  derive the verification algorithm from an untrusted JWK `alg` value or token header.
* **Treat metadata as constraints:** The `kid`, `alg`, and `use` fields can restrict key selection and usage, but do not
  establish provenance, ownership, or authorization.
* **Treat thumbprints as key identifiers:** An RFC 7638 thumbprint identifies public key material. It does not identify
  the organization, issuer, or purpose authorized to use that key.
* **Coordinate key rotation:** Publish a replacement verification key before issuing signatures with the corresponding
  private key. Retain previous keys until every token or signature created with them is outside the application's
  acceptance window.

## License

Distributed under the repository's [MIT License](../LICENSE).