# JWKS

Secure helpers for parsing, publishing, and resolving public JSON Web Key Sets (JWKS) in Go.

The `jwks` module builds on [go-jose](https://github.com/go-jose/go-jose) and integrates public key sets with the
[`jwt`](../jwt) module. It adds validated public-key sets, deterministic `kid` lookup, algorithm and key-use
constraints,
key-rotation support, and bounded JWKS parsing.

The module works exclusively with public asymmetric verification keys. Private and symmetric key material is rejected
by its validated construction and parsing functions.

For a complete runnable example, see the [examples](../examples) directory.

## Features

* **Validated key sets:** Reject empty sets, private or symmetric keys, duplicate key IDs, and anonymous keys in
  multi-key sets.
* **JWT integration:** `Set` implements `jwt.KeyResolver` and can be passed directly to a JWT verifier.
* **Deterministic key selection:** Resolve named keys by protected `kid`, or use a single anonymous key for tokens that
  omit `kid`.
* **Metadata constraints:** Validate compatible `alg` and signature `use` values during key resolution.
* **Key rotation:** Publish current and previous verification keys together in one validated in-memory set.
* **Bounded parsing:** Limit the number of keys accepted from a JWKS document.
* **Standard serialization:** Marshal validated sets as standard `{"keys":[...]}` JWKS documents.

## Installation

```shell
go get github.com/mkbeh/xjose/jwks
```

## Quick Start

This example exports a trusted verification key as JWKS, parses the document, issues a token, and resolves the matching
public key by its protected `kid` during verification.

<!-- @formatter:off -->
```go
type AccessClaims struct {
	Role string `json:"role"`
	gojwt.RegisteredClaims
}

ctx := context.Background()

// Generate a signing key for the example.
// Load private keys from protected key storage in production.
privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
if err != nil {
	log.Fatalf("generate RSA key: %v", err)
}

// Bind the private key to the expected signing algorithm and key ID.
signingKey, err := jwt.NewSigningKey(
	"signing-2026-07",
	gojwt.SigningMethodPS256,
	privateKey,
)
if err != nil {
	log.Fatalf("create signing key: %v", err)
}

// Export the public verification material as JWKS.
verificationKeySet, err := jwt.NewStaticKeySet(
	signingKey.VerificationKey(),
)
if err != nil {
	log.Fatalf("create verification key set: %v", err)
}

publicKeySet, err := jwks.FromStaticKeySet(verificationKeySet)
if err != nil {
	log.Fatalf("create JWKS: %v", err)
}

data, err := json.Marshal(publicKeySet)
if err != nil {
	log.Fatalf("serialize JWKS: %v", err)
}

// Parse and validate the JWKS document.
parsedKeySet, err := jwks.Parse(data)
if err != nil {
	log.Fatalf("parse JWKS: %v", err)
}

// Issue a token whose protected kid identifies the verification key.
signer, err := jwt.NewSigner(
	signingKey,
	jwt.WithType("access+jwt"),
)
if err != nil {
	log.Fatalf("create signer: %v", err)
}

now := time.Now().UTC()
token, err := signer.Sign(
	ctx,
	&AccessClaims{
		Role: "admin",
		RegisteredClaims: gojwt.RegisteredClaims{
			Issuer:    "https://auth.example.com",
			Subject:   "user-123",
			Audience:  gojwt.ClaimStrings{"orders-api"},
			ExpiresAt: gojwt.NewNumericDate(now.Add(15 * time.Minute)),
			IssuedAt:  gojwt.NewNumericDate(now),
		},
	},
)
if err != nil {
	log.Fatalf("sign token: %v", err)
}

// Use the parsed JWKS directly as the verification key resolver.
verifier, err := jwt.NewVerifier(
	parsedKeySet,
	jwt.WithMethods(gojwt.SigningMethodPS256),
	jwt.WithIssuer("https://auth.example.com"),
	jwt.WithAudience("orders-api"),
	jwt.WithType("access+jwt"),
	jwt.RequireIssuedAt(),
	jwt.WithMaxLifetime(15 * time.Minute),
)
if err != nil {
	log.Fatalf("create verifier: %v", err)
}

verifiedClaims := new(AccessClaims)
header, err := verifier.VerifyToken(ctx, token, verifiedClaims)
if err != nil {
	log.Fatalf("verify token: %v", err)
}

log.Printf(
	"verified key %q for subject %q",
	header.KeyID,
	verifiedClaims.Subject,
)
```
<!-- @formatter:on -->

> [!NOTE]
> Successful parsing establishes only that the JWKS contains structurally valid public verification keys. It does not
> establish who published the document or whether its keys are trusted for a particular issuer or purpose. Accept JWKS
> only from authenticated, integrity-protected sources configured by the application.

## Parsing and Serialization

Use `Parse` when reading a JWKS document from an external or otherwise untrusted source:

```go
keySet, err := jwks.Parse(data)
```

`Parse` validates every public key and applies the default key-count limit. Use `ParseWithLimit` when the application
requires a different maximum:

```go
keySet, err := jwks.ParseWithLimit(data, 50)
```

### JSON Interoperability

Validated sets can be serialized with Go's standard `encoding/json` package:

```go
data, err := json.Marshal(keySet)
```

The resulting document uses the standard JWKS structure:

```json
{
  "keys": [
    {
      "kty": "RSA",
      "kid": "signing-2026-07",
      "alg": "PS256",
      "use": "sig",
      "n": "...",
      "e": "..."
    }
  ]
}
```

> [!IMPORTANT]
> `ParseWithLimit` constrains the number of keys, not the byte size of the JSON document. When loading JWKS remotely,
> limit the response body before parsing and reject responses that exceed the configured bound.

## Key Sets and Selection

A validated `Set` can be created from trusted public JWKs or exported from verification keys already configured through
the [`jwt`](../jwt) module.

### Creating a Key Set

Use `New` with trusted in-memory public JWKs:

```go
keySet, err := jwks.New(currentKey, previousKey)
```

Use `FromStaticKeySet` to publish asymmetric `jwt.VerificationKey` values as JWKS:

```go
publicKeySet, err := jwks.FromStaticKeySet(verificationKeySet)
```

Exported keys contain public key material together with:

* `kid` derived from the verification key ID;
* `alg` derived from the bound signing method;
* `use` set to `"sig"`.

HMAC verification keys cannot be exported because their verification material is the shared secret itself rather than a
separate public key.

`Set.Keys` returns a copy of the key slice, but does not deep-copy the underlying key material. Treat returned keys and
their public key objects as immutable while the set is in use.

### JWT Key Resolution

`Set` implements `jwt.KeyResolver` and can be passed directly to `jwt.NewVerifier`.

A set containing multiple keys requires every key to have a non-empty, unique `kid`. During verification, the protected
JWT `kid` must match exactly one key in the set; missing and unknown key IDs are rejected.

A single anonymous key is also supported:

<!-- @formatter:off -->
```go
keySet, err := jwks.New(
	jwks.Key{
		Key:       publicKey,
		Algorithm: gojwt.SigningMethodPS256.Alg(),
		Use:       "sig",
	},
)
```
<!-- @formatter:on -->

An anonymous set accepts only tokens without a `kid`. It does not act as a fallback for tokens containing an unknown key
ID.

After selecting a candidate key, resolution validates that:

* `alg`, when present in the JWK, matches the protected JWT algorithm;
* `use`, when present, permits signature verification;
* the algorithm is supported;
* the public key material is compatible with that algorithm.

The verifier's independent `WithMethods` allowlist remains mandatory.

> [!IMPORTANT]
> The token `kid` is an untrusted lookup selector, not proof of key ownership or issuer identity. Trust in the JWKS
> source and accepted algorithms must be established independently by the application.

## Security Considerations

The module validates public key sets and enforces deterministic lookup rules, but the application remains responsible
for the overall key trust model:

* **Trust the JWKS source:** A structurally valid key set may still contain attacker-controlled keys. Accept JWKS
  documents only from application-configured sources delivered through authenticated and integrity-protected channels.
* **Keep secret material private:** Never publish private or symmetric keys through JWKS. The module's validated
  construction and parsing functions reject both.
* **Configure algorithms independently:** Always define accepted signing methods explicitly on the JWT verifier. JWK
  `alg` metadata is an optional constraint, not a replacement for verifier policy.
* **Require unambiguous key IDs:** Multi-key sets require every key to have a non-empty, unique `kid`, preventing
  ambiguous token-driven key selection.
* **Treat metadata as constraints:** `kid`, `alg`, and `use` restrict key selection and usage, but do not establish key
  ownership, issuer association, or trust by themselves.
* **Balance rotation, revocation, and availability:** Retaining stale key sets too long delays key removal, while
  removing previous keys too early can reject valid tokens during rotation. Account for token lifetime, clock skew, and
  cache propagation.
* **Do not authorize by key ID alone:** A matching `kid` only selects a candidate verification key. Signature and claims
  validation must succeed before the token or resolved key identity is used in authorization decisions.

## License

Distributed under the repository's [MIT License](../LICENSE).