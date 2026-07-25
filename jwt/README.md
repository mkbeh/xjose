# JWT

Secure, typed helpers for signing and verifying compact JSON Web Tokens in Go.

The `jwt` module builds on [golang-jwt/jwt](https://github.com/golang-jwt/jwt) and adds explicit key types, strict
verification defaults, resolver-based key selection, external signing support, and configurable security policies.

> [!IMPORTANT]
> JWTs provide integrity and authenticity, not confidentiality. Anyone who obtains a token can decode its header and
> claims. Use the [JWE module](../jwe) when sensitive payloads must be encrypted.

## Overview

Use this module to issue and verify compact signed JWTs with structured claims.

It provides a high-level API around signing keys, verification keys, claim validation, key rotation, and external
signing systems while preserving compatibility with custom claim types supported by the upstream `jwt.Claims` interface.

For complete runnable examples, see the [examples](../examples) directory.

## Features

* **Strict verification defaults:** Explicit algorithm allowlists, required expiration validation, token size limits,
  and strict compact-token parsing.
* **Typed key configuration:** Signing and verification keys are bound to their expected algorithms, preventing key
  material from being used implicitly with an untrusted token algorithm.
* **Flexible key resolution:** Built-in static key sets and custom resolvers support `kid`-based key selection and key
  rotation.
* **External signing:** Context-aware signing through KMS, HashiCorp Vault, HSMs, remote signing services, or custom
  cryptographic backends.
* **Validation policies:** Configurable checks for issuer (`iss`), audience (`aud`), subject (`sub`), token type (
  `typ`), maximum token lifetime, and maximum token age.
* **Custom claims:** Decode tokens into application-specific claim structures implementing the upstream `jwt.Claims`
  interface.
* **Key parsing helpers:** PEM and DER utilities for RSA, ECDSA, and Ed25519 key material.

## Installation

```shell
go get github.com/mkbeh/xjose/jwt
```

## Quick Start

This example issues an `HS256` access token with custom typed claims, then verifies its signature, token type, issuer,
audience, expiration, and maximum lifetime.

<!-- @formatter:off -->
```go
type AccessClaims struct {
	Role string `json:"role"`
	gojwt.RegisteredClaims
}

ctx := context.Background()

// Create an algorithm-bound signing key.
// Use at least 32 random bytes from a secret store in production.
secret := []byte("0123456789abcdef0123456789abcdef")

signingKey, err := jwt.NewSigningKey("hmac-key-id", gojwt.SigningMethodHS256, secret)
if err != nil {
	log.Fatalf("create signing key: %v", err)
}

// Create a reusable signer with an application-specific token type.
signer, err := jwt.NewSigner(
	signingKey,
	jwt.WithType("access+jwt"),
)
if err != nil {
	log.Fatalf("create signer: %v", err)
}

// Prepare registered and application-specific claims.
now := time.Now().UTC()
claims := &AccessClaims{
	Role: "admin",
	RegisteredClaims: gojwt.RegisteredClaims{
		Issuer:    "https://example.com",
		Subject:   "user-123",
		Audience:  gojwt.ClaimStrings{"example-api"},
		ExpiresAt: gojwt.NewNumericDate(now.Add(15 * time.Minute)),
		IssuedAt:  gojwt.NewNumericDate(now),
	},
}

// Sign and serialize the compact token.
token, err := signer.Sign(ctx, claims)
if err != nil {
	log.Fatalf("sign token: %v", err)
}

// Define the trust policy used to verify incoming tokens.
verifier, err := jwt.NewVerifier(
	signingKey.VerificationKey(),
	jwt.WithMethods(gojwt.SigningMethodHS256),
	jwt.WithIssuer("https://example.com"),
	jwt.WithAudience("example-api"),
	jwt.WithType("access+jwt"),
	jwt.RequireIssuedAt(),
	jwt.WithMaxLifetime(15*time.Minute),
)
if err != nil {
	log.Fatalf("create verifier: %v", err)
}

// Verify the signature, apply the policy, and decode the claims.
verifiedClaims := new(AccessClaims)
if _, err := verifier.VerifyToken(ctx, token, verifiedClaims); err != nil {
	log.Fatalf("verify token: %v", err)
}

log.Printf(
	"verified subject %q with role %q",
	verifiedClaims.Subject,
	verifiedClaims.Role,
)
```
<!-- @formatter:on -->

> [!NOTE]
> HMAC is appropriate only when every verifier is also trusted to issue tokens, because all participants share the same
> secret. Use RSA, ECDSA, or Ed25519 when services should verify tokens without receiving signing authority.

## Claims

The verifier can decode a token into any custom type implementing the upstream `gojwt.Claims` interface. Embedding
`gojwt.RegisteredClaims` is the simplest way to add application-specific fields while retaining standard JWT claims.

### Custom Validation

Custom claims can implement the upstream `gojwt.ClaimsValidator` interface by defining `Validate() error`:

<!-- @formatter:off -->
```go
type AccessClaims struct {
	Role string `json:"role"`
	gojwt.RegisteredClaims
}

func (c AccessClaims) Validate() error {
	if c.Role == "" {
		return errors.New("role is required")
	}
	return nil
}
```
<!-- @formatter:on -->

Custom validation runs automatically during token verification in addition to signature verification, registered-claim
validation, and the policies configured on `Verifier`. It cannot disable or replace those checks.

## Signing

A `SigningKey` binds trusted key material to a specific signing method. The resulting `Signer` constructs the protected
JWT header from that configuration:

* **`alg`** is derived from the signing method bound to the key.
* **`kid`** is included when the signing key has a non-empty ID.
* **`typ`** defaults to `"JWT"`.

Configure the signer once, then use it to issue tokens:

<!-- @formatter:off -->

```go
signer, err := jwt.NewSigner(
	signingKey,
	jwt.WithType("access+jwt"),
	jwt.WithMaxTokenSize(32 << 10),
)

token, err := signer.Sign(ctx, claims)
```

<!-- @formatter:on -->

`WithType` replaces the default `"JWT"` value with an application-specific token type. Use `WithoutType` only when
interoperability requires omitting the `typ` header:

<!-- @formatter:off -->

```go
signer, err := jwt.NewSigner(
	signingKey,
	jwt.WithoutType(),
)
```

<!-- @formatter:on -->

`WithMaxTokenSize` limits the resulting compact token. Signing fails when the serialized token exceeds the configured
bound; keep this limit as small as practical for the claims issued by the application.

## Verification

To prevent algorithm substitution and key-misuse attacks, verification is driven by trusted application configuration
rather than untrusted token headers.

A `Verifier` combines:

* a trusted `KeyResolver`;
* a mandatory algorithm allowlist configured with `WithMethods`;
* optional claim and JOSE header policies.

Both `VerificationKey` and `StaticKeySet` implement `KeyResolver` and can be passed directly to `NewVerifier`.

### Verification Methods

Both methods verify the signature, apply the configured policy, and decode the claims. Choose the method based on
whether the application also needs the verified JOSE header.

Use `Verify` when only the claims are required:

<!-- @formatter:off -->

```go
claims := new(AccessClaims)

err := verifier.Verify(ctx, token, claims)
```

<!-- @formatter:on -->

Use `VerifyToken` to also receive the verified `alg`, `kid`, and `typ` values:

<!-- @formatter:off -->

```go
claims := new(AccessClaims)

header, err := verifier.VerifyToken(ctx, token, claims)
```

<!-- @formatter:on -->

> [!IMPORTANT]
> Token headers are untrusted until verification succeeds. A custom `KeyResolver` may use `alg`, `kid`, and `typ` only
> as candidate-key selectors, never as proof of authenticity.

## Validation Policy

A `Verifier` applies strict baseline validation and can be extended with application-specific claim and header policies.

### Secure Defaults

A verifier starts from a fail-closed validation baseline:

* **Explicit algorithms:** `WithMethods` is required, and tokens using any other signing method are rejected.
* **Strict parsing:** JWT segments must use valid Base64URL encoding, and malformed compact tokens are rejected.
* **Bounded input:** Tokens exceeding the configured size limit are rejected before cryptographic verification.
* **Required expiration:** Every token must contain a valid `exp` claim unless this requirement is explicitly disabled.
* **Not-before validation:** When `nbf` is present, the token is rejected until that time is reached.

Application-specific trust requirements—including issuer, audience, subject, token type, and whether `iat` must be
present—are not inferred automatically and should be configured explicitly.

### Policy Configuration

Verifier options are combined into a single validation policy. A token is accepted only when its signature is valid and
every configured constraint succeeds.

The following policy is suitable for short-lived access tokens issued by a known authority:

<!-- @formatter:off -->

```go
verifier, err := jwt.NewVerifier(
	resolver,

	// Trust only the expected signing algorithm.
	jwt.WithMethods(gojwt.SigningMethodPS256),

	// Bind the token to its intended issuer, audience, and type.
	jwt.WithIssuer("https://auth.example.com"),
	jwt.WithAudience("orders-api"),
	jwt.WithType("access+jwt"),

	// Require an issuance time and limit the declared token lifetime.
	jwt.RequireIssuedAt(),
	jwt.WithMaxLifetime(15 * time.Minute),
	jwt.WithLeeway(30 * time.Second),
)
```

<!-- @formatter:on -->

### Key Interactions

* **Audience:** `WithAudience` requires at least one configured audience to match; `WithAllAudiences` requires all of
  them.
* **Issued At (`iat`):** `ValidateIssuedAt` validates `iat` when present; `RequireIssuedAt` also rejects tokens that
  omit it.
* **Duration limits:** `WithMaxLifetime` restricts `exp - iat`, while `WithMaxTokenAge` restricts `now - iat`.
* **Leeway:** `WithLeeway` applies to expiration, not-before, issued-at, and token-age validation, but does not extend
  `WithMaxLifetime`.

> [!IMPORTANT]
> `WithMaxLifetime` and `WithMaxTokenAge` do not enforce `iat` presence on their own. Combine them with
`RequireIssuedAt` if tokens omitting an issuance timestamp must be rejected.

> [!WARNING]
> Expiration validation is enabled by default. Use `AllowMissingExpiration` only when compatibility with non-expiring
> tokens is explicitly required.

## Key Management and Resolvers

A `Verifier` delegates trusted-key selection to a `KeyResolver`. Both `VerificationKey` and `StaticKeySet` implement
this interface directly.

### Static Verification

Use a single named key when the verifier trusts one signing key:

<!-- @formatter:off -->
```go
verificationKey, err := jwt.NewVerificationKey(
	"key-2026-07",
	gojwt.SigningMethodPS256,
	publicKey,
)

verifier, err := jwt.NewVerifier(
	verificationKey,
	jwt.WithMethods(gojwt.SigningMethodPS256),
)
```
<!-- @formatter:on -->

A named key accepts only tokens containing the same `kid`. To accept only tokens without a `kid`, create an anonymous
key by passing an empty key ID:

<!-- @formatter:off -->
```go
anonymousKey, err := jwt.NewVerificationKey(
	"",
	gojwt.SigningMethodPS256,
	publicKey,
)
```
<!-- @formatter:on -->

For local key rotation, keep the active and recently retired verification keys in a `StaticKeySet`:

<!-- @formatter:off -->
```go
keySet, err := jwt.NewStaticKeySet(currentKey, previousKey)

verifier, err := jwt.NewVerifier(
	keySet,
	jwt.WithMethods(gojwt.SigningMethodPS256),
)
```
<!-- @formatter:on -->

> [!IMPORTANT]
> Named and anonymous keys cannot be mixed in the same `StaticKeySet`. A named set requires an exact `kid` match; tokens
> with a missing or unknown key ID are rejected.

### Custom Resolvers

Use `KeyResolverFunc` when keys are managed dynamically by application infrastructure such as an in-memory cache, a JWKS
provider, or an external key-management system:

<!-- @formatter:off -->
```go
resolver := jwt.KeyResolverFunc(
	func(ctx context.Context, header jwt.Header) (jwt.VerificationKey, error) {
		key, exists := trustedKeys[header.KeyID]
		if !exists {
			return jwt.VerificationKey{}, jwt.ErrUnknownKey
		}

		return key, nil
	},
)

verifier, err := jwt.NewVerifier(
	resolver,
	jwt.WithMethods(gojwt.SigningMethodPS256),
)
```
<!-- @formatter:on -->

The resolver receives parsed `alg`, `kid`, and `typ` values before signature verification. After a key is resolved, the
verifier still requires the token algorithm to be allowlisted and to match the signing method bound to the returned
`VerificationKey`.

> [!WARNING]
> Header values passed to a resolver are untrusted lookup inputs, not proof of authenticity. Do not use them for
> authorization or other security-sensitive decisions before verification succeeds.

## External Signing

Use `NewExternalSigningKey` when private key operations are delegated to an external service such as AWS KMS, Google
Cloud KMS, HashiCorp Vault, or an HSM:

<!-- @formatter:off -->
```go
signingKey, err := jwt.NewExternalSigningKey(
	"kms-key-2026-07",
	gojwt.SigningMethodEdDSA,
	publicKey,
	func(ctx context.Context, signingInput []byte) ([]byte, error) {
		return kmsClient.Sign(ctx, signingInput)
	},
)
if err != nil {
	return err
}

// Derive the matching verification key.
verificationKey := signingKey.VerificationKey()
```
<!-- @formatter:on -->

The callback receives the raw JWT signing input:

```text
base64url(header) + "." + base64url(claims)
```

It must return the raw signature bytes expected by the selected signing method. The module handles the final Base64URL
encoding and compact-token serialization.

The supplied public key is validated against the signing method and retained in the corresponding `VerificationKey`.

> [!IMPORTANT]
> Sign the provided input exactly once. Do not encode, reconstruct, or otherwise modify it. Hash it only when required
> by the contract between the selected signing method and the external signing backend.

## PEM and DER Keys

The module provides helpers for loading and serializing RSA, ECDSA, and Ed25519 key material in standard PEM and DER
formats.

### Key Parsing

Private keys can be parsed from PKCS#8, PKCS#1 RSA, and SEC1 ECDSA encodings:

<!-- @formatter:off -->
```go
privateKey, err := jwt.ParsePrivateKeyPEM(privateKeyPEM)
privateKey, err := jwt.ParsePrivateKeyDER(privateKeyDER)
```
<!-- @formatter:on -->

Public keys can be parsed from PKIX SubjectPublicKeyInfo, PKCS#1 RSA, and X.509 certificates:

<!-- @formatter:off -->
```go
publicKey, err := jwt.ParsePublicKeyPEM(publicKeyPEM)
publicKey, err := jwt.ParsePublicKeyDER(publicKeyDER)
```
<!-- @formatter:on -->

> [!NOTE]
> When an X.509 certificate is supplied, the helper extracts its public key without validating the certificate chain,
> validity period, hostname, or trust policy.

### Key Serialization

Private keys are serialized as unencrypted PKCS#8:

<!-- @formatter:off -->
```go
privateKeyPEM, err := jwt.MarshalPrivateKeyPEM(privateKey)
privateKeyDER, err := jwt.MarshalPrivateKeyDER(privateKey)
```
<!-- @formatter:on -->

Public keys are serialized as PKIX SubjectPublicKeyInfo:

<!-- @formatter:off -->
```go
publicKeyPEM, err := jwt.MarshalPublicKeyPEM(publicKey)
publicKeyDER, err := jwt.MarshalPublicKeyDER(publicKey)
```
<!-- @formatter:on -->

> [!IMPORTANT]
> These helpers do not decrypt encrypted or password-protected private keys. Decrypt protected key material before
> parsing it, or load the key through the application's key-management system.

> [!WARNING]
> Serialized private keys are returned unencrypted. Treat the resulting bytes as highly sensitive and never write them
> to logs, temporary files, or unprotected storage.

## Security Considerations

The module provides strict parsing and verification primitives, but the application remains responsible for the overall
token security model:

* **Prefer asymmetric signing across trust boundaries:** Use RSA, ECDSA, or Ed25519 when token issuers and verifiers
  have different privileges. Any service holding an HMAC secret can both verify and issue valid tokens.
* **Separate token classes:** Configure distinct issuer, audience, and token type policies for access tokens, refresh
  tokens, service credentials, and other token purposes. This prevents a valid token issued for one context from being
  accepted in another.
* **Rotate keys safely:** Distribute a new verification key before issuing tokens with the corresponding private key.
  Retain previous verification keys until every token signed with them has expired, including any configured leeway.
* **Distinguish verification from authorization:** Successful verification proves that the token is authentic and
  satisfies the configured policy. Application code must still determine whether the verified subject, roles, scopes,
  and permissions authorize the requested operation.

## License

Distributed under the repository's [MIT License](../LICENSE).