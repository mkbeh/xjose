# JWT

[![Go](https://github.com/mkbeh/xjose/actions/workflows/go.yml/badge.svg?branch=main)](https://github.com/mkbeh/xjose/actions/workflows/go.yml)
[![Go Reference](https://pkg.go.dev/badge/github.com/mkbeh/xjose/jwt.svg)](https://pkg.go.dev/github.com/mkbeh/xjose/jwt)
[![codecov](https://codecov.io/gh/mkbeh/xjose/branch/main/graph/badge.svg?flag=jwt)](https://codecov.io/gh/mkbeh/xjose)

Secure, typed helpers for signing and verifying compact JSON Web Tokens in Go.

The `jwt` module builds on [golang-jwt/jwt](https://github.com/golang-jwt/jwt) and provides a high-level API for issuing
and verifying signed tokens with structured, application-defined claims. It combines explicit key types, algorithm
allowlists, resolver-based key selection, external signing support, and configurable validation policies.

For complete runnable workflows, see the [examples](../examples) directory.

## Features

* **Strict verification:** Require explicit algorithm allowlists, validate expiration by default, and reject malformed
  Compact JWTs.
* **Algorithm-bound keys:** Bind signing and verification keys to their expected algorithms so an untrusted `alg` header
  cannot select how key material is used.
* **Flexible key resolution:** Use static keys, local key sets, or custom resolvers for trusted `kid`-based key
  selection and rotation.
* **Configurable validation:** Enforce issuer (`iss`), audience (`aud`), subject (`sub`), token type (`typ`),
  issued-at (`iat`), not-before (`nbf`), lifetime, and age policies.
* **Application-defined claims:** Decode tokens into custom claim structures compatible with the upstream `jwt.Claims`
  interface.
* **External signing:** Integrate KMS, HashiCorp Vault, HSMs, remote signing services, and other application-managed
  signing backends.
* **Key parsing helpers:** Import RSA, ECDSA, and Ed25519 key material from PEM and DER encodings.

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

// Sign and serialize the Compact JWT.
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
signer, _ := jwt.NewSigner(
	signingKey,
	jwt.WithType("access+jwt"),
	jwt.WithMaxTokenSize(32 << 10),
)

token, _ := signer.Sign(ctx, claims)
```

<!-- @formatter:on -->

`WithMaxTokenSize` limits the resulting compact token. Signing fails when the serialized token exceeds the configured
bound; keep this limit as small as practical for the claims issued by the application.

## Verification

Verification is controlled by trusted application configuration rather than token-supplied algorithm or key metadata.

A `Verifier` combines:

* a trusted `KeyResolver`;
* a mandatory algorithm allowlist configured with `WithMethods`;
* optional claim and token-type validation policies.

Both `VerificationKey` and `StaticKeySet` implement `KeyResolver` and can be passed directly to `NewVerifier`.

### Verification Methods

Both verification methods validate the signature, apply the configured policy, and decode the claims.

Use `Verify` when only the verified claims are needed:

<!-- @formatter:off -->

```go
claims := new(AccessClaims)

err := verifier.Verify(ctx, token, claims)
```

<!-- @formatter:on -->

Use `VerifyToken` when the application also needs the verified `alg`, `kid`, and `typ` header values:

<!-- @formatter:off -->

```go
claims := new(AccessClaims)

header, _ := verifier.VerifyToken(ctx, token, claims)
```

<!-- @formatter:on -->

Pass a fresh, non-nil claims value to each verification call. Claims may be partially populated when verification fails
and should not be shared concurrently between calls.

> [!IMPORTANT]
> Token headers are untrusted until verification succeeds. A custom `KeyResolver` may use `alg`, `kid`, and `typ` only
> as candidate-key selectors. They must not be treated as authenticated metadata or used for authorization before
> verification completes.

## Validation Policy

A `Verifier` enforces a strict validation baseline and can apply additional application-specific claim and token-type
policies.

### Secure Defaults

Verification starts from a fail-closed baseline:

* **Explicit algorithms:** `WithMethods` is required, and tokens using any other signing method are rejected.
* **Strict parsing:** Malformed Compact JWTs and invalid Base64URL segments are rejected.
* **Bounded input:** Tokens exceeding the configured maximum size are rejected before parsing and cryptographic
  verification.
* **Required expiration:** Every token must contain a valid `exp` claim unless this requirement is explicitly disabled.
* **Temporal validation:** The `exp` claim is always validated, and `nbf` is validated when present.

Application-specific trust requirements—including issuer, audience, subject, token type, and whether `iat` or `nbf` must
be present—are not inferred automatically and should be configured explicitly.

### Policy Configuration

Verifier options are combined into a single validation policy. A token is accepted only when its signature is valid and
every baseline and application-defined constraint succeeds.

The following configuration is suitable for short-lived access tokens issued by a known authority:

<!-- @formatter:off -->

```go
verifier, _ := jwt.NewVerifier(
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

### Policy Interactions

* **Audience:** `WithAudience` requires at least one configured audience to match. `WithAllAudiences` requires every
  configured audience to be present.
* **Issued at (`iat`):** `ValidateIssuedAt` validates `iat` when present. `RequireIssuedAt` also rejects tokens that
  omit it.
* **Not before (`nbf`):** The verifier validates `nbf` when present. `RequireNotBefore` also rejects tokens that omit
  it.
* **Duration limits:** `WithMaxLifetime` restricts the declared lifetime `exp - iat`, while `WithMaxTokenAge` restricts
  the elapsed age `now - iat`.
* **Leeway:** `WithLeeway` applies to expiration, not-before, issued-at, and token-age validation. It does not extend
  the maximum lifetime permitted by `WithMaxLifetime`.

> [!IMPORTANT]
> `WithMaxLifetime` and `WithMaxTokenAge` do not require an `iat` claim on their own. Combine them with
> `RequireIssuedAt` when tokens without an issuance timestamp must be rejected.

> [!WARNING]
> Expiration is required and validated by default. Use `AllowMissingExpiration` only when compatibility with
> non-expiring tokens is explicitly required.

## Key Management and Resolvers

A Verifier uses a KeyResolver to select a verification key from trusted keys managed by the application.. Both
`VerificationKey` and `StaticKeySet` implement this interface and can be passed directly to `NewVerifier`.

### Static Keys

Use a single named key when the verifier trusts one signing key:

<!-- @formatter:off -->

```go
verificationKey, _ := jwt.NewVerificationKey(
	"key-2026-07",
	gojwt.SigningMethodPS256,
	publicKey,
)

verifier, _ := jwt.NewVerifier(
	verificationKey,
	jwt.WithMethods(gojwt.SigningMethodPS256),
)
```

<!-- @formatter:on -->

A named `VerificationKey` accepts only tokens containing the same `kid`. To accept only tokens without a `kid`, create
an anonymous key by passing an empty key ID:

<!-- @formatter:off -->

```go
anonymousKey, _ := jwt.NewVerificationKey(
	"",
	gojwt.SigningMethodPS256,
	publicKey,
)
```

<!-- @formatter:on -->

For local key rotation, place the active and recently retired named keys in a `StaticKeySet`:

<!-- @formatter:off -->

```go
keySet, _ := jwt.NewStaticKeySet(currentKey, previousKey)

verifier, _ := jwt.NewVerifier(
	keySet,
	jwt.WithMethods(gojwt.SigningMethodPS256),
)
```

<!-- @formatter:on -->

> [!IMPORTANT]
> Named and anonymous keys cannot be mixed in the same `StaticKeySet`. A set of named keys requires an exact `kid`
> match; tokens with a missing or unknown key ID are rejected.

### Custom Resolvers

Use `KeyResolverFunc` when verification keys are obtained from application-managed infrastructure such as an in-memory
cache, a local JWKS source, or a custom key service:

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

verifier, _ := jwt.NewVerifier(
	resolver,
	jwt.WithMethods(gojwt.SigningMethodPS256),
)
```

<!-- @formatter:on -->

The resolver receives the parsed `alg`, `kid`, and `typ` header values before signature verification and may use them
only to locate a candidate key. After resolution, the verifier still requires the token algorithm to be allowlisted and
to match the signing method bound to the returned `VerificationKey`.

> [!WARNING]
> Header values passed to a resolver are untrusted lookup inputs. Do not treat them as authenticated metadata or use
> them for authorization or other security-sensitive decisions before verification succeeds.

## External Signing

Use `NewExternalSigningKey` when private key operations are delegated to an external service such as AWS KMS, Google
Cloud KMS, HashiCorp Vault, or an HSM:

<!-- @formatter:off -->

```go
signingKey, _ := jwt.NewExternalSigningKey(
	"kms-key-2026-07",
	gojwt.SigningMethodEdDSA,
	publicKey,
	func(ctx context.Context, signingInput []byte) ([]byte, error) {
		return kmsClient.Sign(ctx, signingInput)
	},
)

// Obtain the corresponding verification key.
verificationKey := signingKey.VerificationKey()
```

<!-- @formatter:on -->

The callback receives the complete JWT signing input:

```text
base64url(header) + "." + base64url(claims)
```

It is responsible for invoking the external signing backend according to the selected signing method and returning the
signature bytes in the format expected by JWT. The module applies the final Base64URL encoding and constructs the
Compact JWT.

The supplied public key is bound to the signing method and retained in the corresponding `VerificationKey`.

> [!IMPORTANT]
> Pass the signing input to the external backend without re-encoding or reconstructing it. Apply hashing only when
> required by the selected signing method and backend contract, and convert provider-specific signature formats before
> returning them to the module.

## PEM and DER Keys

The module provides helpers for loading and serializing RSA, ECDSA, and Ed25519 key material in standard PEM and DER
formats.

### Key Parsing

Private keys can be parsed from PKCS#8, PKCS#1 RSA, and SEC1 ECDSA encodings:

<!-- @formatter:off -->
```go
privateKey, _ := jwt.ParsePrivateKeyPEM(privateKeyPEM)
privateKey, _ := jwt.ParsePrivateKeyDER(privateKeyDER)
```
<!-- @formatter:on -->

Public keys can be parsed from PKIX SubjectPublicKeyInfo, PKCS#1 RSA, and X.509 certificates:

<!-- @formatter:off -->
```go
publicKey, _ := jwt.ParsePublicKeyPEM(publicKeyPEM)
publicKey, _ := jwt.ParsePublicKeyDER(publicKeyDER)
```
<!-- @formatter:on -->

> [!NOTE]
> When an X.509 certificate is supplied, the helper extracts its public key without validating the certificate chain,
> validity period, hostname, or trust policy.

### Key Serialization

Private keys are serialized as unencrypted PKCS#8:

<!-- @formatter:off -->
```go
privateKeyPEM, _ := jwt.MarshalPrivateKeyPEM(privateKey)
privateKeyDER, _ := jwt.MarshalPrivateKeyDER(privateKey)
```
<!-- @formatter:on -->

Public keys are serialized as PKIX SubjectPublicKeyInfo:

<!-- @formatter:off -->
```go
publicKeyPEM, _ := jwt.MarshalPublicKeyPEM(publicKey)
publicKeyDER, _ := jwt.MarshalPublicKeyDER(publicKey)
```
<!-- @formatter:on -->

> [!IMPORTANT]
> These helpers do not decrypt encrypted or password-protected private keys. Decrypt protected key material before
> parsing it, or load the key through the application's key-management system.

> [!WARNING]
> Serialized private keys are returned unencrypted. Treat the resulting bytes as highly sensitive and never write them
> to logs, temporary files, or unprotected storage.

## Security Considerations

The module provides strict parsing, signature verification, and validation primitives, but the application remains
responsible for defining and enforcing the complete token security model:

* **Prefer asymmetric signing across trust boundaries:** Use RSA, ECDSA, or Ed25519 when issuers and verifiers have
  different privileges. Any service that holds an HMAC secret can both verify and issue valid tokens.
* **Separate token classes:** Configure distinct issuer, audience, and token-type policies for access tokens, refresh
  tokens, service credentials, and other token purposes. This prevents a token issued for one context from being
  accepted in another.
* **Rotate keys safely:** Distribute a new verification key before issuing tokens with the corresponding private key.
  Retain previous verification keys until all tokens signed with them have expired, including any configured leeway.
* **Separate verification from authorization:** Successful verification establishes that the token was signed with a
  trusted key and satisfies the configured policy. Application code must still decide whether the verified subject,
  roles, scopes, and permissions authorize the requested operation.

## License

Distributed under the repository's [MIT License](../LICENSE).