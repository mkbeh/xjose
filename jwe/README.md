# JWE

[![Go](https://github.com/mkbeh/xjose/actions/workflows/go.yml/badge.svg?branch=main)](https://github.com/mkbeh/xjose/actions/workflows/go.yml)
[![Go Reference](https://pkg.go.dev/badge/github.com/mkbeh/xjose/jwe.svg)](https://pkg.go.dev/github.com/mkbeh/xjose/jwe)
[![codecov](https://codecov.io/gh/mkbeh/xjose/branch/main/graph/badge.svg?flag=jwe)](https://codecov.io/gh/mkbeh/xjose)

Encrypt and decrypt arbitrary byte payloads using JSON Web Encryption (JWE) in Go.

The `jwe` module builds on [go-jose](https://github.com/go-jose/go-jose) and provides explicit key-management and
content-encryption algorithm allowlists, resolver-based key selection, Compact and multi-recipient JWE workflows,
Additional Authenticated Data (AAD), nested JWT orchestration, and configurable validation policies.

For complete runnable workflows, see the [examples](../examples) directory.

## Features

* **Compact JWE:** Encrypt arbitrary byte payloads for a single recipient using Compact JWE Serialization.
* **JWE JSON Serialization:** Use Flattened serialization for one recipient or General serialization for multiple
  recipients sharing the same ciphertext.
* **Algorithm policies:** Independently allowlist key-management (`alg`) and content-encryption (`enc`) algorithms
  through trusted application configuration.
* **Additional Authenticated Data:** Bind JWE JSON ciphertext to visible application context that is integrity-protected
  but not encrypted.
* **Key resolution:** Use static decryption keys or select application-managed keys through a custom `KeyResolver`.
* **Nested JWT:** Sign claims as an inner JWT, encrypt the signed token, then decrypt and verify both protection layers.
* **Header validation:** Enforce expected `typ`, `cty`, and compression parameters, and access application-specific
  header values after successful decryption.

## Installation

```shell
go get github.com/mkbeh/xjose/jwe
```

## Quick Start

This example encrypts a JSON document as Compact JWE using `RSA-OAEP-256` and `A256GCM`. The decrypter independently
allowlists both algorithms, requires the expected `typ` and `cty` protected headers, and returns the plaintext and
protected header only after successful decryption and authentication.

<!-- @formatter:off -->

```go
ctx := context.Background()

// Generate an RSA encryption key for the example.
// Load private keys from protected key storage in production.
privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
if err != nil {
	log.Fatalf("generate RSA key: %v", err)
}

// Create a reusable Compact JWE encrypter for the recipient.
encrypter, err := jwe.NewEncrypter(
	jose.Recipient{
		Algorithm: jose.RSA_OAEP_256,
		Key:       &privateKey.PublicKey,
		KeyID:     "encryption-2026-07",
	},
	jose.A256GCM,
	jwe.WithType("example+jwe"),
	jwe.WithContentType("application/json"),
)
if err != nil {
	log.Fatalf("create encrypter: %v", err)
}

plaintext := []byte(`{"document_id":"document-123","status":"approved"}`)

// Encrypt and serialize the plaintext as Compact JWE.
raw, err := encrypter.Encrypt(plaintext)
if err != nil {
	log.Fatalf("encrypt plaintext: %v", err)
}

// Define the trusted decryption policy independently of values carried by the JWE.
decrypter, err := jwe.NewDecrypter(
	privateKey,
	[]jose.KeyAlgorithm{
		jose.RSA_OAEP_256,
	},
	[]jose.ContentEncryption{
		jose.A256GCM,
	},
	jwe.WithType("example+jwe"),
	jwe.WithContentType("application/json"),
)
if err != nil {
	log.Fatalf("create decrypter: %v", err)
}

// Decrypt and authenticate the JWE.
decrypted, err := decrypter.DecryptToken(ctx, raw)
if err != nil {
	log.Fatalf("decrypt JWE: %v", err)
}

log.Printf(
	"protected key ID %q, plaintext %s",
	decrypted.Header.KeyID,
	decrypted.Plaintext,
)
```

<!-- @formatter:on -->

> [!NOTE]
> Public encryption keys do not require confidentiality, but their authenticity and intended usage must be protected
> during distribution. Private decryption keys must remain isolated within the recipient's trust boundary.

## Encryption and Decryption

JWE separates key management from content encryption:

* **Key management (`alg`)** determines how the Content Encryption Key (CEK) is encrypted, wrapped, or derived for a
  recipient.
* **Content encryption (`enc`)** determines how the CEK encrypts and authenticates the plaintext.

An `Encrypter` binds both algorithms to trusted configuration when it is created. A `Decrypter` independently
allowlists the accepted `alg` and `enc` values rather than trusting the algorithms declared by an incoming JWE.

<!-- @formatter:off -->

```go
// Configure Compact JWE encryption for one recipient.
encrypter, _ := jwe.NewEncrypter(
	jose.Recipient{
		Algorithm: jose.RSA_OAEP_256,
		Key:       publicKey,
		KeyID:     "encryption-2026-07",
	},
	jose.A256GCM,
	jwe.WithType("example+jwe"),
	jwe.WithContentType("application/json"),
)

// Configure the corresponding decryption policy.
decrypter, _ := jwe.NewDecrypter(
	privateKey,
	[]jose.KeyAlgorithm{
		jose.RSA_OAEP_256,
	},
	[]jose.ContentEncryption{
		jose.A256GCM,
	},
	jwe.WithType("example+jwe"),
	jwe.WithContentType("application/json"),
)
```

<!-- @formatter:on -->

### Decryption Methods

Both methods decrypt and authenticate the ciphertext, enforce the configured algorithm and header policies, and return
plaintext only when every check succeeds.

Use `Decrypt` when only the plaintext is needed:

```go
plaintext, _ := decrypter.Decrypt(ctx, raw)
```

Use `DecryptToken` when the application also needs the authenticated protected header:

```go
decrypted, _ := decrypter.DecryptToken(ctx, raw)

plaintext := decrypted.Plaintext
header := decrypted.Header
```

## Protected Headers

An `Encrypter` constructs the protected JWE header from trusted configuration:

* **`alg`** is derived from the recipient's key-management algorithm.
* **`enc`** is derived from the configured content-encryption algorithm.
* **`kid`** is included when the recipient has a non-empty key ID.
* **`typ`**, **`cty`**, and **`zip`** are included only when configured.

### Header Configuration

Use functional options to configure standard and application-specific protected parameters:

<!-- @formatter:off -->

```go
encrypter, _ := jwe.NewEncrypter(
	recipient,
	jose.A256GCM,
	jwe.WithType("example+jwe"),
	jwe.WithContentType("application/json"),
	jwe.WithHeader(jose.HeaderKey("tenant"), "acme"),
)
```

<!-- @formatter:on -->

`WithType` identifies the JWE object, while `WithContentType` describes the media type of the encrypted plaintext.
`WithHeader` adds an application-specific protected parameter.

When configured on a `Decrypter`, `WithType` and `WithContentType` require exact matches before plaintext is returned.
After successful Compact JWE decryption, application-specific protected parameters are available through
`Header.ExtraHeaders`.

> [!WARNING]
> JWE JSON Serialization may contain protected, shared unprotected, and recipient-specific unprotected parameters.
> `MultiDecrypted.Header` exposes a merged view of these values and does not retain the origin or protection status of
> each parameter. Use only parameters whose trust semantics are defined by the application, and do not treat arbitrary
> merged header values as authenticated input for authorization or access-control decisions.

## Key Management and Resolvers

`NewDecrypter` and `NewMultiDecrypter` use key material supplied directly through trusted application configuration. A
static decrypter does not use the JWE `kid` header to select among multiple keys.

Use the resolver-based constructors when decryption keys are selected dynamically, for example from an in-memory key
registry, a local cache, or application-managed key infrastructure:

* `NewDecrypterWithResolver` for Compact JWE;
* `NewMultiDecrypterWithResolver` for JWE JSON Serialization.

### Dynamic Key Resolution

For Compact JWE, the resolver receives the parsed protected header before ciphertext authentication. The decrypter
independently enforces the configured `alg`, `enc`, `typ`, and `cty` policies, so header values may be used only to
locate a candidate within an already trusted key registry.

<!-- @formatter:off -->

```go
resolver := jwe.KeyResolverFunc(
	func(ctx context.Context, header jwe.Header) (any, error) {
		key, exists := decryptionKeys[header.KeyID]
		if !exists {
			return nil, fmt.Errorf(
				"unknown decryption key %q",
				header.KeyID,
			)
		}

		// Bind the selected key record to the declared key-management algorithm.
		if key.Algorithm != header.Algorithm {
			return nil, fmt.Errorf(
				"decryption key %q does not permit algorithm %q",
				header.KeyID,
				header.Algorithm,
			)
		}

		return key.Material, nil
	},
)

decrypter, _ := jwe.NewDecrypterWithResolver(
	resolver,
	[]jose.KeyAlgorithm{
		jose.RSA_OAEP_256,
	},
	[]jose.ContentEncryption{
		jose.A256GCM,
	},
)
```

<!-- @formatter:on -->

For General JWE JSON Serialization, recipient-specific `alg` and `kid` values are not available when the resolver is
called. The resolver receives only the shared header and returns one candidate key, which the decrypter then tries
against the recipient entries. Flattened JWE may expose its single recipient's `alg` and `kid` during resolution.

> [!WARNING]
> Header values passed to a resolver are untrusted lookup inputs until decryption and authentication succeed. Map them
> only to application-controlled key records, and never treat `kid`, `alg`, or other header parameters as proof of
> sender identity, key ownership, or authorization.

## Multiple Recipients

`MultiEncrypter` encrypts the plaintext once with a shared Content Encryption Key (CEK), then protects that CEK
independently for each recipient.

The serialization format depends on the number of recipients:

* **One recipient:** Flattened JWE JSON Serialization.
* **Multiple recipients:** General JWE JSON Serialization.

All recipients share the protected header, IV, ciphertext, authentication tag, and optional Additional Authenticated
Data (AAD). Each recipient entry contains its own key-management algorithm (`alg`), encrypted key, and optional key ID
(`kid`).

### Encryption and Decryption

Encrypt one plaintext for multiple recipients:

<!-- @formatter:off -->

```go
encrypter, _ := jwe.NewMultiEncrypter(
	[]jose.Recipient{
		{
			Algorithm: jose.RSA_OAEP_256,
			Key:       ordersPublicKey,
			KeyID:     "orders-2026-07",
		},
		{
			Algorithm: jose.RSA_OAEP_256,
			Key:       billingPublicKey,
			KeyID:     "billing-2026-07",
		},
	},
	jose.A256GCM,
	jwe.WithType("example+jwe"),
	jwe.WithContentType("application/json"),
	jwe.WithHeader(jose.HeaderKey("keyset"), "encryption-2026-07"),
)

raw, _ := encrypter.Encrypt(plaintext)
```

<!-- @formatter:on -->

Each recipient can decrypt the shared ciphertext with its corresponding private key:

<!-- @formatter:off -->

```go
decrypter, _ := jwe.NewMultiDecrypter(
	billingPrivateKey,
	[]jose.KeyAlgorithm{
		jose.RSA_OAEP_256,
	},
	[]jose.ContentEncryption{
		jose.A256GCM,
	},
	jwe.WithType("example+jwe"),
	jwe.WithContentType("application/json"),
)

decrypted, _ := decrypter.DecryptToken(ctx, raw)
```

<!-- @formatter:on -->

`MultiDecrypted.RecipientIndex` reports the position of the recipient entry that was successfully decrypted. The index
is positional metadata only; recipient order does not imply preference, priority, or trust.

### Resolver Semantics

For General JWE JSON Serialization, `NewMultiDecrypterWithResolver` invokes the resolver before a recipient has been
selected. The resolver therefore receives only the shared header; recipient-specific `alg` and `kid` values are not
available at that stage.

When dynamic key selection requires a routing hint, place an application-defined value in the shared protected header
and resolve it against application-controlled key records:

<!-- @formatter:off -->

```go
resolver := jwe.KeyResolverFunc(
	func(_ context.Context, header jwe.Header) (any, error) {
		// General JWE does not expose recipient-specific kid values
		// before recipient selection. Use a shared protected parameter
		// as an application-controlled routing hint instead.
		keySetID, ok := header.ExtraHeaders[jose.HeaderKey("keyset")].(string)
		if !ok || keySetID == "" {
			return nil, errors.New("missing keyset header")
		}

		// Resolve the routing hint only within a trusted local registry.
		// The header value is not proof of key ownership or authenticity.
		key, exists := decryptionKeys[keySetID]
		if !exists {
			return nil, fmt.Errorf(
				"unknown decryption key set %q",
				keySetID,
			)
		}

		// MultiDecrypter will try this candidate against the recipient
		// entries until one successfully authenticates the ciphertext.
		return key, nil
	},
)

// Configure the algorithms and protected headers accepted independently
// from values supplied by the incoming JWE.
decrypter, _ := jwe.NewMultiDecrypterWithResolver(
	resolver,
	[]jose.KeyAlgorithm{
		jose.RSA_OAEP_256,
	},
	[]jose.ContentEncryption{
		jose.A256GCM,
	},
	jwe.WithType("example+jwe"),
	jwe.WithContentType("application/json"),
)
```

<!-- @formatter:on -->

The resolver returns one private or symmetric candidate key. The decrypter tries that key against the recipient entries
until one entry successfully decrypts and authenticates the ciphertext.

For Flattened JWE JSON Serialization, the single recipient's `alg` and `kid` values may already be available to the
resolver.

> [!IMPORTANT]
> Do not use `Header.KeyID` for recipient selection in General multi-recipient JWE. Use shared protected metadata or an
> out-of-band key-selection strategy defined by the application.

## Additional Authenticated Data

Additional Authenticated Data (AAD) binds JWE JSON Serialization to application context such as a tenant ID, resource
identifier, or request scope. The value is authenticated together with the ciphertext but is not encrypted.

AAD provides context binding only when the application compares the decrypted value with an independently obtained
expected value.

> [!NOTE]
> External AAD is available only with JWE JSON Serialization. Compact JWE does not have a separate AAD field.

### Encrypting with AAD

Do not place secrets in AAD because its encoded value is included in the serialized JWE:

<!-- @formatter:off -->

```go
authData := []byte("tenant=acme;record=document-123")

raw, _ := encrypter.EncryptWithAuthData(plaintext, authData)
```

<!-- @formatter:on -->

### Validating Authenticated Context

After successful decryption and authentication, the AAD is available through `MultiDecrypted.AuthData`:

<!-- @formatter:off -->

```go
if !bytes.Equal(decrypted.AuthData, expectedAuthData) {
	return errors.New("unexpected authenticated context")
}
```

<!-- @formatter:on -->

Use a stable and unambiguous byte encoding for AAD. Differences in field order, whitespace, casing, or serialization
produce different authenticated values even when the underlying data is semantically equivalent.

## Nested JWT

`NestedIssuer` and `NestedVerifier` implement the **sign-then-encrypt** pattern using a Compact JWT inside a Compact
JWE:

```text
Claims
  → Sign as Compact JWT
  → Encrypt as Compact JWE
  → Decrypt and authenticate the JWE
  → Verify the JWT signature and claims
```

The outer JWE provides confidentiality and integrity for the intended recipient. The inner JWT authenticates the signed
claims under the configured verification key and remains independently verifiable after the encryption layer is removed.

### Nested Token Flow

The protected JWE header must identify its plaintext as a JWT by setting `cty=JWT`. Both the encrypter and decrypter
must be configured with this content type.

<!-- @formatter:off -->

```go
encrypter, _ := jwe.NewEncrypter(
	encryptionRecipient,
	jose.A256GCM,
	jwe.WithContentType("JWT"),
)

decrypter, _ := jwe.NewDecrypter(
	encryptionPrivateKey,
	[]jose.KeyAlgorithm{
		jose.RSA_OAEP_256,
	},
	[]jose.ContentEncryption{
		jose.A256GCM,
	},
	jwe.WithContentType("JWT"),
)

// Compose the JWT signing and JWE encryption layers.
issuer, _ := jwe.NewNestedIssuer(jwtSigner, encrypter)

verifier, _ := jwe.NewNestedVerifier(decrypter, jwtVerifier)

// Sign the claims, then encrypt the resulting Compact JWT.
raw, _ := issuer.Issue(ctx, claims)

// Decrypt the JWE, verify the inner JWT, and decode its claims.
verifiedClaims := new(AccessClaims)
headers, _ := verifier.VerifyToken(ctx, raw, verifiedClaims)
```

<!-- @formatter:on -->

`NestedVerifier` decrypts and authenticates the outer JWE before passing its plaintext to the JWT verifier. Claims and
headers are returned only after both cryptographic layers and every configured JWE and JWT policy succeed.

## Security Considerations

The module provides encryption, decryption, and validation primitives, but the application remains responsible for the
complete message security model:

* **Do not treat encryption as sender authentication:** JWE provides confidentiality and ciphertext integrity for the
  intended recipient, but does not establish who created the message. Use sign-then-encrypt, such as Nested JWT, when
  the sender or issuer must be authenticated.
* **Keep algorithm policies narrow:** Allow only the key-management (`alg`) and content-encryption (`enc`) algorithms
  required by the application.
* **Separate signing and encryption keys:** Signing and encryption have different cryptographic purposes, trust
  boundaries, and rotation lifecycles. Reusing key material increases the impact of compromise and misuse.
* **Use resolver inputs only for candidate selection:** Protected header values are not authenticated until decryption
  succeeds. Unprotected header values are never authenticated. Resolve them only against application-controlled key
  records.
* **Process plaintext only after successful authentication:** Do not parse, deserialize, or act on plaintext unless
  decryption and ciphertext authentication complete successfully.
* **Interpret JWE JSON headers carefully:** JWE JSON Serialization may contain protected, shared unprotected, and
  recipient-specific unprotected parameters. Because `MultiDecrypted.Header` exposes a merged view, do not use arbitrary
  `ExtraHeaders` values for authorization or other security-sensitive decisions.
* **Validate AAD against independent context:** AAD is authenticated but not encrypted. Reading it from the JWE does not
  establish context binding by itself; compare it with an expected value obtained independently by the application.
* **Use compression only when required:** Compression can reveal information through ciphertext length when secret data
  is combined with attacker-controlled input.
* **Coordinate key rotation:** Distribute new public encryption keys before senders begin using them. Retain previous
  private keys for as long as ciphertext encrypted for those keys may still be accepted.
* **Implement replay protection separately:** JWE does not provide freshness, uniqueness, or one-time-use guarantees.
  Enforce timestamps, nonces, identifiers, or replay caches at the application layer when required.

> [!NOTE]
> Critical JOSE extensions declared through `crit` are not supported and are rejected during parsing. Do not depend on
> critical extensions when interoperating with this module.

## License

Distributed under the repository's [MIT License](../LICENSE).