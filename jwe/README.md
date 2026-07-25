# JWE

Secure helpers for encrypting and decrypting arbitrary byte payloads with JSON Web Encryption (JWE) in Go.

The `jwe` module builds on [go-jose](https://github.com/go-jose/go-jose) and adds strict algorithm allowlists,
resolver-based key selection, multi-recipient encryption, Additional Authenticated Data, nested JWT orchestration, and
configurable resource limits.

For complete runnable examples, see the [examples](../examples) directory.

## Features

* **Compact JWE:** Encrypt arbitrary plaintext for a single recipient using Compact JWE Serialization.
* **Multiple recipients:** Encrypt one shared ciphertext for multiple recipients using Flattened or General JWE JSON
  Serialization.
* **Strict decryption policies:** Independently allowlist key-management (`alg`) and content-encryption (`enc`)
  algorithms rather than trusting values supplied by the JWE.
* **Additional Authenticated Data:** Cryptographically bind JWE JSON ciphertext to visible application context without
  encrypting that context.
* **Nested JWT:** Sign claims as an inner JWT, encrypt the signed token, then decrypt and verify both protection layers.
* **Flexible key resolution:** Select static decryption keys or integrate application-managed key stores through a
  custom `KeyResolver`.
* **Protected header policies:** Require expected `typ` and `cty` values, control compression, and expose
  application-specific header parameters after successful decryption.
* **Resource limits:** Bound serialized JWE size and plaintext size before encryption and after decryption or
  decompression.

## Installation

```shell
go get github.com/mkbeh/xjose/jwe
```

## Quick Start

This example encrypts a JSON document with `RSA-OAEP-256` and `A256GCM`, then validates the configured algorithms, token
type, and content type before returning the authenticated protected header and plaintext.

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

// Define the trusted decryption policy independently from JWE headers.
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

// Authenticate the JWE and return its protected header and plaintext.
decrypted, err := decrypter.DecryptToken(ctx, raw)
if err != nil {
	log.Fatalf("decrypt JWE: %v", err)
}

log.Printf(
	"authenticated header key ID %q and plaintext %s",
	decrypted.Header.KeyID,
	decrypted.Plaintext,
)
````

<!-- @formatter:on -->

> [!NOTE]
> Public encryption keys may be distributed to senders through trusted configuration or key-distribution channels.
> Private decryption keys must remain isolated within the recipient's trust boundary.

## Encryption and Decryption

JWE uses two independent cryptographic layers:

* **Key management (`alg`):** Configured through `jose.Recipient.Algorithm`; protects or derives the Content Encryption
  Key (CEK).
* **Content encryption (`enc`):** Passed separately to the constructor; encrypts and authenticates the plaintext with
  the CEK.

An `Encrypter` fixes both algorithms when it is created. A `Decrypter` accepts them only through explicit allowlists
defined by trusted application configuration.

<!-- @formatter:off -->
```go
// Configure Compact JWE encryption for one recipient.
encrypter, err := jwe.NewEncrypter(
	jose.Recipient{
		Algorithm: jose.RSA_OAEP_256,
		Key:       publicKey,
		KeyID:     "encryption-2026-07",
	},
	jose.A256GCM,
	jwe.WithType("example+jwe"),
	jwe.WithContentType("application/json"),
)

// Allow only the expected algorithms and protected headers.
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
````

<!-- @formatter:on -->

### Decryption Methods

Both methods authenticate the ciphertext and enforce all configured algorithm and header policies before returning
plaintext.

Use `Decrypt` when only the authenticated plaintext is required:

```go
plaintext, err := decrypter.Decrypt(ctx, raw)
```

Use `DecryptToken` when the application also needs the authenticated protected JWE header:

```go
decrypted, err := decrypter.DecryptToken(ctx, raw)
```

Use `WithMaxTokenSize` and `WithMaxPlaintextSize` to adjust resource limits. The plaintext limit is enforced before
encryption and after decryption or decompression, bounding both direct payload size and compression expansion.

## Protected Headers

An `Encrypter` constructs the protected JWE header from trusted configuration:

* **`alg`** is derived from the recipient's key-management algorithm.
* **`enc`** is derived from the configured content-encryption algorithm.
* **`kid`** is included when the recipient has a non-empty key ID.
* **`typ`**, **`cty`**, and **`zip`** are included only when configured explicitly.

### Header Configuration

Use functional options to add standard or application-specific protected parameters:

<!-- @formatter:off -->
```go
encrypter, err := jwe.NewEncrypter(
	recipient,
	jose.A256GCM,
	jwe.WithType("example+jwe"),
	jwe.WithContentType("application/json"),
	jwe.WithHeader(jose.HeaderKey("tenant"), "acme"),
)
````

<!-- @formatter:on -->

`WithType` identifies the JWE object, while `WithContentType` describes the media type of its plaintext.
`WithHeader` adds application-specific protected parameters.

When configured on a `Decrypter`, `WithType` and `WithContentType` require exact matches against the protected JWE
header. After successful Compact JWE decryption, custom protected parameters are available through
`Header.ExtraHeaders`.

> [!WARNING]
> JWE JSON Serialization can contain protected, shared unprotected, and recipient-specific unprotected parameters.
> `MultiDecrypted.Header` returns a merged view and does not preserve the origin or protection status of each field.
> Do not use arbitrary merged header values for authorization or access-control decisions.

## Key Management and Resolvers

`NewDecrypter` and `NewMultiDecrypter` use a single private or symmetric key selected by trusted application
configuration.

Use a custom `KeyResolver` when decryption requires dynamic key selection, such as key rotation, multiple key versions,
or metadata-based routing.

For Compact JWE, the decrypter validates the configured algorithm and protected-header policies before invoking the
resolver. The parsed header remains untrusted until ciphertext authentication and decryption succeed.

### Resolution by `kid`

A static decrypter does not use the protected `kid` value to select among multiple keys. Use `KeyResolverFunc` when key
selection must be driven by an application-controlled key ID:

<!-- @formatter:off -->
```go
resolver := jwe.KeyResolverFunc(
	func(ctx context.Context, header jwe.Header) (any, error) {
		key, exists := decryptionKeys[header.KeyID]
		if !exists || key.Algorithm != header.Algorithm {
			return nil, fmt.Errorf("unknown decryption key %q", header.KeyID)
		}
		return key.Material, nil
	},
)

decrypter, err := jwe.NewDecrypterWithResolver(
	resolver,
	[]jose.KeyAlgorithm{
		jose.RSA_OAEP_256,
	},
	[]jose.ContentEncryption{
		jose.A256GCM,
	},
)
````
<!-- @formatter:on -->

> [!WARNING]
> Header values passed to a resolver are untrusted lookup inputs. Map them to application-controlled key records before
> returning key material, and never treat `kid`, `alg`, or other metadata as proof of sender identity or authenticity.

## Multiple Recipients

`MultiEncrypter` encrypts the plaintext once with a shared Content Encryption Key (CEK), then protects that CEK
independently for each recipient.

The serialization format is selected automatically:

* **One recipient:** Flattened JWE JSON Serialization.
* **Multiple recipients:** General JWE JSON Serialization.

All recipients share the protected header, IV, ciphertext, authentication tag, and optional Additional Authenticated
Data. Each recipient has its own key-management algorithm (`alg`), encrypted key, and optional key ID (`kid`).

### Multi-Recipient Flow

Encrypt the shared plaintext for multiple recipients:

<!-- @formatter:off -->
```go
encrypter, err := jwe.NewMultiEncrypter(
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
	jwe.WithHeader(
		jose.HeaderKey("keyset"),
		"encryption-2026-07",
	),
)

raw, err := encrypter.Encrypt(plaintext)
````

<!-- @formatter:on -->

Each intended recipient can decrypt the shared ciphertext using its own private key:

<!-- @formatter:off -->

```go
decrypter, err := jwe.NewMultiDecrypter(
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

decrypted, err := decrypter.DecryptToken(ctx, raw)
```

<!-- @formatter:on -->

`MultiDecrypted.RecipientIndex` identifies the recipient entry that successfully decrypted the shared ciphertext.

> [!NOTE]
> Recipient order does not indicate key preference, trust level, or which key version is current.

### Resolver Semantics

For General JWE with multiple recipients, `NewMultiDecrypterWithResolver` invokes the resolver before a recipient is
selected. At that point, the resolver receives the shared JWE header, while recipient-specific `alg` and `kid` values
are
not available.

Use a shared protected application parameter when key selection requires an application-controlled routing hint:

<!-- @formatter:off -->
```go
keySetID, ok := header.ExtraHeaders[jose.HeaderKey("keyset")].(string)
if !ok {
	return nil, errors.New("missing keyset header")
}
```
<!-- @formatter:on -->

The resolver returns one concrete private or symmetric key. The decrypter tries that key against the recipient entries
until one successfully authenticates the ciphertext.

For Flattened JWE with a single recipient, recipient-specific `alg` and `kid` values may already be available to the
resolver.

> [!IMPORTANT]
> Do not rely on `Header.KeyID` to select a recipient in General multi-recipient JWE. Use shared protected metadata or
> an
> out-of-band key-selection strategy controlled by the application.

## Additional Authenticated Data

Additional Authenticated Data (AAD) cryptographically binds JWE JSON Serialization to visible external context, such as
a tenant ID, resource identifier, or request scope, without encrypting that context.

Context binding is effective only when the decrypted AAD is compared with an expected value obtained independently by
the application.

> [!NOTE]
> External AAD is supported only by JWE JSON Serialization. Compact JWE does not provide a separate AAD field.

### Encrypting with AAD

AAD is authenticated but remains visible in the serialized JWE, so it must not contain secrets.

<!-- @formatter:off -->
```go
authData := []byte("tenant=acme;record=document-123")
raw, err := encrypter.EncryptWithAuthData(plaintext, authData)
````

<!-- @formatter:on -->

### Validating Authenticated Context

After successful decryption, the authenticated value is available through `MultiDecrypted.AuthData`:

<!-- @formatter:off -->
```go
if !bytes.Equal(decrypted.AuthData, expectedAuthData) {
	return errors.New("unexpected authenticated context")
}
```
<!-- @formatter:on -->

Use a stable, unambiguous encoding for AAD. Differences in field order, whitespace, casing, or byte representation
produce
different authenticated values even when they appear semantically equivalent.

## Nested JWT

`NestedIssuer` and `NestedVerifier` implement the **sign-then-encrypt** pattern for compact JWTs:

```text
Claims
  → Sign as Compact JWT
  → Encrypt as Compact JWE
  → Authenticate and decrypt JWE
  → Verify JWT signature and claims
````

The outer JWE provides confidentiality and ciphertext integrity for the intended recipient. The inner JWT authenticates
the issuer and continues to protect the claims after the encrypted layer has been removed.

### Nested Token Flow

The outer JWE must identify its plaintext as a JWT by setting `cty=JWT`.

<!-- @formatter:off -->

```go
encrypter, err := jwe.NewEncrypter(
	encryptionRecipient,
	jose.A256GCM,
	jwe.WithContentType("JWT"),
)

decrypter, err := jwe.NewDecrypter(
	encryptionPrivateKey,
	[]jose.KeyAlgorithm{
		jose.RSA_OAEP_256,
	},
	[]jose.ContentEncryption{
		jose.A256GCM,
	},
	jwe.WithContentType("JWT"),
)

// Compose the signing and encryption layers.
issuer, err := jwe.NewNestedIssuer(jwtSigner, encrypter)

verifier, err := jwe.NewNestedVerifier(decrypter, jwtVerifier)

// Issue and verify the nested token.
raw, err := issuer.Issue(ctx, claims)

verifiedClaims := new(AccessClaims)
verified, err := verifier.VerifyToken(ctx, raw, verifiedClaims)
```

<!-- @formatter:on -->

`NestedVerifier` authenticates and decrypts the outer JWE before passing its plaintext to the JWT verifier. The inner
claims are returned only after both cryptographic layers and all configured policies succeed.

## Security Considerations

The module provides strict encryption and decryption primitives, but the application remains responsible for the
overall message security model:

* **Do not confuse encryption with sender authentication:** JWE provides confidentiality and ciphertext integrity for
  the intended recipient, but does not prove who created the message. Use sign-then-encrypt, such as Nested JWT, when
  authenticated origin is required.
* **Keep algorithm allowlists narrow:** Configure only the key-management (`alg`) and content-encryption (`enc`)
  algorithms required by the application.
* **Separate signing and encryption keys:** These operations serve different cryptographic roles, trust boundaries, and
  rotation policies. Reusing the same key material increases the impact of compromise.
* **Process only authenticated plaintext:** Do not parse, deserialize, or act on plaintext until decryption and
  authentication complete successfully.
* **Treat resolver inputs as untrusted:** JWE headers are unauthenticated before decryption succeeds. Use them only to
  select candidate keys from application-controlled records.
* **Handle JSON headers carefully:** Multi-recipient JWE can contain protected, shared unprotected, and
  recipient-specific unprotected parameters. Do not use arbitrary merged `ExtraHeaders` values for authorization.
* **Validate AAD against independent context:** Reading AAD from the JWE does not establish context binding by itself.
  Compare it with an expected value obtained independently by the application.
* **Use compression carefully:** Compression can leak information through ciphertext length when secrets are combined
  with attacker-controlled input.
* **Rotate keys safely:** Distribute new public encryption keys before senders begin using them, and retain previous
  private keys while ciphertext encrypted for those versions may still arrive.
* **Implement replay protection separately:** JWE does not provide timestamps, uniqueness tracking, or one-time-use
  enforcement. Apply freshness and replay controls at the application layer.

> [!NOTE]
> Critical JOSE extensions declared through `crit` are not supported and are rejected during parsing. Do not rely on
> critical extensions for interoperability with this module.

## License

Distributed under the repository's [MIT License](../LICENSE).