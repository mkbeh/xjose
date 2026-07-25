# JWS

Secure helpers for signing and verifying arbitrary byte payloads with JSON Web Signature (JWS) in Go.

The `jws` module builds on [go-jose](https://github.com/go-jose/go-jose) and adds strict algorithm allowlists,
protected-header validation, resolver-based key selection, detached payload support, multi-signature policies, and
configurable resource limits.

For complete runnable examples, see the [examples](../examples) directory.

## Features

* **Compact and detached JWS:** Embed the payload in Compact JWS Serialization or distribute the exact payload bytes
  separately from its signature.
* **Multiple signatures:** Create and verify Flattened or General JWS JSON Serialization containing one or more
  independent signatures over the same payload.
* **Signature policies:** Require any valid signature, every provided signature, specific trusted signer identities,
  threshold quorums, or custom application-defined policies.
* **Strict verification:** Mandatory algorithm allowlists prevent token-controlled algorithm selection, while protected
  `typ` and `cty` validation helps isolate message classes and payload formats.
* **Flexible key resolution:** Verify with static keys, JWKs, JWKS documents, opaque verifiers, or custom resolvers
  backed
  by application-managed key infrastructure.
* **Opaque signing:** Delegate private-key operations to KMS, HashiCorp Vault, HSMs, PKCS#11 adapters, or other external
  signing backends through `jose.OpaqueSigner`.
* **Resource limits:** Bound serialized JWS size, payload size, and the number of signatures accepted or produced by
  JSON
  serialization operations.

## Installation

```shell
go get github.com/mkbeh/xjose/jws
```

## Quick Start

This example signs a JSON document with `PS256`, then verifies its signature, trusted key identity, token type, and
content type.

<!-- @formatter:off -->
```go
ctx := context.Background()

// Generate an RSA signing key for the example.
// Load private keys from secure storage in production.
privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
if err != nil {
	log.Fatalf("generate RSA key: %v", err)
}

// Create a reusable signer with protected type and content-type headers.
signer, err := jws.NewSigner(
	jws.SigningKey{
		Algorithm: jose.PS256,
		KeyID:     "signing-2026-07",
		Key:       privateKey,
	},
	jws.WithType("example+jws"),
	jws.WithContentType("application/json"),
)
if err != nil {
	log.Fatalf("create signer: %v", err)
}

payload := []byte(`{"document_id":"document-123","status":"approved"}`)

// Sign and serialize the embedded payload as Compact JWS.
raw, err := signer.Sign(payload)
if err != nil {
	log.Fatalf("sign payload: %v", err)
}

// Prepare trusted verification material independently from the signed message.
verificationKey := jose.JSONWebKey{
	Key:       &privateKey.PublicKey,
	KeyID:     "signing-2026-07",
	Algorithm: string(jose.PS256),
	Use:       "sig",
}

// Define the trusted verification policy.
verifier, err := jws.NewVerifier(
	verificationKey,
	[]jose.SignatureAlgorithm{jose.PS256},
	jws.WithType("example+jws"),
	jws.WithContentType("application/json"),
)
if err != nil {
	log.Fatalf("create verifier: %v", err)
}

// Verify the signature and return only authenticated data.
verified, err := verifier.VerifyMessage(ctx, raw)
if err != nil {
	log.Fatalf("verify JWS: %v", err)
}

log.Printf(
	"verified key %q and payload %s",
	verified.KeyID,
	verified.Payload,
)
```
<!-- @formatter:on -->

> [!NOTE]
> Asymmetric signing allows downstream services to verify payloads without receiving signing authority. Any service
> holding a shared HMAC secret can both verify and create valid signatures.

## Compact and Detached JWS

A `Signer` can embed the payload in Compact JWS Serialization or produce a detached JWS whose payload segment is empty
and must be transported separately.

```go
// Embed the payload in the serialized JWS.
raw, err := signer.Sign(payload)

// Sign the payload without embedding it.
detached, err := signer.SignDetached(payload)
````

Use the corresponding verification method based on the required result:

```go
// Return only the authenticated payload.
verifiedPayload, err := verifier.Verify(ctx, raw)

// Return the payload, trusted key identity, and protected header.
verified, err := verifier.VerifyMessage(ctx, raw)

// Verify a detached JWS against the exact external payload bytes.
detachedVerified, err := verifier.VerifyDetached(ctx, detached, payload)
```

Use `Verify` when only the authenticated payload is needed. Use `VerifyMessage` or `VerifyDetached` when the application
also needs the trusted key identity or verified protected header.

> [!WARNING]
> Detached verification requires the exact bytes that were originally signed. Changes to whitespace, line endings,
> character encoding, or binary representation invalidate the signature. After verification, process
> `detachedVerified.Payload` rather than a separately reconstructed representation.

## Signing

A `SigningKey` binds trusted key material to a specific signature algorithm. The resulting `Signer` constructs the
protected JWS header from that configuration:

* **`alg`** is derived from the algorithm bound to the signing key.
* **`kid`** is included when the signing key has a non-empty key ID.

### Protected Headers

Use functional options to add standard or application-specific protected header parameters:

<!-- @formatter:off -->
```go
signer, err := jws.NewSigner(
	signingKey,
	jws.WithType("approval+jws"),
	jws.WithContentType("application/json"),
	jws.WithHeader(jose.HeaderKey("tenant"), "acme"),
)
````

<!-- @formatter:on -->

`WithType` identifies the signed object, while `WithContentType` describes the media type of its payload. Additional
protected parameters can be added with `WithHeader`.

After successful verification, application-specific parameters are available through `Header.ExtraHeaders`.

> [!WARNING]
> Verifiers do not automatically enforce policies for custom headers. Treat values such as `tenant` as authenticated
> metadata only after signature verification succeeds, then validate them against application-specific requirements
> before making authorization decisions.

## Verification

Verification is driven by trusted application configuration rather than values supplied by the JWS.

A `Verifier` combines:

* trusted static key material or a `KeyResolver`;
* a mandatory signature-algorithm allowlist;
* optional protected `typ` and `cty` policies;
* configured token and payload limits.

The protected `alg` value must appear in the configured allowlist, and the resolved key must successfully verify the
signature. When configured, `WithType` and `WithContentType` require exact matches against the protected `typ` and `cty`
headers.

This prevents token-controlled algorithm selection and helps ensure that a valid signature created for one message
class or payload format is not accepted in another context.

> [!IMPORTANT]
> JWS headers are untrusted until the corresponding signature is successfully verified. A custom `KeyResolver` may use
> `alg`, `kid`, and other header values only to select a candidate key; it must never treat them as proof of signer
> identity or authenticity.

## Key Management and Resolvers

`NewVerifier` and `NewMultiVerifier` accept static verification material supported by `go-jose`, including raw keys,
HMAC secrets, JWKs, JWKS documents, and `jose.OpaqueVerifier` implementations.

When JWK or JWKS material is used, available key metadata further constrains key selection:

* **JWK metadata:** When present, `kid`, `alg`, and `use` must be compatible with the protected JWS header and signature
  purpose.
* **JWKS resolution:** The protected header must contain a `kid`, and the set must contain exactly one eligible matching
  signature key.
* **Raw keys:** Key selection is configured out of band, and the key does not provide a canonical signer identity.

### Custom Resolvers

Use `KeyResolverFunc` when verification keys are managed dynamically through an application cache, database, JWKS
provider, or external key-management system:

<!-- @formatter:off -->
```go
resolver := jws.KeyResolverFunc(
	func(ctx context.Context, header jws.Header) (jws.ResolvedKey, error) {
		trusted, exists := trustedKeys[header.KeyID]
		if !exists || trusted.Algorithm != header.Algorithm {
			return jws.ResolvedKey{}, fmt.Errorf("%w: key ID %q", jws.ErrKeyNotFound, header.KeyID)
		}

		return jws.ResolvedKey{
			KeyID: trusted.KeyID,
			Key:   trusted.Key,
		}, nil
	},
)

verifier, err := jws.NewVerifierWithResolver(
	resolver,
	[]jose.SignatureAlgorithm{
		jose.PS256,
		jose.EdDSA,
	},
)

```
<!-- @formatter:on -->

`ResolvedKey.KeyID` is the canonical signer identity assigned by trusted application configuration. Identity-based
multi-signature policies use this value rather than trusting the unverified `kid` header directly.

> [!WARNING]
> Header values passed to a resolver are untrusted lookup inputs. Map them to application-controlled key records before
> returning key material or assigning a canonical signer identity.

## Multiple Signatures

A `MultiSigner` applies one or more independent signatures to the same embedded payload. One signing key produces
Flattened JWS JSON Serialization, while multiple signing keys produce General JWS JSON Serialization.

### Multi-Signature Flow

Use `MultiVerifier` to enforce an explicit application-level policy, such as a quorum or a required set of trusted
signer
identities:

<!-- @formatter:off -->
```go
// Sign the payload with multiple independent keys.
signer, err := jws.NewMultiSigner(
	[]jws.SigningKey{
		issuerKey,
		approvalKey,
	},
	jws.WithType("approval+jws"),
)

raw, err := signer.Sign(payload)

// Require valid signatures from both trusted signer identities.
verifier, err := jws.NewMultiVerifierWithResolver(
	resolver,
	[]jose.SignatureAlgorithm{
		jose.PS256,
		jose.EdDSA,
	},
	jws.WithType("approval+jws"),
	jws.WithSignaturePolicy(
		jws.RequireKeyIDs("issuer-key-id", "approval-key-id"),
	),
)

// Verify the shared payload against the configured policy.
verified, err := verifier.VerifyMessage(ctx, raw)

for _, signature := range verified.Signatures {
	if !signature.Valid() {
		continue
	}

	log.Printf(
		"verified signature %d from canonical key %q",
		signature.Index,
		signature.KeyID,
	)
}

```

<!-- @formatter:on -->

`RequireKeyIDs` evaluates canonical identities returned by the trusted resolver rather than relying directly on
unverified `kid` header values.

The `Signatures` slice contains the results collected while evaluating the configured policy. A policy may stop once its
requirements are satisfied, so the slice does not necessarily describe every signature present in the input.

> [!NOTE]
> `MultiSigner` always embeds the shared payload in the JWS JSON structure. Detached multi-signature serialization is
> intentionally not exposed by this module.

## Signature Policies

`MultiVerifier` uses `RequireAnySignature` by default. Pass `WithSignaturePolicy` to enforce stricter or
application-specific verification requirements:

* **`RequireAnySignature`:** Accepts the JWS after at least one signature verifies with a trusted key.
* **`RequireAllProvidedSignatures`:** Requires every signature present in the serialized JWS object to be valid.
* **`RequireKeyIDs`:** Requires valid signatures from each listed canonical signer identity.
* **`RequireThreshold`:** Requires a minimum number of unique trusted identities from an explicit allowlist.
* **`AllOf`:** Composes multiple policies and requires every nested policy to succeed.
* **`SignaturePolicyFunc`:** Implements custom application-specific policy logic.

Identity-based policies evaluate canonical identities returned through `ResolvedKey.KeyID`, not unverified `kid` header
values. Multiple valid signatures from the same trusted identity count only once toward a threshold.

`RequireThreshold` implements an application-level quorum over independent JWS signatures, not a cryptographic
threshold-signature scheme.

> [!NOTE]
> Policy evaluation may stop as soon as its requirements are satisfied, so `Signatures` may not include results for
> every signature in the input. Use `RequireAllProvidedSignatures` when every provided signature must be evaluated.
> Regardless of the configured policy, `MultiVerifier` always requires at least one cryptographically valid signature.

## Opaque Signing

Use `jose.OpaqueSigner` when private-key operations are delegated to an external backend such as AWS KMS, Google Cloud
KMS, HashiCorp Vault, an HSM, or a PKCS#11 adapter:

<!-- @formatter:off -->
```go
signer, err := jws.NewSigner(
	jws.SigningKey{
		Algorithm: jose.PS256,
		Key:       opaqueSigner,
	},
	jws.WithType("approval+jws"),
)
````
<!-- @formatter:on -->

When an opaque signer is used directly, leave `SigningKey.KeyID` empty. The signer obtains the protected `kid` header
and
public verification material from `OpaqueSigner.Public()`.

The underlying `SignPayload` method receives the complete JWS Signing Input produced by `go-jose`, not only the
application payload, and must return the raw signature bytes expected by the selected algorithm.

## Security Considerations

The module provides strict signing and verification primitives, but the application remains responsible for the overall
message security model:

* **Prefer asymmetric signing across trust boundaries:** Any service holding a shared HMAC secret can both verify and
  create valid signatures. Use RSA, ECDSA, or Ed25519 when signers and verifiers require different privileges.
* **Process only authenticated payloads:** Do not parse or act on an unverified payload. Verify first, then consume the
  payload bytes returned by the verifier to avoid inconsistencies between the data that was checked and the data that
  is processed.
* **Protect signer identity:** Use canonical identities returned by trusted resolvers through `ResolvedKey.KeyID` for
  approval and quorum policies. Never treat an unverified `kid` header as an authenticated signer identity.
* **Choose multi-signature policies deliberately:** Requiring every supplied signature and requiring signatures from
  specific trusted identities express different trust models. Prefer identity-based policies for named approval
  workflows.
* **Implement replay protection separately:** JWS authenticates payload integrity and signer possession of trusted key
  material, but does not provide timestamps, nonces, uniqueness tracking, or one-time-use enforcement.
* **Distinguish verification from authorization:** A valid signature proves that trusted key material authenticated the
  payload. Application logic must still determine whether the verified signer and payload are authorized for the
  requested operation.

> [!WARNING]
> Critical JOSE extensions (`crit`) and unencoded payloads (`b64: false`) are not supported and are rejected during
> parsing. Do not rely on these features for interoperability with this module.

## License

Distributed under the repository's [MIT License](../LICENSE).