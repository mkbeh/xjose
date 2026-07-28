# JWS

[![Go](https://github.com/mkbeh/xjose/actions/workflows/go.yml/badge.svg?branch=main)](https://github.com/mkbeh/xjose/actions/workflows/go.yml)
[![Go Reference](https://pkg.go.dev/badge/github.com/mkbeh/xjose/jws.svg)](https://pkg.go.dev/github.com/mkbeh/xjose/jws)
[![codecov](https://codecov.io/gh/mkbeh/xjose/branch/main/graph/badge.svg?flag=jws)](https://codecov.io/gh/mkbeh/xjose)

Sign and verify arbitrary payloads using JSON Web Signature (JWS) in Go.

The `jws` module builds on [go-jose](https://github.com/go-jose/go-jose) and provides explicit algorithm policies,
protected-header validation, resolver-based key selection, Compact and detached JWS workflows, multiple signatures, and
integration with application-managed signing backends.

For complete runnable workflows, see the [examples](../examples) directory.

## Features

* **Compact and detached JWS:** Sign payloads embedded in Compact JWS Serialization or verify exact payload bytes
  distributed separately from the signature.
* **JWS JSON Serialization:** Use Flattened serialization for one signature or General serialization for multiple
  independent signatures over the same payload.
* **Signature policies:** Require any valid signature, every signature, specific trusted signer identities, threshold
  quorums, or a custom application-defined policy.
* **Algorithm and header policies:** Configure accepted signature algorithms independently of incoming JWS headers, and
  enforce expected protected `typ` and `cty` values.
* **Key resolution:** Verify signatures using static keys, public JWKs, JWK Sets, opaque verifiers, or custom resolvers
  backed by application-managed key infrastructure.
* **External signing and verification:** Delegate cryptographic operations to KMS, HashiCorp Vault, HSMs, PKCS#11
  adapters, remote services, or custom backends through `jose.OpaqueSigner` and `jose.OpaqueVerifier`.

## Installation

```shell
go get github.com/mkbeh/xjose/jws
```

## Quick Start

This example signs a JSON document with `PS256`, enforces an explicit verification algorithm allowlist and the expected
protected `typ` and `cty` headers, then returns the authenticated payload, protected header, and trusted key identity.

<!-- @formatter:off -->

```go
ctx := context.Background()

// Generate an RSA signing key for the example.
// Load private keys from protected key storage in production.
privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
if err != nil {
	log.Fatalf("generate RSA key: %v", err)
}

// Create a reusable Compact JWS signer.
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

// Sign the payload and embed it in Compact JWS Serialization.
raw, err := signer.Sign(payload)
if err != nil {
	log.Fatalf("sign payload: %v", err)
}

// Configure the trusted public JWK independently of the signed message.
verificationKey := jose.JSONWebKey{
	Key:       &privateKey.PublicKey,
	KeyID:     "signing-2026-07",
	Algorithm: string(jose.PS256),
	Use:       "sig",
}

// Define the trusted verification policy.
verifier, err := jws.NewVerifier(
	verificationKey,
	[]jose.SignatureAlgorithm{
		jose.PS256,
	},
	jws.WithType("example+jws"),
	jws.WithContentType("application/json"),
)
if err != nil {
	log.Fatalf("create verifier: %v", err)
}

// Verify the signature and return the authenticated message data.
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

A `Signer` can embed the payload in Compact JWS Serialization or create a detached JWS with an empty payload segment.
Detached payload bytes must be transported separately from the serialized signature.

<!-- @formatter:off -->

```go
// Embed the payload in the Compact JWS.
raw, err := signer.Sign(payload)

// Create a Compact JWS with an empty payload segment.
detached, err := signer.SignDetached(payload)
```

<!-- @formatter:on -->

For a JWS with an embedded payload, use `Verify` when only the authenticated payload is needed:

```go
verifiedPayload, err := verifier.Verify(ctx, raw)
```

Use `VerifyMessage` when the application also needs the trusted key identity and protected header:

```go
verified, err := verifier.VerifyMessage(ctx, raw)

payload := verified.Payload
keyID := verified.KeyID
header := verified.Header
```

A detached JWS must be verified against the exact external payload bytes:

```go
detachedVerified, err := verifier.VerifyDetached(ctx, detached, payload)
```

`VerifyDetached` returns the authenticated payload together with the trusted key identity and protected header.

> [!WARNING]
> Detached verification requires the exact bytes that were originally signed. Changes to whitespace, line endings,
> character encoding, or binary representation invalidate the signature. After successful verification, process
> `detachedVerified.Payload` rather than a separately reconstructed representation.

## Signing

A `SigningKey` binds trusted key material to a specific signature algorithm. A `Signer` uses this configuration to
construct the protected JWS header:

* **`alg`** is derived from the algorithm bound to the signing key.
* **`kid`** is included when the signing key has a non-empty key ID.

The signing algorithm and key ID are taken from trusted application configuration and cannot be selected through the
payload or other untrusted input.

### Protected Headers

Use functional options to configure standard and application-specific protected header parameters:

<!-- @formatter:off -->

```go
signer, err := jws.NewSigner(
	signingKey,
	jws.WithType("approval+jws"),
	jws.WithContentType("application/json"),
	jws.WithHeader(jose.HeaderKey("tenant"), "acme"),
)
```

<!-- @formatter:on -->

`WithType` identifies the class of signed object, while `WithContentType` describes the media type of its payload.
`WithHeader` adds an application-specific protected parameter.

After successful verification, application-specific protected parameters are available through
`Header.ExtraHeaders`.

> [!WARNING]
> Signature verification authenticates protected header values but does not determine whether they are valid for the
> current application context. Validate values such as `tenant` against application-defined policy before using them
> for authorization or other security-sensitive decisions.

## Verification

Verification is controlled by trusted application configuration rather than algorithm or key metadata supplied by the
JWS.

A `Verifier` combines:

* trusted static key material or a custom `KeyResolver`;
* a mandatory signature-algorithm allowlist;
* optional protected `typ` and `cty` validation policies.

For each signature, the protected `alg` value must be present in the configured allowlist, and the resolved key must
successfully verify the signature. When configured, `WithType` and `WithContentType` require exact matches against the
protected `typ` and `cty` values.

Verification succeeds only when the signature is valid and every configured header policy is satisfied. This prevents
untrusted JWS metadata from selecting an unsupported algorithm and helps keep signatures created for different message
classes or payload formats from being accepted interchangeably.

> [!IMPORTANT]
> Protected header values are untrusted until the corresponding signature has been verified. A custom `KeyResolver`
> may use `alg`, `kid`, and other header parameters only to locate a candidate within application-controlled key
> records. Do not treat them as authenticated metadata, signer identity, or authorization input before verification
> succeeds.

## Key Management and Resolvers

`NewVerifier` and `NewMultiVerifier` accept static verification material supported by `go-jose`, including raw public
keys, HMAC secrets, JWKs, JWK Sets, and `jose.OpaqueVerifier` implementations.

Key-selection semantics depend on the supplied material:

* **Raw keys and HMAC secrets:** The key is selected through application configuration and does not provide a canonical
  signer identity.
* **Single JWK:** The JWK `alg` and `use` values, when present, constrain signature verification. If both the protected
  header and JWK contain `kid`, the values must match. The trusted JWK key ID becomes the canonical signer identity.
* **JWK Set:** The protected header must contain `kid`. Resolution requires exactly one signature key whose key ID and
  optional algorithm metadata match the protected header.
* **Opaque verifier:** Verification is delegated to the supplied backend. A canonical signer identity is available only
  when provided through trusted resolver configuration or JWK metadata.

### Custom Resolvers

Use `KeyResolverFunc` when verification keys are selected dynamically from an application-managed key registry, cache,
or external key service:

<!-- @formatter:off -->

```go
resolver := jws.KeyResolverFunc(
	func(_ context.Context, header jws.Header) (jws.ResolvedKey, error) {
		// Treat the protected kid and alg values only as lookup hints.
		trusted, exists := trustedKeys[header.KeyID]
		if !exists {
			return jws.ResolvedKey{}, fmt.Errorf(
				"%w: key ID %q",
				jws.ErrKeyNotFound,
				header.KeyID,
			)
		}

		// Bind the selected key record to the declared signature algorithm.
		if trusted.Algorithm != header.Algorithm {
			return jws.ResolvedKey{}, fmt.Errorf(
				"%w: key ID %q does not permit algorithm %q",
				jws.ErrKeyNotFound,
				header.KeyID,
				header.Algorithm,
			)
		}

		// Return the canonical identity from trusted application state,
		// not directly from the unverified protected header.
		return jws.ResolvedKey{
			KeyID: trusted.KeyID,
			Key:   trusted.Key,
		}, nil
	},
)

verifier, _ := jws.NewVerifierWithResolver(
	resolver,
	[]jose.SignatureAlgorithm{
		jose.PS256,
		jose.EdDSA,
	},
)
```

<!-- @formatter:on -->

`ResolvedKey.KeyID` is the canonical signer identity assigned by trusted application configuration. Identity-based
multi-signature policies use this value rather than the unverified protected `kid` header.

The verifier still requires the protected `alg` value to appear in its configured allowlist and verifies the signature
with the key returned by the resolver.

> [!WARNING]
> Header values passed to a resolver are untrusted lookup inputs until the corresponding signature is verified. Map
> them only to application-controlled key records, and do not copy `kid` into `ResolvedKey.KeyID` unless that value has
> been resolved to a trusted canonical identity.

## Multiple Signatures

`MultiSigner` signs the same embedded payload with one or more independent keys:

* one signing key produces Flattened JWS JSON Serialization;
* multiple signing keys produce General JWS JSON Serialization.

`MultiVerifier` verifies the signatures under an explicit application policy, such as requiring particular trusted
signer identities or a threshold quorum.

<!-- @formatter:off -->

```go
// Sign the payload with independent issuer and approval keys.
signer, _ := jws.NewMultiSigner(
	[]jws.SigningKey{
		issuerKey,
		approvalKey,
	},
	jws.WithType("approval+jws"),
)

raw, _ := signer.Sign(payload)

// Require valid signatures from both trusted signer identities.
verifier, _ := jws.NewMultiVerifierWithResolver(
	resolver,
	[]jose.SignatureAlgorithm{
		jose.PS256,
		jose.EdDSA,
	},
	jws.WithType("approval+jws"),
	jws.WithSignaturePolicy(
		jws.RequireKeyIDs(
			"issuer-key-id",
			"approval-key-id",
		),
	),
)

// Verify the shared payload and evaluate the signature policy.
verified, _ := verifier.VerifyMessage(ctx, raw)

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

`RequireKeyIDs` evaluates canonical signer identities returned by the trusted resolver. It does not rely directly on
unverified protected `kid` values.

`MultiVerified.Signatures` contains the signature results collected while evaluating the configured policy. A policy may
finish as soon as its requirements are satisfied, so the slice does not necessarily contain a result for every signature
present in the JWS.

> [!NOTE]
> `MultiSigner` always embeds the shared payload in JWS JSON Serialization. Detached multi-signature JWS is not exposed
> by this module.

## Signature Policies

`MultiVerifier` uses `RequireAnySignature` by default. Use `WithSignaturePolicy` to define stricter or
application-specific acceptance criteria:

* **`RequireAnySignature`:** Requires at least one signature to verify with a trusted key.
* **`RequireAllSignatures`:** Requires every signature present in the JWS to verify successfully.
* **`RequireKeyIDs`:** Requires a valid signature from each listed canonical signer identity.
* **`RequireThreshold`:** Requires valid signatures from a minimum number of distinct canonical identities selected
  from an explicit allowlist.
* **`AllOf`:** Combines multiple policies and requires each nested policy to succeed.
* **`SignaturePolicyFunc`:** Defines custom application-specific policy logic.

Identity-based policies evaluate canonical identities returned through `ResolvedKey.KeyID`, not protected `kid` values
taken directly from the JWS. Multiple valid signatures resolved to the same canonical identity count only once toward a
threshold.

`RequireThreshold` implements an application-level quorum over independent JWS signatures. It is not a cryptographic
threshold-signature scheme in which multiple parties jointly produce one signature.

> [!NOTE]
> Policy evaluation may stop as soon as the acceptance result is known, so `MultiVerified.Signatures` may not contain a
> result for every signature present in the JWS. Use `RequireAllSignatures` when acceptance must depend on every
> provided signature being valid. Regardless of the configured policy, `MultiVerifier` requires at least one
> cryptographically valid signature.

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
```

<!-- @formatter:on -->

When an opaque signer is supplied directly, leave `SigningKey.KeyID` empty. The protected `kid` value and public
verification material are obtained from the JWK returned by `OpaqueSigner.Public()`.

`OpaqueSigner.SignPayload` receives the complete JWS Signing Input constructed by `go-jose`, not the original
application payload:

```text
base64url(protected header) + "." + base64url(payload)
```

The implementation must invoke the external backend according to the selected signature algorithm and return signature
bytes in the format expected by JWS. Provider-specific encodings must be converted before the signature is returned.

## Security Considerations

The module provides signing, verification, and policy primitives, but the application remains responsible for the
complete message security model:

* **Prefer asymmetric signing across trust boundaries:** Any service holding an HMAC secret can both verify and create
  valid signatures. Use RSA, ECDSA, or Ed25519 when signers and verifiers require different privileges.
* **Process only verified payloads:** Do not parse or act on payload bytes before verification succeeds. Consume the
  payload returned by the verifier to ensure that application logic processes the exact bytes covered by the signature.
* **Use canonical signer identities:** For approval and quorum policies, use identities returned by trusted resolvers
  through `ResolvedKey.KeyID`. Do not treat a protected `kid` value as signer identity until it has been resolved to an
  application-controlled key record and the signature has been verified.
* **Choose multi-signature policies deliberately:** Requiring every signature to be valid, requiring specific signer
  identities, and requiring a threshold of trusted identities represent different trust models. Use identity-based
  policies when particular signers or roles must approve a message.
* **Separate message classes:** Configure distinct `typ`, `cty`, algorithms, keys, and signature policies for messages
  with different purposes. This prevents a valid signature created for one workflow from being accepted in another.
* **Implement replay protection separately:** JWS authenticates payload integrity but does not provide freshness,
  uniqueness, or one-time-use guarantees. Enforce timestamps, nonces, message identifiers, or replay caches at the
  application layer when required.
* **Separate verification from authorization:** Successful verification establishes that the payload was signed with
  trusted key material and satisfies the configured JWS policy. Application code must still determine whether the
  verified signer and message are authorized for the requested operation.

> [!WARNING]
> Critical JOSE extensions (`crit`) and unencoded payloads (`b64: false`) are not supported and are rejected during
> parsing. Do not depend on these features when interoperating with this module.

## License

Distributed under the repository's [MIT License](../LICENSE).