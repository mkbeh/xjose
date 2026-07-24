# JWS Opaque Signer

This example signs a Compact JWS through the `jose.OpaqueSigner` interface without passing private key material directly
to `jws.SigningKey`.

The local implementation simulates an external signing service. A production adapter could delegate the signing
operation to KMS, Vault, an HSM, or PKCS#11.

**This example demonstrates:**

* Implementing `jose.OpaqueSigner`
* Advertising supported signature algorithms
* Returning public verification material from `Public`
* Signing the JWS Signing Input through `SignPayload`
* Passing an opaque signer directly to `jws.NewSigner`
* Obtaining the protected `kid` header from `OpaqueSigner.Public`
* Verifying the JWS with trusted public JWK material

## Run

From this directory:

```shell
go run .
```

Or from the repository root:

```shell
go run ./examples/jws_opaque
```

## Expected output

The RSA key pair and serialized JWS change on every run.

```text
serialized: <compact JWS>
verified payload: {"document_id":"document-123","status":"approved"}
verified key ID: opaque-signing-2026-07
algorithm: PS256
```

## Opaque signing

The example passes the opaque signer directly:

<!-- @formatter:off -->
```go
signer, err := jws.NewSigner(
	jws.SigningKey{
		Algorithm: jose.PS256,
		Key:       opaque,
	},
)
```
<!-- @formatter:on -->

`SigningKey.KeyID` is intentionally left empty. The protected `kid` header and public verification key come from
`OpaqueSigner.Public`.

`SignPayload` receives the complete JWS Signing Input produced by `go-jose`, not only the application payload. The local
implementation hashes and signs those bytes with RSA-PSS.

## Production adapters

A production `OpaqueSigner` implementation should keep private key operations behind a dedicated adapter. Provider
dependencies and behavior such as timeouts, retries, digest handling, signature-format conversion, and key rotation
should remain outside the core `jws` module.

The adapter must be safe for concurrent use when the same `jws.Signer` is shared across goroutines. Verification should
use trusted public key material obtained independently from the signed message.