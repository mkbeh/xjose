# Multi-Signature JWS

This example demonstrates signing one payload with multiple independent keys and enforcing an identity-based
verification policy using `xjwt/jws`.

**This example demonstrates:**

- signing one payload with `PS256` and `EdDSA`
- producing General JWS JSON Serialization
- resolving trusted verification keys from protected signature headers
- restricting verification to an explicit algorithm allowlist
- requiring valid signatures from both the issuer and approver
- inspecting the independently verified signature results

## Running the example

From the repository root:

```bash
go run ./examples/jws_multi
```

Or from this directory:

```bash
go run .
```

## Expected output

The serialized JWS varies because the example generates temporary keys at startup and RSA-PSS uses randomized
signatures.

```text
General JWS JSON
serialized:
{
  "payload": "<base64url payload>",
  "signatures": [
    {
      "protected": "<issuer protected header>",
      "signature": "<issuer signature>"
    },
    {
      "protected": "<approval protected header>",
      "signature": "<approval signature>"
    }
  ]
}
verified payload: {"document_id":"document-123","operation":"approve"}
verified signatures: 2
signature 0: issuer-signing-2026-07 (PS256)
signature 1: approval-signing-2026-07 (EdDSA)
policy: required key IDs satisfied
```

## Verification policy

The example uses:

```go
jws.RequireKeyIDs(
"issuer-signing-2026-07",
"approval-signing-2026-07",
)
```

The JWS is accepted only when both trusted identities have valid signatures. The resolver treats the protected `kid` and
`alg` headers as untrusted routing hints and maps them only to application-controlled verification keys.

Other available policies include `RequireAnySignature`, `RequireAllProvidedSignatures`, `RequireThreshold`, and `AllOf`.

## Security notes

Multiple JWS signatures provide independent integrity and authenticity proofs for the same payload. They do not encrypt
the payload or prevent replay.

The verification policy is an application-level acceptance rule, not a cryptographic threshold-signature scheme.
Identity-based policies use the canonical key IDs returned by the trusted resolver rather than trusting an unverified
header value directly.

The example generates ephemeral keys for convenience. Production applications should keep private keys in protected key
stores, publish only public verification material, restrict accepted algorithms, validate expected `typ` and `cty`
headers, and define signer identities and approval requirements explicitly.