# JWS

This example demonstrates signing and verifying arbitrary byte payloads with Compact JWS Serialization and detached JWS
using `jws`.

**This example demonstrates:**

- Signing an embedded payload with `PS256`
- Verifying a Compact JWS with a strict algorithm allowlist
- Binding the protected kid and alg headers to a trusted public JWK
- Validating protected `typ` and `cty` headers
- Signing and verifying exact payload bytes with detached JWS

## Run

From the repository root:

```bash
go run ./examples/jws
```

Or from this directory:

```bash
go run .
```

## Expected output

The serialized signatures vary because the example generates a temporary RSA key and RSA-PSS uses randomized signatures.

```text
Compact JWS
serialized: <compact JWS>
verified payload: {"document_id":"document-123","status":"approved"}
verified key ID: signing-2026-07
protected algorithm: PS256
protected type: example+jws
protected content type: application/json

Detached JWS
serialized: <detached compact JWS>
verified payload: {"document_id":"document-456","status":"pending"}
verified key ID: signing-2026-07
protected algorithm: PS256
protected type: example+jws
protected content type: application/json
```

## Security notes

JWS provides payload integrity and authenticity, but it does not encrypt the payload or prevent replay.

Detached verification requires the exact original payload bytes. Changing whitespace, line endings, file metadata, or
any other byte invalidates the signature. Applications should process the same byte slice that was verified to avoid
time-of-check/time-of-use races.

The example generates an ephemeral RSA key at startup for convenience. Production applications should load signing keys
from a protected key store, publish only public verification keys, configure an explicit algorithm allowlist, and
validate the expected `typ` and `cty` headers.