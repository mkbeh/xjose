# Nested signed and encrypted JWT

This example creates a nested JWT using sign-then-encrypt:

1. The claims are signed as an inner compact JWT with `PS256`.
2. The signed JWT is encrypted as an outer compact JWE with `RSA-OAEP-256` and `A256GCM`.
3. Verification decrypts the outer JWE before validating the signature and claims of the inner JWT.

The signing and encryption keys are intentionally separate.

**This example demonstrates:**

* Creating independent RSA signing and encryption key pairs
* Signing typed JWT claims with `PS256`
* Encrypting the signed JWT with `RSA-OAEP-256` and `A256GCM`
* Marking the encrypted content as `JWT` through the JWE `cty` header
* Enforcing explicit JWT and JWE algorithm allowlists
* Validating issuer, audience, type, issued-at time, and maximum token lifetime
* Reading both the outer JWE header and inner JWT header
* Performing decrypt-then-verify through `NestedVerifier`

## Run

From this directory:

```shell
go run .
```

Or from the repository root:

```shell
go run ./examples/jwe
```

## Expected output

The nested JWT changes on every run because both RSA key pairs and the issued-at time are generated dynamically.

```text
nested JWT: <compact JWE>

verified user: user-123
verified scopes: [orders:read orders:write]
JWE key algorithm: RSA-OAEP-256
JWE content encryption: A256GCM
JWE key ID: encryption-2026-07
JWE content type: JWT
JWT algorithm: PS256
JWT key ID: signing-2026-07
```

## Nested JWT processing

The issuer follows sign-then-encrypt:

```text
claims
  → sign with the JWT private key
  → compact JWT
  → encrypt with the recipient public key
  → compact JWE
```

The verifier performs the reverse order:

```text
compact JWE
  → decrypt with the recipient private key
  → compact JWT
  → verify with the JWT public key
  → validated claims
```

The outer JWE protects the confidentiality and integrity of the inner signed JWT. The inner signature still establishes
the issuer and protects the claims after decryption.

## Key separation

Signing and encryption keys serve different purposes and should remain separate:

* The signing private key belongs to the JWT issuer
* JWT verification services need only the signing public key
* The encryption public key is used by the sender
* The encryption private key belongs to the intended JWE recipient

Reusing one RSA key pair for both signing and encryption couples unrelated security roles, complicates rotation, and
increases the impact of key compromise.

## Production key handling

This example generates temporary keys for demonstration. In production:

* Load private keys from protected key storage or a KMS/HSM
* Distribute only public signing and encryption keys
* Assign independent `kid` values to signing and encryption key versions
* Rotate signing and encryption keys independently
* Retain previous public verification keys until signed JWTs expire
* Retain previous private decryption keys while encrypted messages may still arrive
* Keep explicit allowlists for JWT signing, JWE key management, and content encryption algorithms