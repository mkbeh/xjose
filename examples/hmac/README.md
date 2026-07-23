# HMAC-signed JWT

This example signs and verifies an access JWT with `HS256` and a shared 256-bit secret.

**This example demonstrates:**

* Generating a cryptographically secure HMAC secret
* Creating a signing key with an explicit key ID
* Signing registered and custom typed claims
* Restricting the accepted signing algorithm
* Validating issuer, audience, type, issued-at time, and maximum token lifetime
* Reading the verified JOSE header and typed claims

## Run

From this directory:

```shell
go run .
```

Or from the repository root:

```shell
go run ./examples/hmac
```

## Expected output

The compact JWT changes on every run because the secret and issued-at time are generated dynamically.

```text
token: <compact JWT>
algorithm: HS256
key ID: hmac-2026-07
subject: user-123
role: admin
```

## HMAC key handling

HMAC uses the same secret for signing and verification. Every service that can verify the token can also create a valid
token with that secret.

This example generates a new secret for each run. In production, load a sufficiently strong secret from a secret manager
and rotate it according to the application's key-management policy.

Use an asymmetric signing algorithm when verification services should not have access to signing key material.