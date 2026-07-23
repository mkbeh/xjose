# Asymmetric JWT signing

This example signs and verifies an access JWT with `PS256`, an RSA-PSS signature using SHA-256.

The issuing side signs with a private RSA key. The verification side uses only the corresponding public key, so services that verify tokens cannot issue new valid tokens.

**This example demonstrates:**

* Generating an RSA key pair
* Creating separate signing and verification keys
* Signing registered and custom typed claims
* Resolving the verification key through a static key set
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
go run ./examples/asymmetric
```

## Expected output

The compact JWT changes on every run because the RSA key pair and issued-at time are generated dynamically.

```text
token: <compact JWT>
algorithm: PS256
key ID: rsa-2026-07
subject: service-123
permissions: [orders:read orders:write]
```

## Asymmetric key handling

The private key is required only by the issuing service. Verification services should receive the public key through a trusted distribution mechanism such as configuration, a secret or key-management system, or a validated JWKS endpoint.

This example generates a temporary RSA key pair for demonstration. In production:

* Load the private key from protected key storage instead of generating it at startup
* Restrict private-key access to the issuing component
* Publish or distribute only the public key
* Assign a stable `kid` to each key version
* Retain previous public keys until all tokens signed with them have expired
* Rotate keys according to the application's key-management policy