# JSON Web Key Set

This example publishes two RSA public verification keys as a JSON Web Key Set (JWKS), parses the published document, and
uses it to verify a JWT issued with the current private key.

The previous public key remains available to demonstrate a typical verification-key rotation window.

**This example demonstrates:**

* Maintaining current and previous verification keys during rotation
* Exporting an `jwt.StaticKeySet` as JWKS
* Serializing and parsing a JWKS document
* Issuing a JWT with the current private key
* Selecting the verification key by the token's `kid`
* Restricting the accepted signing algorithm
* Validating issuer, audience, type, issued-at time, and maximum token lifetime

## Run

From this directory:

```shell
go run .
```

Or from the repository root:

```shell
go run ./examples/jwks
```

## Expected output

The RSA key pairs and JWK values change on every run.

```text
JWKS:
{
  "keys": [
    {
      "use": "sig",
      "kty": "RSA",
      "kid": "rsa-signing-2026-06",
      "alg": "PS256",
      "n": "<previous RSA modulus>",
      "e": "AQAB"
    },
    {
      "use": "sig",
      "kty": "RSA",
      "kid": "rsa-signing-2026-07",
      "alg": "PS256",
      "n": "<current RSA modulus>",
      "e": "AQAB"
    }
  ]
}

token: <compact JWT>
verified user: user-123
verified key ID: rsa-signing-2026-07
verified algorithm: PS256
```

The exact JSON field order may differ.

## Key rotation

During signing-key rotation:

1. Start publishing the new public key in JWKS.
2. Switch the issuer to the new private key and `kid`.
3. Keep the previous public key available until every token signed with it has expired.
4. Remove the previous key only after the maximum token lifetime and any allowed clock skew have elapsed.

The issuer should hold only the active private signing key. JWKS must publish public verification material only.

## Trust and validation

Parsing JWKS loads the published keys but does not replace verifier policy. The verifier must independently restrict
accepted algorithms and validate token claims.

In production:

* Load the private signing key from protected key storage
* Retrieve JWKS only from an authenticated and trusted source
* Apply document-size and key-count limits before accepting remote JWKS
* Cache and refresh remote JWKS according to an explicit availability policy
* Reject unknown `kid`, incompatible algorithms, private keys, and keys not intended for signature verification