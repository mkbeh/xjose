# JSON Web Key

This example exports an RSA public verification key as a JSON Web Key (JWK), calculates its RFC 7638 thumbprint, parses
the serialized JWK, and converts it back to an `xjwt.VerificationKey`.

**This example demonstrates:**

* Creating an RSA public verification key
* Exporting public key material as JWK
* Serializing and parsing JWK JSON
* Calculating an RFC 7638 SHA-256 thumbprint
* Converting a parsed JWK back to an `xjwt.VerificationKey`
* Preserving the key ID and signing algorithm

## Run

From this directory:

```shell
go run .
```

Or from the repository root:

```shell
go run ./examples/jwk
```

## Expected output

The RSA key pair and thumbprint change on every run.

```text
JWK:
{
  "use": "sig",
  "kty": "RSA",
  "kid": "rsa-signing-2026-07",
  "alg": "PS256",
  "n": "<RSA modulus>",
  "e": "AQAB"
}

thumbprint: <RFC 7638 thumbprint>
key ID: rsa-signing-2026-07
algorithm: PS256
```

The exact JSON field order may differ.

## Public key handling

A JWK used for signature verification should contain public key material only. Private signing keys must not be
published or distributed to verification services.

The `kid` and RFC 7638 thumbprint serve different purposes:

* `kid` is application-controlled metadata used to select a key
* The thumbprint is derived from the canonical public key parameters and identifies the key material itself

Changing metadata such as `kid`, `use`, or `alg` does not change the RFC 7638 thumbprint.

In production, obtain JWK data from a trusted source, validate the expected algorithm and key usage, and reject private
or symmetric keys when public verification material is required.