# Examples

This directory contains runnable examples demonstrating the main features and usage patterns of `xjwt`.

| Example                    | Demonstrates                                                                                                                  |
|:---------------------------|:------------------------------------------------------------------------------------------------------------------------------|
| [`hmac`](hmac)             | Signing and verifying typed JWT claims with `HS256` and a shared secret                                                       |
| [`asymmetric`](asymmetric) | Asymmetric JWT signing with `PS256`, separate private and public keys, and a static verification key set                      |
| [`jwk`](jwk)               | Exporting a public verification key as JWK, calculating its RFC 7638 thumbprint, and converting it back                       |
| [`jwks`](jwks)             | Publishing current and previous verification keys as JWKS and selecting the correct key by `kid` during rotation              |
| [`jws`](jws)               | Signing and verifying arbitrary byte payloads with Compact and detached JWS                                                   |
| [`jws_multi`](jws_multi)   | Signing one payload with multiple keys, resolving trusted verification keys, and enforcing an identity-based signature policy |
| [`jws_opaque`](jws_opaque) | Signing through `jose.OpaqueSigner` without exposing private key operations to the JWS API                                    |
| [`jwe`](jwe)               | Creating a nested JWT with sign-then-encrypt and validating it with decrypt-then-verify                                       |
| [`jwe_multi`](jwe_multi)   | Encrypting one payload for multiple recipients with JWE JSON Serialization and Additional Authenticated Data                  |

## Running the examples

Each example is a standalone Go module connected through the repository's `go.work` file.

Run an example from its directory:

```shell
cd hmac
go run .
```

Or run it from the repository root:

```shell
go run ./examples/hmac
```

Replace `hmac` with the directory name of another example.

> [!NOTE]
> The examples generate temporary cryptographic keys at startup and do not require external services. Refer to the
> README in the corresponding example directory for the demonstrated security model, expected output, and production
> key-management considerations.
