<div align="center">

# JOSE toolkit for Go

**JOSE modules built on top of [golang-jwt/jwt](https://github.com/golang-jwt/jwt)
and  [go-jose](https://github.com/go-jose/go-jose).**

[![Go](https://github.com/mkbeh/xjose/actions/workflows/go.yml/badge.svg?branch=main)](https://github.com/mkbeh/xjose/actions/workflows/go.yml)
[![codecov](https://codecov.io/gh/mkbeh/xjose/branch/main/graph/badge.svg)](https://codecov.io/gh/mkbeh/xjose)

</div>

`xjose` is a modular Go toolkit for signing, verification, encryption, decryption, and public-key distribution based on
the JSON Object Signing and Encryption (JOSE) standards.

The project builds on [golang-jwt/jwt](https://github.com/golang-jwt/jwt)
and [go-jose](https://github.com/go-jose/go-jose), adding explicit trust configuration, strict algorithm allowlists,
resolver-based key selection, multi-signature and multi-recipient workflows, external signing support, and consistent
validation policies.

## Features

* **Explicit trust configuration:** Configure accepted algorithms, key sources, token and content types, and validation
  policies through trusted application settings rather than untrusted input.
* **Strict verification:** Enforce algorithm allowlists, registered-claim validation, protected-header requirements, and
  application-defined signature policies.
* **Flexible key management:** Use static keys, local key sets, custom resolvers, JWK/JWKS material, and
  application-managed key infrastructure.
* **Multi-party workflows:** Create and verify JWS objects with multiple independent signatures and JWE objects with
  multiple recipients under explicit application policies.
* **External signing:** Integrate cloud KMS, HashiCorp Vault, hardware security modules, PKCS#11 adapters, and remote
  signing services.
* **Public-key distribution:** Parse, validate, publish, and resolve public JWK and JWKS documents with deterministic
  key selection and RFC 7638 thumbprints.
* **Consistent validation policies:** Apply the same trust and validation model across JWT, JWS, JWE, JWK, and JWKS
  workflows.

## Installation

This repository contains multiple Go modules that are installed and versioned independently.

Install only the modules required by your application.

**[JWT](jwt) — JSON Web Token**

Issue and verify signed tokens with structured claims and configurable validation policies:

```shell
go get github.com/mkbeh/xjose/jwt
```

**[JWS](jws) — JSON Web Signature**

Sign and verify arbitrary payloads using Compact, detached, and multi-signature serialization:

```shell
go get github.com/mkbeh/xjose/jws
```

**[JWE](jwe) — JSON Web Encryption**

Encrypt and decrypt payloads using Compact, multi-recipient, and nested JWT workflows:

```shell
go get github.com/mkbeh/xjose/jwe
```

**[JWK](jwk) — JSON Web Key and JWK Set**

Parse, validate, publish, identify, and resolve public keys and key sets:

```shell
go get github.com/mkbeh/xjose/jwk
```

Each module has its own version, dependencies, and documentation.

## Examples

See the [examples](examples) directory for usage examples:

| Module  | Examples                                                                                                          |
|---------|-------------------------------------------------------------------------------------------------------------------|
| **JWT** | [HMAC Signing](examples/jwt_hmac)<br>[Asymmetric Signing](examples/jwt_asymmetric)                                |
| **JWS** | [Compact JWS](examples/jws)<br>[Multiple Signatures](examples/jws_multi)<br>[Opaque Signing](examples/jws_opaque) |
| **JWE** | [Compact JWE](examples/jwe)<br>[Multiple Recipients](examples/jwe_multi)                                          |
| **JWK** | [Key Conversion and Thumbprints](examples/jwk)<br>[Key Publication and Resolution](examples/jwk_set)              |

Each example is a standalone Go module with its own README covering setup, execution, expected output, workflow details,
and security considerations.

## References

* **[RFC 7515](https://datatracker.ietf.org/doc/html/rfc7515)** — JSON Web Signature (JWS)
* **[RFC 7516](https://datatracker.ietf.org/doc/html/rfc7516)** — JSON Web Encryption (JWE)
* **[RFC 7517](https://datatracker.ietf.org/doc/html/rfc7517)** — JSON Web Key (JWK)
* **[RFC 7518](https://datatracker.ietf.org/doc/html/rfc7518)** — JSON Web Algorithms (JWA)
* **[RFC 7519](https://datatracker.ietf.org/doc/html/rfc7519)** — JSON Web Token (JWT)
* **[RFC 7520](https://datatracker.ietf.org/doc/html/rfc7520)** — Examples of Protecting Content Using JOSE
* **[RFC 7638](https://datatracker.ietf.org/doc/html/rfc7638)** — JSON Web Key Thumbprint
* **[RFC 8037](https://datatracker.ietf.org/doc/html/rfc8037)** — CFRG ECDH and Signatures in JOSE
* **[RFC 8725](https://datatracker.ietf.org/doc/html/rfc8725)** — JSON Web Token Best Current Practices
* **[RFC 9864](https://datatracker.ietf.org/doc/html/rfc9864)** — Fully-Specified Algorithms for JOSE and COSE

## License

This project is licensed under the [MIT License](LICENSE).