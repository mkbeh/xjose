<div align="center">

# JOSE toolkit for Go

**JOSE modules built on top of [go-jose](https://github.com/go-jose/go-jose)
and [golang-jwt/jwt](https://github.com/golang-jwt/jwt).**

[![Go](https://github.com/mkbeh/xjose/actions/workflows/go.yml/badge.svg?branch=main)](https://github.com/mkbeh/xjose/actions/workflows/go.yml)
[![codecov](https://codecov.io/gh/mkbeh/xjose/branch/main/graph/badge.svg)](https://codecov.io/gh/mkbeh/xjose)

</div>

`xjose` is a collection of focused Go modules for signing, verification, encryption, and public-key distribution using
the JSON Object Signing and Encryption (JOSE) standards.

The project builds on [golang-jwt/jwt](https://github.com/golang-jwt/jwt) and
[go-jose](https://github.com/go-jose/go-jose), adding explicit trust configuration, strict algorithm allowlists,
resolver-based key selection, multi-signature and multi-recipient workflows, external signing support, and configurable
resource limits.

## Features

* **Explicit trust configuration:** Configure accepted algorithms, key sources, token types, content types, and
  validation policies through trusted application settings instead of inferring them from untrusted input.
* **Strict verification policies:** Enforce algorithm allowlists, registered-claim validation, protected-header
  requirements, signature policies, and bounded input processing.
* **Flexible key management:** Work with static keys, local key sets, custom resolvers, JWK/JWKS material, and
  application-managed key infrastructure.
* **Multi-party workflows:** Support multiple independent JWS signatures and multiple JWE recipients with explicit
  application-level policies.
* **External signing:** Integrate cloud KMS, HashiCorp Vault, hardware security modules, PKCS#11 adapters, and remote
  signing services.
* **Public-key distribution:** Parse, validate, publish, and resolve public JWK and JWKS documents with deterministic
  key selection and RFC 7638 thumbprints.
* **Bounded processing:** Apply configurable limits to serialized tokens, payloads, plaintext, signatures, recipients,
  and parsed key sets.

## Installation

This repository contains multiple Go modules that are installed and versioned independently.

Install only the modules required by your application.

**[JWT](jwt) — JSON Web Token**

Issue and verify signed tokens with structured claims and configurable validation policies:

```shell
go get github.com/mkbeh/xjose/jwt
```

**[JWS](jws) — JSON Web Signature**

Sign and verify arbitrary payloads using Compact, detached, or multi-signature serialization:

```shell
go get github.com/mkbeh/xjose/jws
```

**[JWE](jwe) — JSON Web Encryption**

Encrypt and decrypt payloads using Compact, multi-recipient, or nested JWT workflows:

```shell
go get github.com/mkbeh/xjose/jwe
```

**[JWK](jwk) — JSON Web Key**

Parse, validate, export, and identify individual public keys:

```shell
go get github.com/mkbeh/xjose/jwk
```

**[JWKS](jwks) — JSON Web Key Set**

Parse, publish, and resolve collections of public verification keys:

```shell
go get github.com/mkbeh/xjose/jwks
```

Each module maintains its own documentation, versions, and dependency graph.

## Examples

See the [examples](examples) directory for usage examples:

* **JWT — JSON Web Token**
    * [HMAC Signing](examples/jwt_hmac)
    * [Asymmetric Signing](examples/jwt_asymmetric)
* **JWS — JSON Web Signature**
    * [Compact JWS](examples/jws)
    * [Multiple Signatures](examples/jws_multi)
    * [Opaque Signing](examples/jws_opaque)
* **JWE — JSON Web Encryption**
    * [Compact JWE](examples/jwe)
    * [Multiple Recipients](examples/jwe_multi)
* **JWK — JSON Web Key**
    * [Key Conversion and Thumbprints](examples/jwk)
* **JWKS — JSON Web Key Set**
    * [Key Publication and Resolution](examples/jwks)

For installation details, core workflows, and security considerations, see the README for each module.

## References

* **[RFC 7515](https://datatracker.ietf.org/doc/html/rfc7515)** — JSON Web Signature (JWS)
* **[RFC 7516](https://datatracker.ietf.org/doc/html/rfc7516)** — JSON Web Encryption (JWE)
* **[RFC 7517](https://datatracker.ietf.org/doc/html/rfc7517)** — JSON Web Key (JWK)
* **[RFC 7518](https://datatracker.ietf.org/doc/html/rfc7518)** — JSON Web Algorithms (JWA)
* **[RFC 7519](https://datatracker.ietf.org/doc/html/rfc7519)** — JSON Web Token (JWT)
* **[RFC 7520](https://datatracker.ietf.org/doc/html/rfc7520)** — Examples of Protecting Content Using JOSE
* **[RFC 7638](https://datatracker.ietf.org/doc/html/rfc7638)** — JSON Web Key Thumbprint
* **[RFC 8037](https://datatracker.ietf.org/doc/html/rfc8037)** — CFRG Elliptic Curves in JOSE
* **[RFC 8725](https://datatracker.ietf.org/doc/html/rfc8725)** — JSON Web Token Best Current Practices

## License

This project is licensed under the [MIT License](LICENSE).