<div align="center">

# xjwt

**Lightweight JWT wrapper for Go, built on top of [golang-jwt/jwt](https://github.com/golang-jwt/jwt).**

![Go Version](https://img.shields.io/badge/go-1.26%2B-blue)
[![License: MIT](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)

</div>

`xjwt` is a lightweight wrapper around [`golang-jwt/jwt`](https://github.com/golang-jwt/jwt) that provides a clean API
for creating and validating JSON Web Tokens.

## Features

* **Tokens**: Create signed JWTs with custom claims.
* **Claims**: Parse and validate tokens into typed claim structs.
* **Bearer**: Built-in `Bearer <token>` extraction and validation.
* **Signing**: Configurable signing method with `HS256` by default.
* **Errors**: Exported errors for invalid tokens, schemes, signatures, and claims.
* **Expiration**: Helper for setting `exp` in registered claims.

## Installation

```bash id="b20l9e"
go get github.com/mkbeh/xjwt
```

## Quick Start

The example below demonstrates how to initialize the token manager, generate a signed JWT with custom claims, and parse
it back using a `Bearer` token string.

<!-- @formatter:off -->
```go
package main

import (
	"fmt"
	"log"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/mkbeh/xjwt"
)

type MyClaims struct {
	jwt.RegisteredClaims
	UserID string `json:"user_id"`
}

func main() {
	tm, err := xjwt.New(
		xjwt.WithSecretKey([]byte("secret")),
	)
	if err != nil {
		log.Fatalf("failed to init token manager: %v", err)
	}

	token, err := tm.CreateWithClaims(&MyClaims{
		UserID: "42",
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: xjwt.AddExpiresAt(time.Hour),
		},
	})
	if err != nil {
		log.Fatalf("failed to create token: %v", err)
	}

	fmt.Println("token:", token)

	claims := &MyClaims{}
	err = tm.ParseWithClaims("Bearer "+token, claims)
	if err != nil {
		log.Fatalf("failed to parse token: %v", err)
	}

	fmt.Println("user_id:", claims.UserID)
}

```
<!-- @formatter:on -->

More examples: [examples/](https://github.com/mkbeh/xjwt/tree/main/examples)

## Signing Method

By default, `xjwt` uses `HS256`.

Use `WithSigningMethod` to configure any other signing method supported by `golang-jwt/jwt`.

<!-- @formatter:off -->
```go
tm, err := xjwt.New(
	xjwt.WithSecretKey([]byte("secret")),
	xjwt.WithSigningMethod(jwt.SigningMethodHS512),
)
if err != nil {
	log.Fatalf("failed to initialize token manager: %v", err)
}
```
<!-- @formatter:on -->

During parsing, `xjwt` automatically validates that the incoming token's signing algorithm matches the configured method
to prevent algorithm confusion attacks.

## Error Handling

`xjwt` wraps validation failures with exported errors, allowing you to easily inspect specific failure reasons using
standard `errors.Is`.

<!-- @formatter:off -->
```go
claims := &MyClaims{}
err := tm.ParseWithClaims(tokenString, claims)
if err != nil {
	if errors.Is(err, xjwt.ErrTokenRestriction) {
		// token is expired or has invalid claims (e.g., nbf, aud)
		return nil, ErrExpired
	}
	if errors.Is(err, xjwt.ErrInvalidSignature) {
		// signature verification failed
		return nil, ErrBadSignature
	}

	return nil, fmt.Errorf("failed to parse token: %w", err)
}
```
<!-- @formatter:on -->

### Exported Errors

| Error | Description |
| :--- | :--- |
| `ErrTokenSigned` | Token signing failed. |
| `ErrInvalidToken` | Token is malformed, missing, or invalid. |
| `ErrInvalidScheme` | Authorization scheme is not `Bearer`. |
| `ErrInvalidSignature` | Token signature is invalid or algorithm mismatches. |
| `ErrTokenRestriction` | Token claims are invalid (e.g., expired). |

## References

* [JWT Introduction](https://jwt.io/introduction) — Core concepts of JSON Web Tokens.
* [RFC 7519](https://datatracker.ietf.org/doc/html/rfc7519) — Official JSON Web Token specification.

## License

This project is licensed under the [MIT License](LICENSE).