// Package xjwt provides secure-by-default primitives for signing and verifying
// compact JSON Web Tokens.
//
// The package is intentionally limited to JWT/JWS concerns. It does not
// implement HTTP middleware, OAuth, OIDC, sessions, remote key fetching, or
// clients for external signing services. Applications provide those I/O
// concerns through KeyResolver and SignFunc.
package xjwt
