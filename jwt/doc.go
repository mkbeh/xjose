// Package jwt provides secure, typed helpers for signing and verifying compact
// JSON Web Tokens.
//
// The package binds key material to explicit signing methods, requires an
// algorithm allowlist during verification, and supports static key sets,
// custom key resolvers, external signing backends, and configurable claim and
// JOSE header validation.
//
// Custom claim types remain compatible with the Claims interface provided by
// github.com/golang-jwt/jwt/v5.
//
// JWTs provide integrity and authenticity, but not confidentiality. Token
// headers and claims can be decoded without the signing key; use JWE when
// payload encryption is required.
package jwt
