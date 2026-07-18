// Package jwk parses and serializes public JSON Web Keys used for JWT
// signature verification.
//
// The package supports RSA, NIST ECDSA, and Ed25519 public keys. Symmetric and
// private key material is intentionally rejected; use
// xjwt.NewVerificationKey directly for locally configured HMAC secrets.
package jwk
