// Package jwks provides secure helpers for parsing, publishing, and resolving
// public JSON Web Key Sets.
//
// [Set] contains validated public asymmetric verification keys and can be used
// directly as a key resolver by the JWT module. [Parse] and [ParseWithLimit]
// reject malformed sets, private or symmetric keys, duplicate key IDs, and
// ambiguous multi-key configurations. [FromStaticKeySet] exports configured
// JWT verification keys as public JWKS documents.
//
// The package performs no network requests, caching, refreshes, or retries.
// Trust in the JWKS source and accepted signing algorithms remains the
// responsibility of the application.
package jwks
