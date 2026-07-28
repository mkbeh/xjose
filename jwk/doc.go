// Package jwk provides helpers for validating, parsing, exporting, identifying,
// publishing, and resolving public JSON Web Keys and JWK Sets.
//
// The package accepts public asymmetric keys only. It validates JWK structure,
// converts keys to and from algorithm-bound JWT verification keys, enforces
// compatible algorithm and key-use metadata, and calculates RFC 7638 SHA-256
// thumbprint identifiers.
//
// [Parse] validates a single externally supplied JWK document. [ParseSet] and
// [ParseSetWithLimit] validate JWK Set documents, enforce deterministic key-ID
// selection, and return a [Set] that implements jwt.KeyResolver.
//
// The package performs no network requests, caching, refreshes, or retries.
// Successful validation establishes only that a document contains valid public
// key material. Trust in the key source, issuer, and intended purpose remains
// the responsibility of the application.
package jwk
