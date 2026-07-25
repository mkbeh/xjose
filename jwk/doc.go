// Package jwk provides helpers for parsing, exporting, and identifying public
// JSON Web Keys.
//
// The package accepts public asymmetric keys only. It validates JWK structure,
// converts keys to and from algorithm-bound JWT verification keys, enforces
// compatible algorithm and key-use metadata, and calculates RFC 7638
// SHA-256 thumbprint identifiers.
//
// [Parse] should be used for externally supplied JWK documents because direct
// JSON unmarshalling into [Key] bypasses the package's public-key validation.
//
// Successful parsing establishes only that the JWK contains valid public key
// material. Trust in the key source, issuer, and intended purpose remains the
// responsibility of the application.
package jwk
