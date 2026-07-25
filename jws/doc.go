// Package jws provides secure helpers for signing and verifying arbitrary byte
// payloads using JSON Web Signature (JWS).
//
// [Signer] and [Verifier] operate on Compact JWS Serialization with embedded or
// detached payloads.
//
// [MultiSigner] and [MultiVerifier] operate on Flattened and General JWS JSON
// Serialization with one or more independent signatures. [MultiVerifier]
// supports resolver-based key selection and configurable application-level
// signature policies.
//
// JWS provides payload integrity and authenticity, but not confidentiality or
// replay protection. The package treats payloads as opaque bytes and does not
// interpret or validate JWT claims.
package jws
