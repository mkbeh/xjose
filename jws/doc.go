// Package jws provides helpers for signing and verifying arbitrary byte
// payloads using JSON Web Signature (JWS).
//
// Signer and Verifier operate on Compact JWS Serialization with one signature
// and support both embedded and detached payloads.
//
// MultiSigner and MultiVerifier operate on Flattened and General JWS JSON
// Serialization with one or more independent signatures. MultiVerifier
// supports configurable application-level signature policies.
//
// JWS provides payload integrity and authenticity, but not encryption or replay
// protection. The package does not interpret JWT claims.
package jws
