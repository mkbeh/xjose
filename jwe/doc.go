// Package jwe provides secure helpers for encrypting and decrypting arbitrary
// byte payloads using Compact and JSON Web Encryption serializations.
//
// The package supports single- and multi-recipient encryption, explicit
// allowlists for key-management and content-encryption algorithms, Additional
// Authenticated Data, resolver-based key selection, protected-header policies,
// configurable resource limits, and nested sign-then-encrypt JWT workflows.
//
// JWE provides confidentiality and ciphertext integrity for the intended
// recipient, but does not by itself authenticate the sender. Use a nested JWT
// or sign the payload before encryption when authenticated origin is required.
package jwe
