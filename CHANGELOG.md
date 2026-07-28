# Changelog

## jwt/v0.2.0

Initial release of the `jwt` module, providing secure helpers for issuing and verifying signed JSON Web Tokens with
typed claims and explicit verification policies.

### Added

* **Strict Verification Defaults:** Enforces explicit algorithm allowlists, mandatory expiration checks, configurable
  size limits, and strict Compact JWT parsing.
* **Typed Key Configuration:** Binds signing and verification keys to their expected algorithms, preventing untrusted
  token headers from implicitly changing how key material is interpreted.
* **Flexible Key Resolution:** Supports static key sets and custom `KeyResolver` implementations for `kid`-based key
  selection and application-managed key rotation.
* **External Signing:** Provides context-aware signing APIs backed by `crypto.Signer`, custom signing functions, cloud
  KMS, HashiCorp Vault, hardware security modules, and remote signing services.
* **Validation Policies:** Validates issuer (`iss`), audience (`aud`), subject (`sub`), token type (`typ`), maximum
  token
  lifetime, and maximum token age.
* **Custom Claims:** Decodes claims into application-specific types implementing the upstream `jwt.Claims` interface.
* **Key Parsing Utilities:** Provides PEM and DER parsing helpers for RSA, ECDSA, and Ed25519 key material.
* **Typed Errors:** Provides dedicated errors for expired, malformed, not-yet-valid, unverifiable, oversized, and
  otherwise invalid tokens.

## jws/v0.2.0

Initial release of the `jws` module, providing helpers for signing and verifying arbitrary byte payloads using JSON Web
Signature serializations.

### Added

* **Compact and Detached JWS:** Supports Compact JWS Serialization with embedded payloads and detached signatures
  verified against the exact externally supplied payload bytes.
* **Multiple Signatures:** Creates and verifies Flattened and General JWS JSON Serialization containing one or more
  independent signatures over a shared payload.
* **Signature Policies:** Supports any-signature, all-signatures, trusted-signer, threshold quorum, and custom
  application-defined verification policies.
* **Strict Verification:** Enforces explicit algorithm allowlists and configurable validation of protected token type
  (`typ`), content type (`cty`), and critical JOSE header parameters.
* **Flexible Key Resolution:** Supports static verification keys, JWK and JWKS material, opaque verifiers, and custom
  resolvers backed by application-managed key infrastructure.
* **Opaque Signing:** Delegates private-key operations to cloud KMS, HashiCorp Vault, hardware security modules,
  PKCS#11 adapters, and other external backends through `jose.OpaqueSigner`.
* **Protected Headers:** Supports custom protected headers while rejecting reserved parameters and unsupported critical
  extensions.
* **Resource Limits:** Configurable limits for serialized JWS size, payload size, and the number of signatures accepted
  or produced by JSON serialization workflows.
* **Typed Errors:** Dedicated errors for malformed messages, invalid signatures, unsupported algorithms, failed
  signature policies, and oversized inputs.

## jwe/v0.2.0

Initial release of the `jwe` module, providing helpers for encrypting and decrypting arbitrary byte payloads using JSON
Web Encryption serializations.

### Added

* **Compact JWE:** Encrypts and decrypts arbitrary plaintext for a single recipient using Compact JWE Serialization.
* **JWE JSON Serialization:** Supports Flattened serialization for single-recipient messages and General serialization
  for multi-recipient workflows.
* **Multiple Recipients:** Encrypts one shared ciphertext for multiple recipients while maintaining independent
  key-management parameters for each recipient.
* **Strict Decryption Policies:** Enforces independent allowlists for key-management (`alg`) and content-encryption
  (`enc`) algorithms instead of trusting values supplied by the JWE.
* **Additional Authenticated Data:** Cryptographically binds JSON-serialized ciphertext to visible application context
  without encrypting that context.
* **Flexible Key Resolution:** Supports static decryption keys and custom `KeyResolver` implementations backed by
  application-managed key infrastructure.
* **Protected Header Policies:** Validates expected token type (`typ`), content type (`cty`), compression settings, and
  application-specific protected header parameters.
* **Nested JWT:** Supports sign-then-encrypt workflows with decryption followed by verification of the inner signed JWT.
* **Resource Limits:** Configurable limits for serialized JWE size, plaintext size, and recipient count, including
  validation after decryption and decompression.
* **Typed Errors:** Dedicated errors for malformed messages, unsupported algorithms, decryption failures, policy
  violations, and oversized inputs.

## jwk/v0.2.0

Initial release of the `jwk` module, providing helpers for parsing, validating, exporting, identifying, publishing, and
resolving public JSON Web Keys and JWK Sets.

### Added

* **Public-Key Validation:** Rejects private, symmetric, malformed, empty, and incomplete key material during validated
  JWK and JWK Set construction and parsing.
* **JWT Integration:** Converts public JWK values to and from algorithm-bound `jwt.VerificationKey` configurations and
  implements `jwt.KeyResolver` through validated `Set` values.
* **Metadata Constraints:** Validates compatibility between requested algorithms, declared key algorithm (`alg`), and
  signature use (`use`) during conversion and resolution.
* **Deterministic Key Selection:** Resolves named keys using the protected `kid` header and supports a single anonymous
  key when a token omits `kid`.
* **Validated Key Sets:** Rejects empty sets, duplicate key IDs, and anonymous keys in multi-key configurations.
* **Key Rotation:** Publishes current and previous verification keys together in a validated JWK Set.
* **RFC 7638 Thumbprints:** Generates deterministic Base64URL-encoded SHA-256 thumbprints from public key material.
* **Bounded Set Parsing:** Provides configurable limits for the number of keys accepted from a JWK Set document.
* **Standard Interoperability:** Uses the upstream `jose.JSONWebKey` representation and serializes sets as standard
  `{"keys":[...]}` documents.