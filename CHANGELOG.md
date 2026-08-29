# Changelog

## jwt/v0.3.0

### Changed

* **Minimum Go version:** Raised the minimum supported Go version from Go 1.26 to Go 1.27. No public API changes.

## jws/v0.3.0

### Changed

* **Minimum Go version:** Raised the minimum supported Go version from Go 1.26 to Go 1.27. No public API changes.

## jwe/v0.3.0

### Changed

* **Minimum Go version:** Raised the minimum supported Go version from Go 1.26 to Go 1.27. No public API changes.
* **JWT dependency:** Updated `github.com/mkbeh/xjose/jwt` from `v0.2.0` to `v0.3.0`.

## jwk/v0.3.0

### Changed

* **Minimum Go version:** Raised the minimum supported Go version from Go 1.26 to Go 1.27. No public API changes.
* **JWT dependency:** Updated `github.com/mkbeh/xjose/jwt` from `v0.2.0` to `v0.3.0`.

## jwt/v0.2.0

Initial release of the `jwt` module for issuing and verifying signed JSON Web Tokens with application-defined claims,
algorithm-bound keys, and configurable verification policies.

### Added

* **Signing and verification:** APIs for issuing and verifying Compact JWTs with application-defined claim types
  implementing the upstream `jwt.Claims` interface.
* **Algorithm-bound keys:** `SigningKey` and `VerificationKey` types that bind key material to an expected signing
  method.
* **Verification policies:** Required algorithm allowlists, expiration validation by default, strict Compact JWT
  parsing, and configurable token-size limits.
* **Claim validation:** Policies for issuer (`iss`), audience (`aud`), subject (`sub`), issued-at (`iat`), not-before
  (`nbf`), maximum declared lifetime, maximum token age, and clock leeway.
* **Token-type validation:** Protected `typ` header configuration for separating tokens used for different purposes.
* **Key resolution:** Static verification keys, `StaticKeySet`, and custom `KeyResolver` implementations for trusted
  `kid`-based key selection and rotation.
* **External signing:** Context-aware signing through `crypto.Signer`, custom signing functions, and application-managed
  signing backends.
* **Key parsing and serialization:** PEM and DER helpers for RSA, ECDSA, and Ed25519 public and private key material.

## jws/v0.2.0

Initial release of the `jws` module for signing and verifying arbitrary byte payloads using Compact and JSON Web
Signature serializations.

### Added

* **Compact and detached JWS:** Signing and verification of Compact JWS with embedded payloads or detached payloads
  supplied separately as exact byte sequences.
* **JWS JSON Serialization:** Creation and verification of Flattened JWS with one signature and General JWS with
  multiple independent signatures over the same payload.
* **Signature policies:** Built-in policies requiring any valid signature, all signatures, specific canonical signer
  identities, a threshold of trusted identities, or custom application-defined criteria.
* **Algorithm and header policies:** Explicit signature-algorithm allowlists and validation of protected `typ` and `cty`
  values.
* **Key resolution:** Static verification material, public JWKs, JWK Sets, opaque verifiers, and custom `KeyResolver`
  implementations for application-managed key selection.
* **External signing and verification:** Integration with application-managed cryptographic backends through
  `jose.OpaqueSigner` and `jose.OpaqueVerifier`.
* **Protected headers:** Configuration of application-specific protected parameters while preventing reserved-header
  overrides and rejecting unsupported critical JOSE extensions.

## jwe/v0.2.0

Initial release of the `jwe` module for encrypting and decrypting arbitrary byte payloads using Compact and JSON Web
Encryption serializations.

### Added

* **Compact JWE:** Encryption and decryption of byte payloads for a single recipient using Compact JWE Serialization.
* **JWE JSON Serialization:** Flattened serialization for one recipient and General serialization for multiple
  recipients sharing the same ciphertext with independent key-management parameters.
* **Algorithm and header policies:** Independent allowlists for key-management (`alg`) and content-encryption (`enc`)
  algorithms, with validation of configured protected `typ`, `cty`, and compression parameters.
* **Additional Authenticated Data:** Authentication of unencrypted application context through the external AAD field in
  JWE JSON Serialization.
* **Key resolution:** Static decryption keys and custom `KeyResolver` implementations for application-managed key
  selection.
* **Protected headers:** Configuration of standard and application-specific protected parameters, with authenticated
  header values available after successful decryption.
* **Nested JWT:** Sign-then-encrypt orchestration with decryption and authentication of the outer JWE followed by
  verification of the inner signed JWT.

## jwk/v0.2.0

Initial release of the `jwk` module for working with public JSON Web Keys and JWK Sets, including parsing,
serialization, JWT verification integration, key resolution, and RFC 7638 thumbprints.

### Added

* **JWK operations:** Parsing, validation, construction, and serialization of public asymmetric JWKs using the upstream
  `jose.JSONWebKey` representation.
* **JWK Set operations:** Construction, parsing, inspection, and serialization of standard `{"keys":[...]}` documents
  containing public verification keys.
* **JWT integration:** Conversion between public JWKs and algorithm-bound `jwt.VerificationKey` values, including export
  from `jwt.StaticKeySet`.
* **Key resolution:** `Set` implements `jwt.KeyResolver` with exact protected `kid` matching for named keys and support
  for a single anonymous key when the token omits `kid`.
* **Metadata enforcement:** JWK `alg` and `use` values, when present, constrain conversion and signature verification
  without selecting the verification algorithm.
* **Public-key restrictions:** Private keys, symmetric secrets, malformed key material, empty sets, duplicate key IDs,
  and ambiguous multi-key sets are rejected.
* **RFC 7638 thumbprints:** Generation of unpadded Base64URL-encoded SHA-256 thumbprints derived from canonical public
  key members.