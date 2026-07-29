# Multi-recipient JWE

This example encrypts one JSON payload for two independent recipients using General JWE JSON Serialization.

The payload is encrypted once with a content-encryption key (CEK). The CEK is then wrapped separately for the orders and
billing recipients, allowing either recipient to decrypt the same ciphertext with its own private key.

**This example demonstrates:**

* Creating independent RSA encryption keys for two recipients
* Encrypting one payload with `RSA-OAEP-256` and `A256GCM`
* Producing General JWE JSON Serialization
* Assigning a separate `kid` to each recipient
* Adding a shared protected `keyset` header
* Binding the ciphertext to external application context with Additional Authenticated Data (AAD)
* Decrypting with the second recipient's private key
* Reading the selected recipient index, merged header, plaintext, and authenticated data

## Run

From this directory:

```shell
go run .
```

Or from the repository root:

```shell
go run ./examples/jwe_multi
```

## Expected output

The JWE changes on every run because both RSA key pairs and the encryption randomness are generated dynamically.

```text
JWE JSON: <General JWE JSON Serialization>

recipient index: 1
recipient key ID: billing-encryption-2026-07
keyset ID: encryption-2026-07
key algorithm: RSA-OAEP-256
content encryption: A256GCM
content type: application/json
plaintext: {"order_id":"order-123","status":"created"}
authenticated data: tenant=acme;record=order-123
```

The billing key matches the second entry in the recipients slice, so the returned recipient index is `1`.

## How multi-recipient JWE works

Multi-recipient JWE does not encrypt the plaintext independently for every recipient:

```text
plaintext
  → encrypt once with a random CEK
  → one shared ciphertext

CEK
  → wrap with the orders public key
  → wrap with the billing public key
  → one encrypted key per recipient
```

Each recipient receives the same protected header, IV, ciphertext, and authentication tag. Recipient-specific headers
contain the key-management algorithm and `kid`.

During decryption, the application supplies a private key. `DecryptMulti` tries that key against the recipient entries
and returns the first successful recipient. The array order does not indicate which key is current or preferred.

## Additional Authenticated Data

AAD is authenticated together with the protected header and ciphertext, but it is not encrypted and remains visible in
the serialized JWE.

The example compares the returned AAD with application context obtained independently:

```text
tenant=acme;record=order-123
```

Reading the AAD from the JWE without comparing it to an expected value does not provide context binding.

Do not place secrets in AAD.

## Key and header handling

In production:

* Give each recipient an independent key pair
* Keep recipient private keys isolated from other recipients
* Distribute only public encryption keys to senders
* Assign stable `kid` values to key versions
* Rotate recipient keys independently
* Retain previous private keys while messages encrypted for them may still arrive
* Treat custom header values as untrusted until JWE authentication succeeds
* Keep explicit allowlists for key-management and content-encryption algorithms

The shared `keyset` header identifies an application-controlled key generation or profile. It is common to all
recipients and does not replace each recipient's `kid`.