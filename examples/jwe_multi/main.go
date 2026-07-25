package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"log"

	"github.com/go-jose/go-jose/v4"
	"github.com/mkbeh/xjose/jwe"
)

const (
	ordersRecipientKeyID  = "orders-encryption-2026-07"
	billingRecipientKeyID = "billing-encryption-2026-07"
	keySetID              = "encryption-2026-07"

	jweType     = "JWE"
	contentType = "application/json"
	rsaKeyBits  = 2048

	keySetHeader jose.HeaderKey = "keyset"
)

func main() {
	ctx := context.Background()

	// Each recipient owns an independent encryption key pair.
	ordersPrivateKey := generateRSAKey("orders recipient")
	billingPrivateKey := generateRSAKey("billing recipient")

	// Encrypt the payload once and wrap the content-encryption key separately
	// for the orders and billing recipients.
	encrypter, err := jwe.NewMultiEncrypter(
		[]jose.Recipient{
			{
				Algorithm: jose.RSA_OAEP_256,
				Key:       &ordersPrivateKey.PublicKey,
				KeyID:     ordersRecipientKeyID,
			},
			{
				Algorithm: jose.RSA_OAEP_256,
				Key:       &billingPrivateKey.PublicKey,
				KeyID:     billingRecipientKeyID,
			},
		},
		jose.A256GCM,
		jwe.WithType(jweType),
		jwe.WithContentType(contentType),
		jwe.WithHeader(keySetHeader, keySetID),
	)
	if err != nil {
		log.Fatalf("create multi-recipient JWE encrypter: %v", err)
	}

	plaintext := []byte(
		`{"order_id":"order-123","status":"created"}`,
	)
	expectedAuthData := []byte(
		"tenant=acme;record=order-123",
	)

	rawJWE, err := encrypter.EncryptWithAuthData(
		plaintext,
		expectedAuthData,
	)
	if err != nil {
		log.Fatalf("encrypt payload: %v", err)
	}

	// The billing service supplies only its private key. DecryptMulti finds the
	// matching recipient entry and returns its index and merged header.
	decrypter, err := jwe.NewMultiDecrypter(
		billingPrivateKey,
		[]jose.KeyAlgorithm{
			jose.RSA_OAEP_256,
		},
		[]jose.ContentEncryption{
			jose.A256GCM,
		},
		jwe.WithType(jweType),
		jwe.WithContentType(contentType),
	)
	if err != nil {
		log.Fatalf("create multi-recipient JWE decrypter: %v", err)
	}

	decrypted, err := decrypter.DecryptToken(ctx, rawJWE)
	if err != nil {
		log.Fatalf("decrypt payload: %v", err)
	}

	// AAD provides context binding only when compared with context obtained
	// independently by the application.
	if !bytes.Equal(decrypted.AuthData, expectedAuthData) {
		log.Fatal(
			"authenticated data does not match the expected context",
		)
	}

	keySet, ok := decrypted.Header.ExtraHeaders[keySetHeader].(string)
	if !ok {
		log.Fatal("missing or invalid keyset header")
	}

	fmt.Printf("JWE JSON: %s\n\n", rawJWE)
	fmt.Printf("recipient index: %d\n", decrypted.RecipientIndex)
	fmt.Printf("recipient key ID: %s\n", decrypted.Header.KeyID)
	fmt.Printf("keyset ID: %s\n", keySet)
	fmt.Printf("key algorithm: %s\n", decrypted.Header.Algorithm)
	fmt.Printf(
		"content encryption: %s\n",
		decrypted.Header.Encryption,
	)
	fmt.Printf("content type: %s\n", decrypted.Header.ContentType)
	fmt.Printf("plaintext: %s\n", decrypted.Plaintext)
	fmt.Printf("authenticated data: %s\n", decrypted.AuthData)
}

func generateRSAKey(name string) *rsa.PrivateKey {
	privateKey, err := rsa.GenerateKey(rand.Reader, rsaKeyBits)
	if err != nil {
		log.Fatalf("generate %s RSA key: %v", name, err)
	}

	return privateKey
}
