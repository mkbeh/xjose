package doctests_test

import (
	"bytes"
	"crypto/ed25519"
	"time"
)

func must[T any](value T, err error) T {
	if err != nil {
		panic(err)
	}

	return value
}

func testEd25519Key(seedByte byte) (ed25519.PublicKey, ed25519.PrivateKey) {
	seed := bytes.Repeat([]byte{seedByte}, ed25519.SeedSize)
	privateKey := ed25519.NewKeyFromSeed(seed)

	publicKey, ok := privateKey.Public().(ed25519.PublicKey)
	if !ok {
		panic("unexpected Ed25519 public key type")
	}

	return publicKey, privateKey
}

func testTime() time.Time {
	return time.Date(2026, time.July, 26, 12, 0, 0, 0, time.UTC)
}
