package doctests_test

import (
	"encoding/json"
	"fmt"

	gojwt "github.com/golang-jwt/jwt/v5"
	"github.com/mkbeh/xjose/jwk"
	"github.com/mkbeh/xjose/jwt"
)

func Example_jwkRoundTrip() {
	// Deterministic key material keeps the example reproducible.
	// Generate or load keys securely in production.
	publicKey, _ := testEd25519Key(0x31)

	verificationKey := must(jwt.NewVerificationKey(
		"signing-key",
		gojwt.SigningMethodEdDSA,
		publicKey,
	))

	key := must(jwk.FromVerificationKey(verificationKey))
	data := must(json.Marshal(key))
	parsed := must(jwk.Parse(data))
	thumbprint := must(jwk.ThumbprintID(parsed))
	restored := must(jwk.ToVerificationKey(
		parsed,
		gojwt.SigningMethodEdDSA,
	))

	fmt.Println(restored.ID())
	fmt.Println(restored.Method().Alg())
	fmt.Println(len(thumbprint))

	// Output:
	// signing-key
	// EdDSA
	// 43
}
