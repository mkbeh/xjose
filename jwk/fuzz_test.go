package jwk

import (
	"encoding/json"
	"testing"
)

func FuzzParse(f *testing.F) {
	for _, testCase := range asymmetricKeyFixtures(f) {
		data, err := json.Marshal(Key{
			Key:       testCase.publicKey,
			KeyID:     testCase.keyID,
			Algorithm: testCase.method.Alg(),
			Use:       keyUseSignature,
		})
		if err != nil {
			f.Fatalf("marshal seed JWK: %v", err)
		}

		f.Add(data)
	}

	f.Add([]byte(`{}`))
	f.Add([]byte(`null`))
	f.Add([]byte(`{"kty":"RSA","n":"***","e":"AQAB"}`))
	f.Add([]byte(`not-json`))

	f.Fuzz(func(t *testing.T, data []byte) {
		key, err := Parse(data)
		if err != nil {
			return
		}

		if !key.Valid() {
			t.Fatal("Parse() succeeded with an invalid JWK")
		}
		if !key.IsPublic() {
			t.Fatal("Parse() succeeded with a non-public JWK")
		}

		encoded, err := json.Marshal(key)
		if err != nil {
			t.Fatalf("json.Marshal() error = %v", err)
		}

		roundTrip, err := Parse(encoded)
		if err != nil {
			t.Fatalf("Parse(json.Marshal(key)) error = %v", err)
		}

		firstThumbprint, err := ThumbprintID(key)
		if err != nil {
			t.Fatalf("ThumbprintID() error = %v", err)
		}
		secondThumbprint, err := ThumbprintID(roundTrip)
		if err != nil {
			t.Fatalf("ThumbprintID(roundTrip) error = %v", err)
		}
		if firstThumbprint != secondThumbprint {
			t.Fatalf(
				"thumbprint changed after round trip: %q != %q",
				firstThumbprint,
				secondThumbprint,
			)
		}
	})
}
