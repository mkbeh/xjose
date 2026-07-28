package jwks

import (
	"encoding/json"
	"testing"

	"github.com/go-jose/go-jose/v4"
)

func FuzzParse(f *testing.F) {
	fixtures := asymmetricKeyFixtures(f)
	valid := make([]Key, 0, len(fixtures))
	for _, fixture := range fixtures {
		valid = append(valid, Key{
			Key:       fixture.publicKey,
			KeyID:     fixture.keyID,
			Algorithm: fixture.method.Alg(),
			Use:       keyUseSignature,
		})
	}

	f.Add(marshalSet(f, valid))
	f.Add([]byte(`{"keys":[]}`))
	f.Add([]byte(`{"keys":{}}`))
	f.Add([]byte(`null`))
	f.Add([]byte(`not-json`))

	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 64<<10 {
			return
		}

		set, err := Parse(data)
		if err != nil {
			return
		}

		keys := set.Keys()
		if len(keys) == 0 {
			t.Fatal("Parse() succeeded with an empty key set")
		}
		if len(keys) > DefaultMaxKeys {
			t.Fatalf("Parse() returned %d keys, limit is %d", len(keys), DefaultMaxKeys)
		}
		for index, key := range keys {
			if !key.Valid() {
				t.Fatalf("Parse() returned invalid key %d", index)
			}
			if !key.IsPublic() {
				t.Fatalf("Parse() returned non-public key %d", index)
			}
		}

		encoded, err := json.Marshal(set)
		if err != nil {
			t.Fatalf("json.Marshal(set) error = %v", err)
		}

		roundTrip, err := Parse(encoded)
		if err != nil {
			t.Fatalf("Parse(json.Marshal(set)) error = %v", err)
		}
		if len(roundTrip.Keys()) != len(keys) {
			t.Fatalf(
				"round-trip key count = %d, want %d",
				len(roundTrip.Keys()),
				len(keys),
			)
		}
	})
}

func FuzzParseWithLimit(f *testing.F) {
	fixture := asymmetricKeyFixtures(f)[0]
	f.Add(marshalSet(f, makeKeys(fixture, 3)), uint8(3))
	f.Add([]byte(`{"keys":[]}`), uint8(1))
	f.Add([]byte(`not-json`), uint8(4))

	f.Fuzz(func(t *testing.T, data []byte, rawLimit uint8) {
		if len(data) > 64<<10 {
			return
		}

		limit := int(rawLimit%16) + 1
		set, err := ParseWithLimit(data, limit)
		if err != nil {
			return
		}

		keys := set.Keys()
		if len(keys) == 0 {
			t.Fatal("ParseWithLimit() succeeded with an empty key set")
		}
		if len(keys) > limit {
			t.Fatalf("ParseWithLimit() returned %d keys, limit is %d", len(keys), limit)
		}

		encoded, err := json.Marshal(jose.JSONWebKeySet{Keys: keys})
		if err != nil {
			t.Fatalf("json.Marshal() error = %v", err)
		}
		if _, err := ParseWithLimit(encoded, limit); err != nil {
			t.Fatalf("ParseWithLimit(round trip) error = %v", err)
		}
	})
}
