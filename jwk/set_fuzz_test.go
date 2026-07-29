package jwk

import (
	"encoding/json"
	"testing"

	"github.com/go-jose/go-jose/v4"
)

func FuzzParseSet(f *testing.F) {
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

		set, err := ParseSet(data)
		if err != nil {
			return
		}

		keys := set.Keys()
		if len(keys) == 0 {
			t.Fatal("ParseSet() succeeded with an empty key set")
		}
		if len(keys) > DefaultMaxSetKeys {
			t.Fatalf("ParseSet() returned %d keys, limit is %d", len(keys), DefaultMaxSetKeys)
		}
		for index, key := range keys {
			if !key.Valid() {
				t.Fatalf("ParseSet() returned invalid key %d", index)
			}
			if !key.IsPublic() {
				t.Fatalf("ParseSet() returned non-public key %d", index)
			}
		}

		encoded, err := json.Marshal(set)
		if err != nil {
			t.Fatalf("json.Marshal(set) error = %v", err)
		}

		roundTrip, err := ParseSet(encoded)
		if err != nil {
			t.Fatalf("ParseSet(json.Marshal(set)) error = %v", err)
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

func FuzzParseSetWithLimit(f *testing.F) {
	fixture := asymmetricKeyFixtures(f)[0]
	f.Add(marshalSet(f, makeKeys(fixture, 3)), uint8(3))
	f.Add([]byte(`{"keys":[]}`), uint8(1))
	f.Add([]byte(`not-json`), uint8(4))

	f.Fuzz(func(t *testing.T, data []byte, rawLimit uint8) {
		if len(data) > 64<<10 {
			return
		}

		limit := int(rawLimit%16) + 1
		set, err := ParseSetWithLimit(data, limit)
		if err != nil {
			return
		}

		keys := set.Keys()
		if len(keys) == 0 {
			t.Fatal("ParseSetWithLimit() succeeded with an empty key set")
		}
		if len(keys) > limit {
			t.Fatalf("ParseSetWithLimit() returned %d keys, limit is %d", len(keys), limit)
		}

		encoded, err := json.Marshal(jose.JSONWebKeySet{Keys: keys})
		if err != nil {
			t.Fatalf("json.Marshal() error = %v", err)
		}
		if _, err := ParseSetWithLimit(encoded, limit); err != nil {
			t.Fatalf("ParseSetWithLimit(round trip) error = %v", err)
		}
	})
}
