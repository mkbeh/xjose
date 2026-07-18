// Package josejson contains strict JSON helpers shared by JOSE subpackages.
package josejson

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
)

// DecodeObject decodes one JSON object, rejects duplicate member names, and
// returns every member as raw JSON. Additional members can then be ignored by
// callers according to the relevant JOSE specification.
func DecodeObject(data []byte) (map[string]json.RawMessage, error) {
	decoder := json.NewDecoder(bytes.NewReader(data))

	token, err := decoder.Token()
	if err != nil {
		return nil, fmt.Errorf("read opening JSON token: %w", err)
	}

	delimiter, ok := token.(json.Delim)
	if !ok || delimiter != '{' {
		return nil, fmt.Errorf("expected a JSON object")
	}

	members := make(map[string]json.RawMessage)
	for decoder.More() {
		nameToken, err := decoder.Token()
		if err != nil {
			return nil, fmt.Errorf("read JSON member name: %w", err)
		}

		name, ok := nameToken.(string)
		if !ok {
			return nil, fmt.Errorf("JSON member name is not a string")
		}
		if _, exists := members[name]; exists {
			return nil, fmt.Errorf("duplicate JSON member %q", name)
		}

		var value json.RawMessage
		if err := decoder.Decode(&value); err != nil {
			return nil, fmt.Errorf("decode JSON member %q: %w", name, err)
		}

		members[name] = value
	}

	token, err = decoder.Token()
	if err != nil {
		return nil, fmt.Errorf("read closing JSON token: %w", err)
	}

	delimiter, ok = token.(json.Delim)
	if !ok || delimiter != '}' {
		return nil, fmt.Errorf("expected the end of a JSON object")
	}

	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		if err == nil {
			return nil, fmt.Errorf("unexpected JSON value after object")
		}

		return nil, fmt.Errorf("decode trailing JSON data: %w", err)
	}

	return members, nil
}
