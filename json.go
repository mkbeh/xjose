package xjwt

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"unicode/utf8"
)

const maxJSONDepth = 64

// parseJSONObject validates the entire JSON value, rejects duplicate members
// at every nesting level, and returns the top-level members.
func parseJSONObject(data []byte) (map[string]json.RawMessage, error) {
	if len(data) == 0 {
		return nil, fmt.Errorf("JSON object is empty")
	}
	if !utf8.Valid(data) {
		return nil, fmt.Errorf("JSON object is not valid UTF-8")
	}

	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	first, err := decoder.Token()
	if err != nil {
		return nil, fmt.Errorf("decode JSON: %w", err)
	}
	delim, ok := first.(json.Delim)
	if !ok || delim != '{' {
		return nil, fmt.Errorf("top-level JSON value must be an object")
	}
	if err := consumeJSONObject(decoder, 1); err != nil {
		return nil, err
	}
	if _, err := decoder.Token(); err != io.EOF {
		if err == nil {
			return nil, fmt.Errorf("JSON contains trailing values")
		}
		return nil, fmt.Errorf("decode trailing JSON value: %w", err)
	}

	var members map[string]json.RawMessage
	if err := json.Unmarshal(data, &members); err != nil {
		return nil, fmt.Errorf("decode JSON object: %w", err)
	}
	if members == nil {
		return nil, fmt.Errorf("top-level JSON value must be an object")
	}
	return members, nil
}

func consumeJSONObject(decoder *json.Decoder, depth int) error {
	if depth > maxJSONDepth {
		return fmt.Errorf("JSON nesting exceeds %d levels", maxJSONDepth)
	}
	seen := make(map[string]struct{})
	for decoder.More() {
		keyToken, err := decoder.Token()
		if err != nil {
			return fmt.Errorf("decode JSON object member: %w", err)
		}
		key, ok := keyToken.(string)
		if !ok {
			return fmt.Errorf("JSON object member name must be a string")
		}
		if _, exists := seen[key]; exists {
			return fmt.Errorf("duplicate JSON object member %q", key)
		}
		seen[key] = struct{}{}

		valueToken, err := decoder.Token()
		if err != nil {
			return fmt.Errorf("decode JSON value for %q: %w", key, err)
		}
		if err := consumeJSONValue(decoder, valueToken, depth+1); err != nil {
			return err
		}
	}
	end, err := decoder.Token()
	if err != nil {
		return fmt.Errorf("close JSON object: %w", err)
	}
	if delim, ok := end.(json.Delim); !ok || delim != '}' {
		return fmt.Errorf("invalid JSON object terminator")
	}
	return nil
}

func consumeJSONArray(decoder *json.Decoder, depth int) error {
	if depth > maxJSONDepth {
		return fmt.Errorf("JSON nesting exceeds %d levels", maxJSONDepth)
	}
	for decoder.More() {
		valueToken, err := decoder.Token()
		if err != nil {
			return fmt.Errorf("decode JSON array value: %w", err)
		}
		if err := consumeJSONValue(decoder, valueToken, depth+1); err != nil {
			return err
		}
	}
	end, err := decoder.Token()
	if err != nil {
		return fmt.Errorf("close JSON array: %w", err)
	}
	if delim, ok := end.(json.Delim); !ok || delim != ']' {
		return fmt.Errorf("invalid JSON array terminator")
	}
	return nil
}

func consumeJSONValue(decoder *json.Decoder, token json.Token, depth int) error {
	delim, ok := token.(json.Delim)
	if !ok {
		return nil
	}
	switch delim {
	case '{':
		return consumeJSONObject(decoder, depth)
	case '[':
		return consumeJSONArray(decoder, depth)
	default:
		return fmt.Errorf("unexpected JSON delimiter %q", delim)
	}
}
