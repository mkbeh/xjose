package jwe

import (
	"bytes"

	"github.com/go-jose/go-jose/v4"
)

func cloneKeyMaterial(key any) any {
	switch key := key.(type) {
	case []byte:
		return bytes.Clone(key)

	case jose.JSONWebKey:
		key.Key = cloneKeyMaterial(key.Key)

		return key

	case *jose.JSONWebKey:
		if key == nil {
			return nil
		}

		cloned := *key
		cloned.Key = cloneKeyMaterial(key.Key)

		return &cloned

	default:
		// RSA, ECDSA and custom key objects are retained as-is and must be
		// treated as immutable.
		return key
	}
}
