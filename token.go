package xjwt

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
)

const (
	// DefaultMaxTokenSize is the default maximum compact JWT size accepted or
	// produced by xjwt.
	DefaultMaxTokenSize  = 16 << 10
	maxDecodedHeaderSize = 4 << 10
)

type compactToken struct {
	signingInput []byte
	header       Header
	payload      []byte
	signature    []byte
	claimMembers map[string]json.RawMessage
}

func parseCompactToken(raw string, maxSize int) (compactToken, error) {
	if raw == "" {
		return compactToken{}, ErrMissingToken
	}
	if maxSize <= 0 {
		return compactToken{}, ErrInvalidConfig
	}
	if len(raw) > maxSize {
		return compactToken{}, fmt.Errorf("%w: got %d bytes, limit is %d", ErrTokenTooLarge, len(raw), maxSize)
	}

	headerSegment, remainder, ok := strings.Cut(raw, ".")
	if !ok {
		return compactToken{}, fmt.Errorf("%w: compact JWT must contain three segments", ErrMalformedToken)
	}
	payloadSegment, signatureSegment, ok := strings.Cut(remainder, ".")
	if !ok || strings.Contains(signatureSegment, ".") {
		return compactToken{}, fmt.Errorf("%w: compact JWT must contain three segments", ErrMalformedToken)
	}
	if headerSegment == "" || payloadSegment == "" || signatureSegment == "" {
		return compactToken{}, fmt.Errorf("%w: compact JWT segments must be non-empty", ErrMalformedToken)
	}

	headerBytes, err := decodeCompactSegment(headerSegment)
	if err != nil {
		return compactToken{}, fmt.Errorf("%w: decode JOSE header: %w", ErrMalformedToken, err)
	}
	if len(headerBytes) > maxDecodedHeaderSize {
		return compactToken{}, fmt.Errorf("%w: JOSE header exceeds %d decoded bytes", ErrMalformedToken, maxDecodedHeaderSize)
	}
	header, err := parseHeader(headerBytes)
	if err != nil {
		return compactToken{}, fmt.Errorf("%w: %w", ErrMalformedToken, err)
	}

	payload, err := decodeCompactSegment(payloadSegment)
	if err != nil {
		return compactToken{}, fmt.Errorf("%w: decode claims: %w", ErrMalformedToken, err)
	}
	claimMembers, err := parseJSONObject(payload)
	if err != nil {
		return compactToken{}, fmt.Errorf("%w: invalid claims set: %w", ErrMalformedToken, err)
	}

	signature, err := decodeCompactSegment(signatureSegment)
	if err != nil {
		return compactToken{}, fmt.Errorf("%w: decode signature: %w", ErrMalformedToken, err)
	}
	if len(signature) == 0 {
		return compactToken{}, fmt.Errorf("%w: signature is empty", ErrMalformedToken)
	}

	return compactToken{
		signingInput: []byte(headerSegment + "." + payloadSegment),
		header:       header,
		payload:      payload,
		signature:    signature,
		claimMembers: claimMembers,
	}, nil
}

func decodeCompactSegment(segment string) ([]byte, error) {
	decoded, err := base64.RawURLEncoding.Strict().DecodeString(segment)
	if err != nil {
		return nil, err
	}
	if base64.RawURLEncoding.EncodeToString(decoded) != segment {
		return nil, fmt.Errorf("non-canonical base64url encoding")
	}
	return decoded, nil
}
