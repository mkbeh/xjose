package xjwt

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"

	jwtv5 "github.com/golang-jwt/jwt/v5"
)

// Signer creates compact signed JWTs with one immutable signing key.
type Signer struct {
	key         SigningKey
	tokenType   string
	includeType bool
	contentType string
	maxSize     int
}

// NewSigner creates a JWT signer.
func NewSigner(key SigningKey, options ...SignerOption) (*Signer, error) {
	if key.sign == nil || key.verification.value == nil {
		return nil, fmt.Errorf("%w: signing key is not initialized", ErrInvalidConfig)
	}
	if _, err := key.algorithm.spec(); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalidConfig, err)
	}
	config := signerConfig{tokenType: "JWT", includeType: true, maxSize: DefaultMaxTokenSize}
	for index, option := range options {
		if option == nil {
			return nil, fmt.Errorf("%w: signer option %d is nil", ErrInvalidConfig, index)
		}
		if err := option.applySigner(&config); err != nil {
			return nil, fmt.Errorf("apply signer option %d: %w", index, err)
		}
	}
	return &Signer{
		key:         key,
		tokenType:   config.tokenType,
		includeType: config.includeType,
		contentType: config.contentType,
		maxSize:     config.maxSize,
	}, nil
}

// Algorithm returns the signer's fixed algorithm.
func (s *Signer) Algorithm() Algorithm {
	if s == nil {
		return ""
	}
	return s.key.algorithm
}

// KeyID returns the signer's optional key identifier.
func (s *Signer) KeyID() string {
	if s == nil {
		return ""
	}
	return s.key.id
}

// Sign serializes claims, signs the JWS signing input, and returns a compact
// JWT. Verification policy is always enforced independently by Verifier.
func (s *Signer) Sign(ctx context.Context, claims jwtv5.Claims) (string, error) {
	if s == nil || s.key.sign == nil || s.maxSize <= 0 {
		return "", ErrInvalidConfig
	}
	if err := ctx.Err(); err != nil {
		return "", err
	}
	if claims == nil {
		return "", fmt.Errorf("%w: %w: claims are nil", ErrSign, ErrInvalidClaims)
	}

	payload, err := json.Marshal(claims)
	if err != nil {
		return "", fmt.Errorf("%w: encode claims: %w", ErrSign, err)
	}
	if _, err := parseJSONObject(payload); err != nil {
		return "", fmt.Errorf("%w: %w: %v", ErrSign, ErrInvalidClaims, err)
	}

	header := Header{
		Algorithm:   s.key.algorithm,
		KeyID:       s.key.id,
		ContentType: s.contentType,
	}
	if s.includeType {
		header.Type = s.tokenType
	}
	headerBytes, err := marshalHeader(header)
	if err != nil {
		return "", fmt.Errorf("%w: encode JOSE header: %w", ErrSign, err)
	}

	headerSegment := base64.RawURLEncoding.EncodeToString(headerBytes)
	payloadSegment := base64.RawURLEncoding.EncodeToString(payload)
	signingInput := []byte(headerSegment + "." + payloadSegment)
	signatureSize, err := expectedSignatureSize(s.key.algorithm, s.key.verification)
	if err != nil {
		return "", fmt.Errorf("%w: determine signature size: %w", ErrSign, err)
	}
	expectedSize := len(signingInput) + 1 + base64.RawURLEncoding.EncodedLen(signatureSize)
	if expectedSize > s.maxSize {
		return "", fmt.Errorf(
			"%w: %w: expected %d bytes, limit is %d",
			ErrSign,
			ErrTokenTooLarge,
			expectedSize,
			s.maxSize,
		)
	}
	if err := ctx.Err(); err != nil {
		return "", err
	}

	signature, err := s.key.sign(ctx, signingInput)
	if err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return "", ctxErr
		}
		return "", fmt.Errorf("%w: create signature: %w", ErrSign, err)
	}
	compact := string(signingInput) + "." + base64.RawURLEncoding.EncodeToString(signature)
	if len(compact) > s.maxSize {
		return "", fmt.Errorf("%w: %w: got %d bytes, limit is %d", ErrSign, ErrTokenTooLarge, len(compact), s.maxSize)
	}
	if err := ctx.Err(); err != nil {
		return "", err
	}
	return compact, nil
}
