package jwt

import "errors"

var (
	ErrInvalidConfig  = errors.New("invalid jwt configuration")
	ErrInvalidKey     = errors.New("invalid jwt key")
	ErrInvalidKeyID   = errors.New("invalid jwt key id")
	ErrDuplicateKeyID = errors.New("duplicate jwt key id")
	ErrMissingKeyID   = errors.New("missing jwt key id")
	ErrUnknownKey     = errors.New("unknown jwt key")
	ErrKeyIDMismatch  = errors.New("jwt key id mismatch")
	ErrKeyUnavailable = errors.New("jwt key unavailable")

	ErrMissingToken        = errors.New("missing jwt")
	ErrMalformedToken      = errors.New("malformed jwt")
	ErrTokenTooLarge       = errors.New("jwt is too large")
	ErrInvalidHeader       = errors.New("invalid jwt header")
	ErrUnexpectedAlgorithm = errors.New("unexpected jwt algorithm")
	ErrUnexpectedType      = errors.New("unexpected jwt type")

	ErrInvalidSignature = errors.New("invalid jwt signature")
	ErrInvalidClaims    = errors.New("invalid jwt claims")
	ErrExpiredToken     = errors.New("expired jwt")
	ErrNotYetValid      = errors.New("jwt is not valid yet")
	ErrIssuedInFuture   = errors.New("jwt issued in the future")
	ErrInvalidLifetime  = errors.New("invalid jwt lifetime")

	ErrSign   = errors.New("sign jwt")
	ErrVerify = errors.New("verify jwt")
)
