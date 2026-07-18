package jwk

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"unicode/utf8"

	xjwt "github.com/mkbeh/xjwt"
	"github.com/mkbeh/xjwt/internal/josejson"
)

const (
	// KeyTypeRSA identifies an RSA JWK.
	KeyTypeRSA = "RSA"

	// KeyTypeEC identifies a NIST elliptic-curve JWK.
	KeyTypeEC = "EC"

	// KeyTypeOKP identifies an octet key pair JWK such as Ed25519.
	KeyTypeOKP = "OKP"

	maxParameterLength = 16 * 1024
)

var strictBase64URL = base64.RawURLEncoding.Strict()

// Key is an immutable public JSON Web Key suitable for signature
// verification. An empty Algorithm means that the JWK omitted alg; the key is
// then bound to the token's algorithm when VerificationKey is called.
type Key struct {
	id         string
	algorithm  xjwt.Algorithm
	use        string
	operations []string
	keyType    string
	curve      string
	value      any
}

// Parse parses one public signature-verification JWK. Unknown members are
// ignored, while duplicate member names and private key material are rejected.
func Parse(data []byte) (Key, error) {
	members, err := josejson.DecodeObject(data)
	if err != nil {
		return Key{}, fmt.Errorf("%w: decode object: %w", ErrInvalid, err)
	}

	keyType, err := requiredString(members, "kty")
	if err != nil {
		return Key{}, err
	}
	switch keyType {
	case KeyTypeRSA, KeyTypeEC, KeyTypeOKP:
	case "oct":
		return Key{}, fmt.Errorf("%w: symmetric JWKs are not public verification keys", ErrPrivateKeyMaterial)
	default:
		return Key{}, fmt.Errorf("%w: %q", ErrUnsupportedKeyType, keyType)
	}
	if err := rejectPrivateMaterial(keyType, members); err != nil {
		return Key{}, err
	}

	id, err := optionalString(members, "kid")
	if err != nil {
		return Key{}, err
	}

	algorithm, err := optionalAlgorithm(members)
	if err != nil {
		return Key{}, err
	}

	use, operations, err := parseUsage(members)
	if err != nil {
		return Key{}, err
	}

	key := Key{
		id:         id,
		algorithm:  algorithm,
		use:        use,
		operations: operations,
		keyType:    keyType,
	}

	switch keyType {
	case KeyTypeRSA:
		value, err := parseRSA(members, algorithm)
		if err != nil {
			return Key{}, err
		}
		key.value = value
	case KeyTypeEC:
		value, curve, err := parseEC(members, algorithm)
		if err != nil {
			return Key{}, err
		}
		key.value = value
		key.curve = curve
	case KeyTypeOKP:
		value, curve, err := parseOKP(members, algorithm)
		if err != nil {
			return Key{}, err
		}
		key.value = value
		key.curve = curve
	}

	candidate := algorithm
	if candidate == "" {
		candidate = defaultAlgorithm(key)
	}
	if _, err := key.VerificationKey(candidate); err != nil {
		return Key{}, fmt.Errorf("%w: validate public key: %w", ErrInvalid, err)
	}

	return key, nil
}

// NewVerificationKey creates a public JWK from verified asymmetric key
// material. The resulting JWK declares use "sig", key_ops ["verify"], and the
// supplied algorithm.
func NewVerificationKey(
	id string,
	algorithm xjwt.Algorithm,
	publicKey crypto.PublicKey,
) (Key, error) {
	if !algorithm.IsSupported() {
		return Key{}, fmt.Errorf("%w: %q", xjwt.ErrInvalidAlgorithm, algorithm)
	}

	if _, err := xjwt.NewVerificationKey(id, algorithm, publicKey); err != nil {
		return Key{}, err
	}

	key := Key{
		id:         id,
		algorithm:  algorithm,
		use:        "sig",
		operations: []string{"verify"},
	}

	switch algorithm {
	case xjwt.RS256, xjwt.RS384, xjwt.RS512,
		xjwt.PS256, xjwt.PS384, xjwt.PS512:
		value, ok := publicKey.(*rsa.PublicKey)
		if !ok {
			return Key{}, fmt.Errorf("%w: RSA algorithm requires *rsa.PublicKey", ErrInvalid)
		}
		key.keyType = KeyTypeRSA
		key.value = cloneRSAPublicKey(value)
	case xjwt.ES256, xjwt.ES384, xjwt.ES512:
		value, ok := publicKey.(*ecdsa.PublicKey)
		if !ok {
			return Key{}, fmt.Errorf("%w: ECDSA algorithm requires *ecdsa.PublicKey", ErrInvalid)
		}
		key.keyType = KeyTypeEC
		key.curve = curveNameForAlgorithm(algorithm)
		key.value = cloneECDSAPublicKey(value)
	case xjwt.Ed25519:
		value, ok := publicKey.(ed25519.PublicKey)
		if !ok {
			return Key{}, fmt.Errorf("%w: %s requires ed25519.PublicKey", ErrInvalid, algorithm)
		}
		key.keyType = KeyTypeOKP
		key.curve = "Ed25519"
		key.value = ed25519.PublicKey(bytes.Clone(value))
	default:
		return Key{}, fmt.Errorf(
			"%w: symmetric keys must not be represented by a public JWK",
			ErrPrivateKeyMaterial,
		)
	}

	return key, nil
}

// ID returns the optional kid value.
func (k Key) ID() string {
	return k.id
}

// Algorithm returns the optional alg value. The empty value means alg was not
// present in the parsed JWK.
func (k Key) Algorithm() xjwt.Algorithm {
	return k.algorithm
}

// KeyType returns the kty value.
func (k Key) KeyType() string {
	return k.keyType
}

// Curve returns the optional crv value.
func (k Key) Curve() string {
	return k.curve
}

// Use returns the optional use value.
func (k Key) Use() string {
	return k.use
}

// Operations returns a copy of key_ops.
func (k Key) Operations() []string {
	return append([]string(nil), k.operations...)
}

// Validate verifies that the JWK contains supported public key material and
// internally consistent metadata.
func (k Key) Validate() error {
	algorithm := k.algorithm
	if algorithm == "" {
		algorithm = defaultAlgorithm(k)
	}
	if algorithm == "" {
		return fmt.Errorf("%w: JWK is not initialized", ErrInvalid)
	}

	_, err := k.VerificationKey(algorithm)

	return err
}

// VerificationKey binds the JWK to algorithm and returns a validated JWT
// verification key. If the JWK contains alg, it must exactly match algorithm.
func (k Key) VerificationKey(algorithm xjwt.Algorithm) (xjwt.VerificationKey, error) {
	if k.value == nil || k.keyType == "" {
		return xjwt.VerificationKey{}, fmt.Errorf("%w: JWK is not initialized", ErrInvalid)
	}
	if !algorithm.IsSupported() {
		return xjwt.VerificationKey{}, fmt.Errorf("%w: %q", xjwt.ErrInvalidAlgorithm, algorithm)
	}
	if k.algorithm != "" && k.algorithm != algorithm {
		return xjwt.VerificationKey{}, fmt.Errorf(
			"%w: JWK alg %q does not match %q",
			xjwt.ErrUnexpectedAlgorithm,
			k.algorithm,
			algorithm,
		)
	}
	if !compatible(k, algorithm) {
		return xjwt.VerificationKey{}, fmt.Errorf(
			"%w: JWK %s/%s cannot be used with %s",
			xjwt.ErrUnexpectedAlgorithm,
			k.keyType,
			k.curve,
			algorithm,
		)
	}

	return xjwt.NewVerificationKey(k.id, algorithm, clonePublicKey(k.value))
}

// MarshalJSON serializes the public JWK without private or symmetric key
// material.
func (k Key) MarshalJSON() ([]byte, error) {
	if k.value == nil || k.keyType == "" {
		return nil, fmt.Errorf("%w: JWK is not initialized", ErrInvalid)
	}

	wire := wireKey{
		KeyType:    k.keyType,
		Use:        k.use,
		Operations: append([]string(nil), k.operations...),
		Algorithm:  k.algorithm.String(),
		KeyID:      k.id,
		Curve:      k.curve,
	}

	switch value := k.value.(type) {
	case *rsa.PublicKey:
		wire.Modulus = encodeUInt(value.N)
		wire.Exponent = encodeUInt(big.NewInt(int64(value.E)))
	case *ecdsa.PublicKey:
		size := coordinateSize(k.curve)
		if size == 0 {
			return nil, fmt.Errorf("%w: %w: %q", ErrInvalid, ErrUnsupportedCurve, k.curve)
		}
		wire.X = encodeFixed(value.X, size)
		wire.Y = encodeFixed(value.Y, size)
	case ed25519.PublicKey:
		wire.X = strictBase64URL.EncodeToString(value)
	default:
		return nil, fmt.Errorf("%w: unsupported public key value %T", ErrInvalid, k.value)
	}

	return json.Marshal(wire)
}

type wireKey struct {
	KeyType    string   `json:"kty"`
	Use        string   `json:"use,omitempty"`
	Operations []string `json:"key_ops,omitempty"`
	Algorithm  string   `json:"alg,omitempty"`
	KeyID      string   `json:"kid,omitempty"`
	Curve      string   `json:"crv,omitempty"`
	X          string   `json:"x,omitempty"`
	Y          string   `json:"y,omitempty"`
	Modulus    string   `json:"n,omitempty"`
	Exponent   string   `json:"e,omitempty"`
}

func requiredString(members map[string]json.RawMessage, name string) (string, error) {
	value, exists := members[name]
	if !exists {
		return "", fmt.Errorf("%w: missing %s", ErrInvalid, name)
	}

	text, err := decodeString(value, name)
	if err != nil {
		return "", err
	}
	if text == "" {
		return "", fmt.Errorf("%w: %s must not be empty", ErrInvalid, name)
	}

	return text, nil
}

func optionalString(members map[string]json.RawMessage, name string) (string, error) {
	value, exists := members[name]
	if !exists {
		return "", nil
	}

	return decodeString(value, name)
}

func decodeString(value json.RawMessage, name string) (string, error) {
	var text string
	if err := json.Unmarshal(value, &text); err != nil {
		return "", fmt.Errorf("%w: %s must be a string: %w", ErrInvalid, name, err)
	}
	if !utf8.ValidString(text) {
		return "", fmt.Errorf("%w: %s is not valid UTF-8", ErrInvalid, name)
	}

	return text, nil
}

func optionalAlgorithm(members map[string]json.RawMessage) (xjwt.Algorithm, error) {
	value, exists := members["alg"]
	if !exists {
		return "", nil
	}

	text, err := decodeString(value, "alg")
	if err != nil {
		return "", err
	}
	if text == "" {
		return "", fmt.Errorf("%w: alg must not be empty", ErrInvalid)
	}

	algorithm, err := xjwt.ParseAlgorithm(text)
	if err != nil {
		return "", fmt.Errorf("%w: alg %q is not a supported JWS algorithm: %w", ErrNotForSignature, text, err)
	}

	return algorithm, nil
}

func parseUsage(members map[string]json.RawMessage) (string, []string, error) {
	use, err := optionalString(members, "use")
	if err != nil {
		return "", nil, err
	}
	if use != "" && use != "sig" {
		return "", nil, fmt.Errorf("%w: use is %q", ErrNotForSignature, use)
	}

	raw, exists := members["key_ops"]
	if !exists {
		return use, nil, nil
	}

	var operations []string
	if err := json.Unmarshal(raw, &operations); err != nil {
		return "", nil, fmt.Errorf("%w: key_ops must be an array of strings: %w", ErrInvalid, err)
	}

	seen := make(map[string]struct{}, len(operations))
	hasVerify := false
	hasUnrelated := false
	for _, operation := range operations {
		if operation == "" {
			return "", nil, fmt.Errorf("%w: empty operation", ErrInvalidKeyOperation)
		}
		if _, duplicate := seen[operation]; duplicate {
			return "", nil, fmt.Errorf("%w: duplicate %q", ErrInvalidKeyOperation, operation)
		}
		seen[operation] = struct{}{}

		switch operation {
		case "verify":
			hasVerify = true
		case "sign":
		case "encrypt", "decrypt", "wrapKey", "unwrapKey", "deriveKey", "deriveBits":
			hasUnrelated = true
		default:
			// Extension operations are not understood by this package. A key
			// that does not also declare verify is simply not a verification
			// key; combining an unknown operation with verify is rejected below.
			hasUnrelated = true
		}
	}

	if !hasVerify {
		if use == "sig" && hasUnrelated {
			return "", nil, fmt.Errorf(
				"%w: signature use conflicts with non-signature key_ops",
				ErrInvalidKeyOperation,
			)
		}

		return "", nil, fmt.Errorf("%w: key_ops does not include verify", ErrNotForSignature)
	}
	if hasUnrelated {
		return "", nil, fmt.Errorf(
			"%w: verify is combined with an unrelated operation",
			ErrInvalidKeyOperation,
		)
	}
	return use, append([]string(nil), operations...), nil
}

func parseRSA(
	members map[string]json.RawMessage,
	algorithm xjwt.Algorithm,
) (*rsa.PublicKey, error) {
	if containsAny(members, "d", "p", "q", "dp", "dq", "qi", "oth") {
		return nil, fmt.Errorf("%w: RSA private parameters are present", ErrPrivateKeyMaterial)
	}
	if algorithm != "" && !isRSAAlgorithm(algorithm) {
		return nil, fmt.Errorf("%w: RSA key declares %s", xjwt.ErrUnexpectedAlgorithm, algorithm)
	}

	modulusText, err := requiredString(members, "n")
	if err != nil {
		return nil, err
	}
	exponentText, err := requiredString(members, "e")
	if err != nil {
		return nil, err
	}

	modulusBytes, err := decodeUInt("n", modulusText)
	if err != nil {
		return nil, err
	}
	exponentBytes, err := decodeUInt("e", exponentText)
	if err != nil {
		return nil, err
	}

	exponentValue := new(big.Int).SetBytes(exponentBytes)
	if !exponentValue.IsInt64() {
		return nil, fmt.Errorf("%w: RSA exponent does not fit an integer", ErrInvalid)
	}
	exponent := exponentValue.Int64()
	maxInt := int64(^uint(0) >> 1)
	if exponent <= 0 || exponent > maxInt {
		return nil, fmt.Errorf("%w: RSA exponent is out of range", ErrInvalid)
	}

	key := &rsa.PublicKey{
		N: new(big.Int).SetBytes(modulusBytes),
		E: int(exponent),
	}

	candidate := algorithm
	if candidate == "" {
		candidate = xjwt.RS256
	}
	if _, err := xjwt.NewVerificationKey("", candidate, key); err != nil {
		return nil, fmt.Errorf("%w: RSA public key: %w", ErrInvalid, err)
	}

	return key, nil
}

func parseEC(
	members map[string]json.RawMessage,
	algorithm xjwt.Algorithm,
) (*ecdsa.PublicKey, string, error) {
	if containsAny(members, "d") {
		return nil, "", fmt.Errorf("%w: EC private parameter is present", ErrPrivateKeyMaterial)
	}

	curveName, err := requiredString(members, "crv")
	if err != nil {
		return nil, "", err
	}

	curve, expectedAlgorithm, size := curveParameters(curveName)
	if curve == nil {
		return nil, "", fmt.Errorf("%w: %q", ErrUnsupportedCurve, curveName)
	}
	if algorithm != "" && algorithm != expectedAlgorithm {
		return nil, "", fmt.Errorf(
			"%w: curve %s requires %s, got %s",
			xjwt.ErrUnexpectedAlgorithm,
			curveName,
			expectedAlgorithm,
			algorithm,
		)
	}

	xText, err := requiredString(members, "x")
	if err != nil {
		return nil, "", err
	}
	yText, err := requiredString(members, "y")
	if err != nil {
		return nil, "", err
	}

	xBytes, err := decodeFixed("x", xText, size)
	if err != nil {
		return nil, "", err
	}
	yBytes, err := decodeFixed("y", yText, size)
	if err != nil {
		return nil, "", err
	}

	key := &ecdsa.PublicKey{
		Curve: curve,
		X:     new(big.Int).SetBytes(xBytes),
		Y:     new(big.Int).SetBytes(yBytes),
	}
	if _, err := xjwt.NewVerificationKey("", expectedAlgorithm, key); err != nil {
		return nil, "", fmt.Errorf("%w: EC public key: %w", ErrInvalid, err)
	}

	return key, curveName, nil
}

func parseOKP(
	members map[string]json.RawMessage,
	algorithm xjwt.Algorithm,
) (ed25519.PublicKey, string, error) {
	if containsAny(members, "d") {
		return nil, "", fmt.Errorf("%w: OKP private parameter is present", ErrPrivateKeyMaterial)
	}

	curveName, err := requiredString(members, "crv")
	if err != nil {
		return nil, "", err
	}
	if curveName != "Ed25519" {
		return nil, "", fmt.Errorf("%w: %q", ErrUnsupportedCurve, curveName)
	}
	if algorithm != "" && algorithm != xjwt.Ed25519 {
		return nil, "", fmt.Errorf(
			"%w: Ed25519 key requires Ed25519, got %s",
			xjwt.ErrUnexpectedAlgorithm,
			algorithm,
		)
	}

	xText, err := requiredString(members, "x")
	if err != nil {
		return nil, "", err
	}
	x, err := decodeFixed("x", xText, ed25519.PublicKeySize)
	if err != nil {
		return nil, "", err
	}

	key := ed25519.PublicKey(bytes.Clone(x))
	candidate := algorithm
	if candidate == "" {
		candidate = xjwt.Ed25519
	}
	if _, err := xjwt.NewVerificationKey("", candidate, key); err != nil {
		return nil, "", fmt.Errorf("%w: Ed25519 public key: %w", ErrInvalid, err)
	}

	return key, curveName, nil
}

func decodeUInt(name, text string) ([]byte, error) {
	decoded, err := decodeBase64URL(name, text)
	if err != nil {
		return nil, err
	}
	if len(decoded) > 1 && decoded[0] == 0 {
		return nil, fmt.Errorf("%w: %s has a non-minimal unsigned integer encoding", ErrInvalid, name)
	}

	return decoded, nil
}

func decodeFixed(name, text string, size int) ([]byte, error) {
	decoded, err := decodeBase64URL(name, text)
	if err != nil {
		return nil, err
	}
	if len(decoded) != size {
		return nil, fmt.Errorf("%w: %s must decode to %d bytes", ErrInvalid, name, size)
	}

	return decoded, nil
}

func decodeBase64URL(name, text string) ([]byte, error) {
	if text == "" || len(text) > maxParameterLength {
		return nil, fmt.Errorf("%w: %s has an invalid length", ErrInvalid, name)
	}

	decoded, err := strictBase64URL.DecodeString(text)
	if err != nil {
		return nil, fmt.Errorf("%w: %s is not canonical base64url: %w", ErrInvalid, name, err)
	}
	if len(decoded) == 0 || strictBase64URL.EncodeToString(decoded) != text {
		return nil, fmt.Errorf("%w: %s is not canonical base64url", ErrInvalid, name)
	}

	return decoded, nil
}

func rejectPrivateMaterial(keyType string, members map[string]json.RawMessage) error {
	switch keyType {
	case KeyTypeRSA:
		if containsAny(members, "d", "p", "q", "dp", "dq", "qi", "oth") {
			return fmt.Errorf("%w: RSA private parameters are present", ErrPrivateKeyMaterial)
		}
	case KeyTypeEC, KeyTypeOKP:
		if containsAny(members, "d") {
			return fmt.Errorf("%w: private parameter is present", ErrPrivateKeyMaterial)
		}
	case "oct":
		return fmt.Errorf("%w: symmetric JWKs are not public verification keys", ErrPrivateKeyMaterial)
	}

	return nil
}

func containsAny(members map[string]json.RawMessage, names ...string) bool {
	for _, name := range names {
		if _, exists := members[name]; exists {
			return true
		}
	}

	return false
}

func compatible(key Key, algorithm xjwt.Algorithm) bool {
	switch key.keyType {
	case KeyTypeRSA:
		return isRSAAlgorithm(algorithm)
	case KeyTypeEC:
		return curveNameForAlgorithm(algorithm) == key.curve
	case KeyTypeOKP:
		return key.curve == "Ed25519" &&
			(algorithm == xjwt.Ed25519)
	default:
		return false
	}
}

func defaultAlgorithm(key Key) xjwt.Algorithm {
	switch key.keyType {
	case KeyTypeRSA:
		return xjwt.RS256
	case KeyTypeEC:
		switch key.curve {
		case "P-256":
			return xjwt.ES256
		case "P-384":
			return xjwt.ES384
		case "P-521":
			return xjwt.ES512
		}
	case KeyTypeOKP:
		if key.curve == "Ed25519" {
			return xjwt.Ed25519
		}
	}

	return ""
}

func isRSAAlgorithm(algorithm xjwt.Algorithm) bool {
	switch algorithm {
	case xjwt.RS256, xjwt.RS384, xjwt.RS512,
		xjwt.PS256, xjwt.PS384, xjwt.PS512:
		return true
	default:
		return false
	}
}

func curveNameForAlgorithm(algorithm xjwt.Algorithm) string {
	switch algorithm {
	case xjwt.ES256:
		return "P-256"
	case xjwt.ES384:
		return "P-384"
	case xjwt.ES512:
		return "P-521"
	default:
		return ""
	}
}

func curveParameters(name string) (elliptic.Curve, xjwt.Algorithm, int) {
	switch name {
	case "P-256":
		return elliptic.P256(), xjwt.ES256, 32
	case "P-384":
		return elliptic.P384(), xjwt.ES384, 48
	case "P-521":
		return elliptic.P521(), xjwt.ES512, 66
	default:
		return nil, "", 0
	}
}

func coordinateSize(curve string) int {
	_, _, size := curveParameters(curve)

	return size
}

func clonePublicKey(value any) any {
	switch key := value.(type) {
	case *rsa.PublicKey:
		return cloneRSAPublicKey(key)
	case *ecdsa.PublicKey:
		return cloneECDSAPublicKey(key)
	case ed25519.PublicKey:
		return ed25519.PublicKey(bytes.Clone(key))
	default:
		return nil
	}
}

func cloneRSAPublicKey(key *rsa.PublicKey) *rsa.PublicKey {
	if key == nil {
		return nil
	}

	clone := &rsa.PublicKey{E: key.E}
	if key.N != nil {
		clone.N = new(big.Int).Set(key.N)
	}

	return clone
}

func cloneECDSAPublicKey(key *ecdsa.PublicKey) *ecdsa.PublicKey {
	if key == nil {
		return nil
	}

	clone := &ecdsa.PublicKey{Curve: key.Curve}
	if key.X != nil {
		clone.X = new(big.Int).Set(key.X)
	}
	if key.Y != nil {
		clone.Y = new(big.Int).Set(key.Y)
	}

	return clone
}

func encodeUInt(value *big.Int) string {
	if value == nil {
		return ""
	}

	return strictBase64URL.EncodeToString(value.Bytes())
}

func encodeFixed(value *big.Int, size int) string {
	if value == nil || size <= 0 {
		return ""
	}

	buffer := make([]byte, size)
	value.FillBytes(buffer)

	return strictBase64URL.EncodeToString(buffer)
}

// IsIgnorable reports whether err describes a JWK that a mixed JWK Set can
// skip because it is not a supported signature-verification key.
func IsIgnorable(err error) bool {
	return errors.Is(err, ErrUnsupportedKeyType) ||
		errors.Is(err, ErrUnsupportedCurve) ||
		errors.Is(err, ErrNotForSignature)
}
