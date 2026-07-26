package doctests_test

import (
	"bytes"
	"context"
	"fmt"
	"sort"
	"strings"

	jose "github.com/go-jose/go-jose/v4"
	"github.com/mkbeh/xjose/jws"
)

func Example_jwsCompact() {
	ctx := context.Background()
	key := bytes.Repeat([]byte{0x51}, 32)

	signer := must(jws.NewSigner(
		jws.SigningKey{
			Algorithm: jose.HS256,
			KeyID:     "document-signing-key",
			Key:       key,
		},
		jws.WithType("document+jws"),
		jws.WithContentType("text/plain"),
	))

	raw := must(signer.Sign([]byte("approved")))

	verifier := must(jws.NewVerifier(
		jose.JSONWebKey{
			Key:       key,
			KeyID:     "document-signing-key",
			Algorithm: string(jose.HS256),
			Use:       "sig",
		},
		[]jose.SignatureAlgorithm{jose.HS256},
		jws.WithType("document+jws"),
		jws.WithContentType("text/plain"),
	))

	verified := must(verifier.VerifyMessage(ctx, raw))

	fmt.Println(string(verified.Payload))
	fmt.Println(verified.KeyID)
	fmt.Println(verified.Header.Algorithm)

	// Output:
	// approved
	// document-signing-key
	// HS256
}

func Example_jwsDetached() {
	ctx := context.Background()
	key := bytes.Repeat([]byte{0x52}, 32)
	payload := []byte("detached payload")

	signer := must(jws.NewSigner(
		jws.SigningKey{
			Algorithm: jose.HS256,
			Key:       key,
		},
		jws.WithType("detached+jws"),
	))

	raw := must(signer.SignDetached(payload))

	verifier := must(jws.NewVerifier(
		key,
		[]jose.SignatureAlgorithm{jose.HS256},
		jws.WithType("detached+jws"),
	))

	verified := must(verifier.VerifyDetached(ctx, raw, payload))

	fmt.Println(string(verified.Payload))
	fmt.Println(verified.Header.Type)

	// Output:
	// detached payload
	// detached+jws
}

func Example_jwsMultipleSignatures() {
	ctx := context.Background()
	issuerPublicKey, issuerPrivateKey := testEd25519Key(0x61)
	approvalPublicKey, approvalPrivateKey := testEd25519Key(0x62)

	signer := must(jws.NewMultiSigner(
		[]jws.SigningKey{
			{
				Algorithm: jose.EdDSA,
				KeyID:     "issuer",
				Key:       issuerPrivateKey,
			},
			{
				Algorithm: jose.EdDSA,
				KeyID:     "approver",
				Key:       approvalPrivateKey,
			},
		},
		jws.WithType("approval+jws"),
	))

	raw := must(signer.Sign([]byte("approve order-123")))

	resolver := jws.KeyResolverFunc(func(
		ctx context.Context,
		header jws.Header,
	) (jws.ResolvedKey, error) {
		if err := ctx.Err(); err != nil {
			return jws.ResolvedKey{}, err
		}

		switch header.KeyID {
		case "issuer":
			return jws.ResolvedKey{KeyID: "issuer", Key: issuerPublicKey}, nil
		case "approver":
			return jws.ResolvedKey{KeyID: "approver", Key: approvalPublicKey}, nil
		default:
			return jws.ResolvedKey{}, fmt.Errorf(
				"%w: key ID %q",
				jws.ErrKeyNotFound,
				header.KeyID,
			)
		}
	})

	verifier := must(jws.NewMultiVerifierWithResolver(
		resolver,
		[]jose.SignatureAlgorithm{jose.EdDSA},
		jws.WithType("approval+jws"),
		jws.WithSignaturePolicy(
			jws.RequireKeyIDs("issuer", "approver"),
		),
	))

	verified := must(verifier.VerifyMessage(ctx, raw))

	keyIDs := make([]string, 0, len(verified.Signatures))
	for _, signature := range verified.Signatures {
		if signature.Valid() {
			keyIDs = append(keyIDs, signature.KeyID)
		}
	}
	sort.Strings(keyIDs)

	fmt.Println(string(verified.Payload))
	fmt.Println(len(keyIDs))
	fmt.Println(strings.Join(keyIDs, ","))

	// Output:
	// approve order-123
	// 2
	// approver,issuer
}
