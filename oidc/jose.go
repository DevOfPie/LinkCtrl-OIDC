package oidc

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"hash"
	"math/big"
	"strings"
)

// This file is a JWS verifier and a JWK reader, and it is written out rather
// than depended on.
//
// A module is 8 MiB of linear memory and a package initialization the visitor
// waits for, so a dependency's size is a visitor's latency; and the SDK's whole
// claim is that an add-on needs the standard library and nothing else, which an
// add-on that pulled in a JOSE library would demonstrate the opposite of. What
// is here is the subset OpenID Connect actually uses: the asymmetric algorithms,
// verification only, no JWE, no signing.

// jwsHeader is the protected header of a compact JWS.
type jwsHeader struct {
	Alg string `json:"alg"`
	Kid string `json:"kid"`
	Typ string `json:"typ"`
}

// jws is one parsed compact serialization.
type jws struct {
	header    jwsHeader
	payload   []byte
	signature []byte
	// signed is the exact bytes the signature covers: header and payload as they
	// arrived, with their dot. Kept rather than re-encoded, because base64url is
	// not a canonical encoding of a JSON document and re-encoding would verify a
	// different string than the provider signed.
	signed []byte
}

// b64 is base64url without padding, which is what JOSE uses everywhere.
var b64 = base64.RawURLEncoding

// parseJWS splits a compact serialization and reads its header.
func parseJWS(token string) (*jws, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("a compact JWS has three parts and this has %d", len(parts))
	}
	rawHeader, err := b64.DecodeString(parts[0])
	if err != nil {
		return nil, fmt.Errorf("the header is not base64url: %w", err)
	}
	var h jwsHeader
	if err := json.Unmarshal(rawHeader, &h); err != nil {
		return nil, fmt.Errorf("the header is not JSON: %w", err)
	}
	payload, err := b64.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("the payload is not base64url: %w", err)
	}
	signature, err := b64.DecodeString(parts[2])
	if err != nil {
		return nil, fmt.Errorf("the signature is not base64url: %w", err)
	}
	return &jws{
		header:    h,
		payload:   payload,
		signature: signature,
		signed:    []byte(parts[0] + "." + parts[1]),
	}, nil
}

// JWK is one key from a provider's key set, in the fields this add-on reads.
type JWK struct {
	Kty string `json:"kty"`
	Kid string `json:"kid"`
	Use string `json:"use"`
	Alg string `json:"alg"`
	Crv string `json:"crv"`
	N   string `json:"n"`
	E   string `json:"e"`
	X   string `json:"x"`
	Y   string `json:"y"`
}

// JWKS is a provider's key set.
type JWKS struct {
	Keys []JWK `json:"keys"`
}

// errUnknownKid is the one failure a caller can do something about: the key set
// this add-on has cached does not carry the key the token names, which is what a
// rotation looks like from here. The caller drops the cached document and
// fetches once more.
var errUnknownKid = errors.New("the key set does not carry the key this token names")

// find picks the key a token names.
//
// A `kid` is matched exactly. Without one — legal, and what a provider with a
// single key often sends — the set must hold exactly one usable key, and two is
// refused rather than tried in turn: trying keys in turn is how a verifier ends
// up accepting a token signed by a key that was rotated out for a reason.
func (s JWKS) find(h jwsHeader) (JWK, error) {
	var usable []JWK
	for _, k := range s.Keys {
		if k.Use != "" && k.Use != "sig" {
			continue
		}
		if k.Alg != "" && k.Alg != h.Alg {
			continue
		}
		usable = append(usable, k)
	}
	if h.Kid != "" {
		for _, k := range usable {
			if k.Kid == h.Kid {
				return k, nil
			}
		}
		return JWK{}, errUnknownKid
	}
	switch len(usable) {
	case 0:
		return JWK{}, errUnknownKid
	case 1:
		return usable[0], nil
	default:
		return JWK{}, errors.New("the token names no kid and the key set holds several " +
			"keys; a verifier that tried each in turn would accept one that was rotated out")
	}
}

// publicKey turns a JWK into a key crypto can use.
func (k JWK) publicKey() (crypto.PublicKey, error) {
	switch k.Kty {
	case "RSA":
		n, err := b64.DecodeString(k.N)
		if err != nil {
			return nil, fmt.Errorf("the modulus is not base64url: %w", err)
		}
		e, err := b64.DecodeString(k.E)
		if err != nil {
			return nil, fmt.Errorf("the exponent is not base64url: %w", err)
		}
		if len(n) == 0 || len(e) == 0 || len(e) > 8 {
			return nil, errors.New("the RSA key's modulus or exponent is not a usable size")
		}
		exponent := new(big.Int).SetBytes(e)
		if !exponent.IsInt64() || exponent.Int64() < 3 {
			return nil, errors.New("the RSA key's exponent is not a usable value")
		}
		return &rsa.PublicKey{
			N: new(big.Int).SetBytes(n),
			E: int(exponent.Int64()),
		}, nil
	case "EC":
		curve, size, err := curveOf(k.Crv)
		if err != nil {
			return nil, err
		}
		x, err := coordinate(k.X, size)
		if err != nil {
			return nil, fmt.Errorf("the x coordinate: %w", err)
		}
		y, err := coordinate(k.Y, size)
		if err != nil {
			return nil, fmt.Errorf("the y coordinate: %w", err)
		}
		// Not checked against the curve here, and that is not an omission:
		// ecdsa.Verify builds the point through crypto/internal/fips140 and refuses
		// one that is not on the curve, so an off-curve key fails verification
		// rather than verifying something. elliptic.Curve.IsOnCurve is deprecated
		// and calling it would be the less trustworthy of the two checks.
		return &ecdsa.PublicKey{Curve: curve, X: x, Y: y}, nil
	default:
		return nil, fmt.Errorf("key type %q is not one this add-on verifies; OpenID "+
			"Connect's asymmetric algorithms are RSA and EC", k.Kty)
	}
}

func curveOf(name string) (elliptic.Curve, int, error) {
	switch name {
	case "P-256":
		return elliptic.P256(), 32, nil
	case "P-384":
		return elliptic.P384(), 48, nil
	case "P-521":
		return elliptic.P521(), 66, nil
	default:
		return nil, 0, fmt.Errorf("curve %q is not one this add-on verifies", name)
	}
}

// coordinate reads one field element, insisting on the fixed width RFC 7518
// gives it. A short encoding is refused rather than left-padded, because a JWK
// whose coordinates are not the curve's width is not a JWK this add-on should be
// guessing about.
func coordinate(raw string, size int) (*big.Int, error) {
	b, err := b64.DecodeString(raw)
	if err != nil {
		return nil, fmt.Errorf("not base64url: %w", err)
	}
	if len(b) != size {
		return nil, fmt.Errorf("is %d bytes and this curve's is %d", len(b), size)
	}
	return new(big.Int).SetBytes(b), nil
}

// hashFor is the digest an alg names, and it is also the allowlist: an algorithm
// this function does not know is one no token gets verified under.
//
// `none` and the HMAC family are absent on purpose. `none` is the algorithm
// confusion attack itself. HS256 is legal in OpenID Connect — the client secret
// is the key — and it is refused here anyway, because a verifier that accepts
// both an asymmetric family and a symmetric one is a verifier where a token
// signed with the *public* key, as an HMAC key, can be made to verify. Refusing
// the whole family is the fix that does not depend on getting the branch right.
func hashFor(alg string) (crypto.Hash, hash.Hash, error) {
	switch alg {
	case "RS256", "PS256", "ES256":
		return crypto.SHA256, sha256.New(), nil
	case "RS384", "PS384", "ES384":
		return crypto.SHA384, sha512.New384(), nil
	case "RS512", "PS512", "ES512":
		return crypto.SHA512, sha512.New(), nil
	default:
		return 0, nil, fmt.Errorf("alg %q is not one this add-on verifies: the asymmetric "+
			"families RS, PS and ES, and deliberately not `none` and not the HMAC family",
			alg)
	}
}

// verify checks a signature against a key set and hands back the payload.
func (j *jws) verify(set JWKS) ([]byte, error) {
	hashID, digest, err := hashFor(j.header.Alg)
	if err != nil {
		return nil, err
	}
	key, err := set.find(j.header)
	if err != nil {
		return nil, err
	}
	pub, err := key.publicKey()
	if err != nil {
		return nil, err
	}
	digest.Write(j.signed)
	sum := digest.Sum(nil)

	switch {
	case strings.HasPrefix(j.header.Alg, "RS"):
		rsaKey, ok := pub.(*rsa.PublicKey)
		if !ok {
			return nil, fmt.Errorf("alg %q names an RSA signature and the key is %q",
				j.header.Alg, key.Kty)
		}
		if err := rsa.VerifyPKCS1v15(rsaKey, hashID, sum, j.signature); err != nil {
			return nil, fmt.Errorf("the signature does not verify: %w", err)
		}
	case strings.HasPrefix(j.header.Alg, "PS"):
		rsaKey, ok := pub.(*rsa.PublicKey)
		if !ok {
			return nil, fmt.Errorf("alg %q names an RSA signature and the key is %q",
				j.header.Alg, key.Kty)
		}
		opts := &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash, Hash: hashID}
		if err := rsa.VerifyPSS(rsaKey, hashID, sum, j.signature, opts); err != nil {
			return nil, fmt.Errorf("the signature does not verify: %w", err)
		}
	case strings.HasPrefix(j.header.Alg, "ES"):
		ecKey, ok := pub.(*ecdsa.PublicKey)
		if !ok {
			return nil, fmt.Errorf("alg %q names an ECDSA signature and the key is %q",
				j.header.Alg, key.Kty)
		}
		// JWS spells an ECDSA signature as r and s concatenated at the curve's fixed
		// width, not as the ASN.1 sequence ecdsa.VerifyASN1 reads. Splitting on the
		// declared width rather than on half the length is what makes a truncated
		// signature a refusal instead of a different pair of numbers.
		_, size, err := curveOf(ecKey.Curve.Params().Name)
		if err != nil {
			return nil, err
		}
		if len(j.signature) != 2*size {
			return nil, fmt.Errorf("an ECDSA signature on this curve is %d bytes and this "+
				"is %d", 2*size, len(j.signature))
		}
		r := new(big.Int).SetBytes(j.signature[:size])
		s := new(big.Int).SetBytes(j.signature[size:])
		if !ecdsa.Verify(ecKey, sum, r, s) {
			return nil, errors.New("the signature does not verify")
		}
	default:
		// Unreachable while hashFor is the allowlist, and here so that adding a
		// family to that function without adding it here fails loudly.
		return nil, fmt.Errorf("alg %q has no verifier", j.header.Alg)
	}
	return j.payload, nil
}
