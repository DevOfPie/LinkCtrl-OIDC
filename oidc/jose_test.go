package oidc

import (
	"crypto/hmac"
	"crypto/sha256"
	"errors"
	"strings"
	"testing"
)

// keySet is the set a test verifies against, published for whichever key the
// token was signed with.
func keySet(kid string, ec bool) JWKS {
	if ec {
		return JWKS{Keys: []JWK{ecJWK(testECKey, kid)}}
	}
	return JWKS{Keys: []JWK{rsaJWK(testRSAKey, kid)}}
}

func verifyPayload(t *testing.T, token string, set JWKS) []byte {
	t.Helper()
	j, err := parseJWS(token)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	payload, err := j.verify(set)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	return payload
}

func TestEveryAsymmetricFamilyVerifies(t *testing.T) {
	for _, tc := range []struct {
		alg string
		ec  bool
	}{
		{"RS256", false}, {"RS384", false}, {"RS512", false},
		{"PS256", false}, {"PS384", false}, {"PS512", false},
		{"ES256", true},
	} {
		t.Run(tc.alg, func(t *testing.T) {
			claims := map[string]any{"sub": "s"}
			var token string
			if tc.ec {
				token = signJWT(tc.alg, testECKey, "k", claims)
			} else {
				token = signJWT(tc.alg, testRSAKey, "k", claims)
			}
			got := verifyPayload(t, token, keySet("k", tc.ec))
			mustContain(t, string(got), `"sub":"s"`)
		})
	}
}

func TestTheAlgorithmVocabularyIsAnAllowlist(t *testing.T) {
	// `none` is the algorithm-confusion attack itself, and the HMAC family is
	// refused as a family: a verifier that accepts both an asymmetric algorithm
	// and a symmetric one is a verifier where a token signed with the public key,
	// used as an HMAC key, can be made to verify.
	header := b64.EncodeToString([]byte(`{"alg":"none","typ":"JWT"}`))
	payload := b64.EncodeToString([]byte(`{"sub":"anybody"}`))

	for _, tc := range []struct{ name, token string }{
		{"none", header + "." + payload + "."},
		{"HS256", hmacToken(t)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			j, err := parseJWS(tc.token)
			if err != nil {
				t.Fatalf("parse: %v", err)
			}
			if _, err := j.verify(keySet("k", false)); err == nil {
				t.Fatal("verified a token this add-on must never verify")
			} else {
				mustContain(t, err.Error(), "not one this add-on verifies")
			}
		})
	}
}

// hmacToken signs with the RSA public modulus as an HMAC key, which is the shape
// of the confusion attack: the "secret" is a value the attacker has, because it
// is published in the key set.
func hmacToken(t *testing.T) string {
	t.Helper()
	signing := b64.EncodeToString([]byte(`{"alg":"HS256","typ":"JWT","kid":"k"}`)) + "." +
		b64.EncodeToString([]byte(`{"sub":"anybody"}`))
	mac := hmac.New(sha256.New, testRSAKey.PublicKey.N.Bytes())
	mac.Write([]byte(signing))
	return signing + "." + b64.EncodeToString(mac.Sum(nil))
}

func TestATamperedTokenDoesNotVerify(t *testing.T) {
	good := signJWT("RS256", testRSAKey, "k", map[string]any{"sub": "person"})
	parts := strings.Split(good, ".")

	for _, tc := range []struct {
		name  string
		token string
	}{
		{"payload rewritten", parts[0] + "." +
			b64.EncodeToString([]byte(`{"sub":"somebody-else"}`)) + "." + parts[2]},
		{"signature truncated", parts[0] + "." + parts[1] + "." + parts[2][:len(parts[2])-4]},
		{"signature from another token", parts[0] + "." + parts[1] + "." +
			strings.Split(signJWT("RS256", testRSAKey, "k",
				map[string]any{"sub": "other"}), ".")[2]},
	} {
		t.Run(tc.name, func(t *testing.T) {
			j, err := parseJWS(tc.token)
			if err != nil {
				return // refused at the parse, which is also a refusal
			}
			if _, err := j.verify(keySet("k", false)); err == nil {
				t.Fatal("a tampered token verified")
			}
		})
	}
}

func TestAKeyOfTheWrongTypeForTheAlgIsRefused(t *testing.T) {
	// An RS256 header over a set that publishes an EC key. The header names the
	// verification this add-on will do and the key set names what it has; a
	// verifier that reconciled them by trying something else is one that can be
	// steered.
	token := signJWT("RS256", testRSAKey, "k", map[string]any{"sub": "s"})
	j, err := parseJWS(token)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := j.verify(keySet("k", true)); err == nil {
		t.Fatal("an RSA signature verified against an EC key set")
	} else {
		mustContain(t, err.Error(), "RSA signature")
	}
}

func TestAnUnknownKidIsItsOwnAnswer(t *testing.T) {
	// The one failure the caller can fix by fetching again, so it is the one that
	// has to be distinguishable from every other.
	token := signJWT("RS256", testRSAKey, "rotated-in", map[string]any{"sub": "s"})
	j, err := parseJWS(token)
	if err != nil {
		t.Fatal(err)
	}
	_, err = j.verify(keySet("rotated-out", false))
	if !errors.Is(err, errUnknownKid) {
		t.Fatalf("error is %v, want errUnknownKid", err)
	}
}

func TestATokenWithNoKidNeedsAnUnambiguousKeySet(t *testing.T) {
	token := signJWT("RS256", testRSAKey, "", map[string]any{"sub": "s"})

	t.Run("one key", func(t *testing.T) {
		set := JWKS{Keys: []JWK{rsaJWK(testRSAKey, "")}}
		verifyPayload(t, token, set)
	})
	t.Run("several keys", func(t *testing.T) {
		set := JWKS{Keys: []JWK{rsaJWK(testRSAKey, "a"), rsaJWK(testRSAKey, "b")}}
		j, err := parseJWS(token)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := j.verify(set); err == nil {
			t.Fatal("a token naming no kid was verified against an ambiguous key set")
		} else {
			mustContain(t, err.Error(), "rotated out")
		}
	})
}

func TestKeysNotForSigningAreSkipped(t *testing.T) {
	// An encryption key with the kid the token names is not a signing key, and
	// picking it would fail verification for the wrong reason.
	enc := rsaJWK(testRSAKey, "k")
	enc.Use = "enc"
	sig := rsaJWK(testRSAKey, "k")
	set := JWKS{Keys: []JWK{enc, sig}}
	verifyPayload(t, signJWT("RS256", testRSAKey, "k", map[string]any{"sub": "s"}), set)
}

func TestAMalformedKeyIsRefusedRatherThanGuessedAt(t *testing.T) {
	token := signJWT("ES256", testECKey, "k", map[string]any{"sub": "s"})
	good := ecJWK(testECKey, "k")

	for _, tc := range []struct {
		name string
		key  JWK
		want string
	}{
		{"short coordinate", JWK{Kty: "EC", Kid: "k", Crv: "P-256",
			X: b64.EncodeToString([]byte("short")), Y: good.Y}, "curve's is 32"},
		{"unknown curve", JWK{Kty: "EC", Kid: "k", Crv: "P-192", X: good.X, Y: good.Y},
			"not one this add-on verifies"},
		{"unknown key type", JWK{Kty: "OKP", Kid: "k"}, "not one this add-on verifies"},
		{"exponent 1", JWK{Kty: "RSA", Kid: "k",
			N: b64.EncodeToString(testRSAKey.PublicKey.N.Bytes()),
			E: b64.EncodeToString([]byte{1})}, "not a usable value"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			j, err := parseJWS(token)
			if err != nil {
				t.Fatal(err)
			}
			_, err = j.verify(JWKS{Keys: []JWK{tc.key}})
			if err == nil {
				t.Fatal("a malformed key verified something")
			}
			mustContain(t, err.Error(), tc.want)
		})
	}
}

func TestAnECDSASignatureIsReadAtTheCurvesWidth(t *testing.T) {
	// JWS spells it as r and s concatenated at a fixed width, not as the ASN.1
	// sequence ecdsa.VerifyASN1 reads. A signature of the wrong length is refused
	// rather than split down the middle into a different pair of numbers.
	token := signJWT("ES256", testECKey, "k", map[string]any{"sub": "s"})
	parts := strings.Split(token, ".")
	sig, err := b64.DecodeString(parts[2])
	if err != nil {
		t.Fatal(err)
	}
	short := parts[0] + "." + parts[1] + "." + b64.EncodeToString(sig[:len(sig)-2])

	j, err := parseJWS(short)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := j.verify(keySet("k", true)); err == nil {
		t.Fatal("a short ECDSA signature verified")
	} else {
		mustContain(t, err.Error(), "64 bytes and this is 62")
	}
}

func TestParseRefusesWhatIsNotACompactJWS(t *testing.T) {
	for _, tc := range []struct{ name, token, want string }{
		{"two parts", "a.b", "three parts"},
		{"header not base64", "!!!.e30.sig", "not base64url"},
		{"header not JSON", b64.EncodeToString([]byte("nope")) + ".e30.c2ln", "not JSON"},
		{"payload not base64", b64.EncodeToString([]byte(`{"alg":"RS256"}`)) + ".!!!.c2ln",
			"payload is not base64url"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := parseJWS(tc.token); err == nil {
				t.Fatal("parsed something that is not a compact JWS")
			} else {
				mustContain(t, err.Error(), tc.want)
			}
		})
	}
}
