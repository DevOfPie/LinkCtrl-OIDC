package oidc

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/json"
	"math/big"
	"net/url"
	"strings"
	"time"
)

// This file is an identity provider, as a test double.
//
// It signs real ID tokens with real keys and answers a real discovery document,
// because the thing under test is a verifier: a fake that handed back a claim
// set would be testing the parts of this add-on that do not decide anything. The
// authorization endpoint is not served — a visitor's browser goes there, not the
// host — so a test drives that leg itself, with [fakeIDP.authorize].

// The keys, generated once per test binary. 2048 bits because a shorter RSA key
// is not what a provider uses and this add-on's verifier should be exercised at
// the size it will meet.
var (
	testRSAKey = mustRSA()
	testECKey  = mustEC()
)

func mustRSA() *rsa.PrivateKey {
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(err)
	}
	return k
}

func mustEC() *ecdsa.PrivateKey {
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		panic(err)
	}
	return k
}

type issuedCode struct {
	challenge   string
	nonce       string
	redirectURI string
}

type fakeIDP struct {
	issuer       string
	clientID     string
	clientSecret string
	now          func() time.Time

	// Where the three documents live. Separate fields because a provider that
	// spreads them across hostnames is the case the operator has to name three
	// origins for, and this add-on's advice about that is worth testing.
	tokenEndpoint string
	jwksURI       string
	authEndpoint  string

	// What the discovery document claims to be, when a test wants it to disagree
	// with the configured issuer.
	discoveryIssuer  string
	responseModes    []string
	challengeMethods []string

	// The signing key, and the key set. Two fields, so a rotation is expressible:
	// sign with one and publish another.
	signAlg    string
	signKID    string
	publishKID string
	publishEC  bool

	codes map[string]issuedCode

	// Knobs for the failure cases.
	tokenStatus      int
	tokenError       string
	tokenErrorDesc   string
	omitIDToken      bool
	claimOverride    map[string]any
	dropClaims       []string
	discoveryStatus  int
	jwksStatus       int
	emptyJWKS        bool
	discoveryBody    string
	jwksFetches      int
	discoveryFetches int
	tokenPosts       int
	lastTokenForm    url.Values
}

func newFakeIDP() *fakeIDP {
	return &fakeIDP{
		issuer:        "https://idp.example.com",
		clientID:      "linkctrl",
		clientSecret:  "s3cret",
		tokenEndpoint: "https://idp.example.com/oauth2/token",
		jwksURI:       "https://idp.example.com/oauth2/keys",
		authEndpoint:  "https://idp.example.com/oauth2/authorize",
		signAlg:       "RS256",
		signKID:       "key-1",
		publishKID:    "key-1",
		codes:         map[string]issuedCode{},
		now:           func() time.Time { return time.Date(2026, 8, 27, 12, 0, 0, 0, time.UTC) },
	}
}

func (p *fakeIDP) origin() string { return originOf(p.issuer) }

// authorize is the leg a browser walks. It takes what this add-on put in the
// authorization URL and hands back a code, the way a provider would after
// somebody signed in there.
func (p *fakeIDP) authorize(q url.Values) string {
	code := "code-" + q.Get("state")[:8]
	p.codes[code] = issuedCode{
		challenge:   q.Get("code_challenge"),
		nonce:       q.Get("nonce"),
		redirectURI: q.Get("redirect_uri"),
	}
	return code
}

func (p *fakeIDP) discovery() map[string]any {
	issuer := p.discoveryIssuer
	if issuer == "" {
		issuer = p.issuer
	}
	d := map[string]any{
		"issuer":                 issuer,
		"authorization_endpoint": p.authEndpoint,
		"token_endpoint":         p.tokenEndpoint,
		"jwks_uri":               p.jwksURI,
	}
	if p.challengeMethods != nil {
		d["code_challenge_methods_supported"] = p.challengeMethods
	}
	if p.responseModes != nil {
		d["response_modes_supported"] = p.responseModes
	}
	return d
}

func (p *fakeIDP) jwks() JWKS {
	if p.publishEC {
		return JWKS{Keys: []JWK{ecJWK(testECKey, p.publishKID)}}
	}
	return JWKS{Keys: []JWK{rsaJWK(testRSAKey, p.publishKID)}}
}

// serve answers one fetch the host made.
func (p *fakeIDP) serve(req FetchRequest) (int, string, string) {
	switch {
	case strings.HasSuffix(req.URL, DiscoveryPath):
		p.discoveryFetches++
		if p.discoveryStatus != 0 {
			return p.discoveryStatus, "application/json", `{"error":"nope"}`
		}
		if p.discoveryBody != "" {
			return 200, "application/json", p.discoveryBody
		}
		return 200, "application/json", toJSON(p.discovery())

	case req.URL == p.jwksURI:
		p.jwksFetches++
		if p.jwksStatus != 0 {
			return p.jwksStatus, "application/json", `{"error":"nope"}`
		}
		if p.emptyJWKS {
			return 200, "application/json", `{"keys":[]}`
		}
		return 200, "application/json", toJSON(p.jwks())

	case req.URL == p.tokenEndpoint:
		return p.token(req)
	}
	return 404, "text/plain", "no such endpoint"
}

// token is the exchange, and it checks what a real token endpoint checks: the
// client credentials in the body (because this ABI has no way to send an
// Authorization header), and the PKCE verifier against the challenge.
func (p *fakeIDP) token(req FetchRequest) (int, string, string) {
	p.tokenPosts++
	if req.Method != "POST" {
		return 405, "application/json", `{"error":"invalid_request"}`
	}
	form, err := url.ParseQuery(req.Body)
	if err != nil {
		return 400, "application/json", `{"error":"invalid_request"}`
	}
	p.lastTokenForm = form
	if p.tokenError != "" {
		status := p.tokenStatus
		if status == 0 {
			status = 400
		}
		return status, "application/json", toJSON(map[string]any{
			"error": p.tokenError, "error_description": p.tokenErrorDesc,
		})
	}
	if form.Get("client_id") != p.clientID || form.Get("client_secret") != p.clientSecret {
		return 401, "application/json", `{"error":"invalid_client"}`
	}
	issued, ok := p.codes[form.Get("code")]
	if !ok {
		return 400, "application/json", `{"error":"invalid_grant"}`
	}
	// Single use, which is what an authorization code is. This is the layer that
	// catches a replayed code even where the add-on's own single-use record did
	// not, and a test asserts both.
	delete(p.codes, form.Get("code"))
	if issued.redirectURI != form.Get("redirect_uri") {
		return 400, "application/json", `{"error":"invalid_grant","error_description":"redirect_uri does not match"}`
	}
	if challenge(form.Get("code_verifier")) != issued.challenge {
		return 400, "application/json", `{"error":"invalid_grant","error_description":"PKCE verification failed"}`
	}
	if p.omitIDToken {
		return 200, "application/json", `{"token_type":"Bearer","access_token":"a"}`
	}
	return 200, "application/json", toJSON(map[string]any{
		"token_type": "Bearer",
		"id_token":   p.idToken(issued.nonce),
	})
}

// idToken builds and signs one, with the overrides a test asked for applied last
// so that any claim can be made wrong.
func (p *fakeIDP) idToken(nonce string) string {
	now := p.now()
	claims := map[string]any{
		"iss":            p.issuer,
		"sub":            "provider-subject-1",
		"aud":            p.clientID,
		"exp":            now.Add(5 * time.Minute).Unix(),
		"iat":            now.Unix(),
		"nonce":          nonce,
		"email":          "person@example.com",
		"email_verified": true,
		"name":           "A Person",
		"groups":         []string{"engineering"},
	}
	for k, v := range p.claimOverride {
		claims[k] = v
	}
	for _, k := range p.dropClaims {
		delete(claims, k)
	}
	if p.publishEC || strings.HasPrefix(p.signAlg, "ES") {
		return signJWT(p.signAlg, testECKey, p.signKID, claims)
	}
	return signJWT(p.signAlg, testRSAKey, p.signKID, claims)
}

// --- signing, which the tests also use directly ------------------------------

func rsaJWK(k *rsa.PrivateKey, kid string) JWK {
	e := big.NewInt(int64(k.PublicKey.E)).Bytes()
	return JWK{
		Kty: "RSA", Kid: kid, Use: "sig",
		N: b64.EncodeToString(k.PublicKey.N.Bytes()),
		E: b64.EncodeToString(e),
	}
}

func ecJWK(k *ecdsa.PrivateKey, kid string) JWK {
	size := (k.Curve.Params().BitSize + 7) / 8
	return JWK{
		Kty: "EC", Kid: kid, Use: "sig", Crv: k.Curve.Params().Name,
		X: b64.EncodeToString(pad(k.X.Bytes(), size)),
		Y: b64.EncodeToString(pad(k.Y.Bytes(), size)),
	}
}

func pad(b []byte, size int) []byte {
	if len(b) >= size {
		return b
	}
	out := make([]byte, size)
	copy(out[size-len(b):], b)
	return out
}

// signJWT produces a compact JWS. It is written here rather than reached for,
// for the reason the verifier is: this repository depends on the standard
// library and the LinkCtrl SDK, in its tests as well as in its module.
func signJWT(alg string, key crypto.Signer, kid string, claims map[string]any) string {
	header := map[string]any{"alg": alg, "typ": "JWT"}
	if kid != "" {
		header["kid"] = kid
	}
	signing := b64.EncodeToString([]byte(toJSON(header))) + "." +
		b64.EncodeToString([]byte(toJSON(claims)))

	var sum []byte
	var hashID crypto.Hash
	switch {
	case strings.HasSuffix(alg, "256"):
		h := sha256.Sum256([]byte(signing))
		sum, hashID = h[:], crypto.SHA256
	case strings.HasSuffix(alg, "384"):
		h := sha512.Sum384([]byte(signing))
		sum, hashID = h[:], crypto.SHA384
	default:
		h := sha512.Sum512([]byte(signing))
		sum, hashID = h[:], crypto.SHA512
	}

	var sig []byte
	switch {
	case alg == "none":
		return signing + "."
	case strings.HasPrefix(alg, "RS"):
		s, err := rsa.SignPKCS1v15(rand.Reader, key.(*rsa.PrivateKey), hashID, sum)
		if err != nil {
			panic(err)
		}
		sig = s
	case strings.HasPrefix(alg, "PS"):
		s, err := rsa.SignPSS(rand.Reader, key.(*rsa.PrivateKey), hashID, sum,
			&rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash, Hash: hashID})
		if err != nil {
			panic(err)
		}
		sig = s
	case strings.HasPrefix(alg, "ES"):
		ec := key.(*ecdsa.PrivateKey)
		r, s, err := ecdsa.Sign(rand.Reader, ec, sum)
		if err != nil {
			panic(err)
		}
		size := (ec.Curve.Params().BitSize + 7) / 8
		sig = append(pad(r.Bytes(), size), pad(s.Bytes(), size)...)
	default:
		panic("no signer for " + alg)
	}
	return signing + "." + b64.EncodeToString(sig)
}

func toJSON(v any) string {
	raw, err := json.Marshal(v)
	if err != nil {
		panic(err)
	}
	return string(raw)
}
