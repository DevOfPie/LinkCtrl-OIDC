package oidc

import (
	"testing"
)

func newProviderSuite(t *testing.T) (*fakeHost, *Provider) {
	t.Helper()
	h := newFakeHost(t)
	h.idp = newFakeIDP()
	h.configured()
	cfg, err := LoadConfig(h)
	if err != nil {
		t.Fatal(err)
	}
	return h, NewProvider(h, NewStore(h), cfg)
}

func TestDiscoveryIsReadOnceAndThenFromTheSchema(t *testing.T) {
	h, p := newProviderSuite(t)
	for i := range 3 {
		if _, err := p.Discovery(); err != nil {
			t.Fatalf("read %d: %v", i, err)
		}
	}
	if h.idp.discoveryFetches != 1 {
		t.Fatalf("the discovery document was fetched %d times", h.idp.discoveryFetches)
	}
}

func TestACachedDocumentExpires(t *testing.T) {
	h, p := newProviderSuite(t)
	if _, err := p.Discovery(); err != nil {
		t.Fatal(err)
	}
	h.now = h.now.Add(901 * 1e9) // one second past the default TTL
	if _, err := p.Discovery(); err != nil {
		t.Fatal(err)
	}
	if h.idp.discoveryFetches != 2 {
		t.Fatalf("a stale document was served: %d fetches", h.idp.discoveryFetches)
	}
}

func TestDiscoveryMustDescribeTheConfiguredIssuer(t *testing.T) {
	// OpenID Connect Discovery's own requirement, and the check that makes the
	// rest of the document trustworthy: every endpoint below is read out of this
	// file, so a document belonging to somebody else is a token endpoint
	// belonging to somebody else.
	h, p := newProviderSuite(t)
	h.idp.discoveryIssuer = "https://someone-else.example.com"

	if _, err := p.Discovery(); err == nil {
		t.Fatal("a discovery document naming another issuer was accepted")
	} else {
		mustContain(t, err.Error(), "names issuer")
	}
}

func TestADiscoveryDocumentIsRefusedForWhatItLacks(t *testing.T) {
	for _, tc := range []struct{ name, body, want string }{
		{"no token endpoint",
			`{"issuer":"https://idp.example.com","authorization_endpoint":"https://idp.example.com/a","jwks_uri":"https://idp.example.com/k"}`,
			"no token_endpoint"},
		{"a cleartext endpoint",
			`{"issuer":"https://idp.example.com","authorization_endpoint":"http://idp.example.com/a","token_endpoint":"https://idp.example.com/t","jwks_uri":"https://idp.example.com/k"}`,
			"not an absolute https URL"},
		{"no S256",
			`{"issuer":"https://idp.example.com","authorization_endpoint":"https://idp.example.com/a","token_endpoint":"https://idp.example.com/t","jwks_uri":"https://idp.example.com/k","code_challenge_methods_supported":["plain"]}`,
			"does not fall back"},
		{"not JSON at all", `<html>a login page</html>`, "not a discovery document"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h, p := newProviderSuite(t)
			h.idp.discoveryBody = tc.body
			if _, err := p.Discovery(); err == nil {
				t.Fatal("accepted it")
			} else {
				mustContain(t, err.Error(), tc.want)
			}
		})
	}
}

func TestACachedDocumentThatNoLongerAgreesIsDropped(t *testing.T) {
	// An operator re-pointing `issuer` is not an error; it is a stale cache.
	h, p := newProviderSuite(t)
	if _, err := p.Discovery(); err != nil {
		t.Fatal(err)
	}
	h.idp.issuer = "https://idp2.example.com"
	h.idp.tokenEndpoint = "https://idp2.example.com/t"
	h.idp.jwksURI = "https://idp2.example.com/k"
	h.idp.authEndpoint = "https://idp2.example.com/a"
	h.configured()
	cfg, err := LoadConfig(h)
	if err != nil {
		t.Fatal(err)
	}
	p2 := NewProvider(h, NewStore(h), cfg)
	d, err := p2.Discovery()
	if err != nil {
		t.Fatal(err)
	}
	if d.TokenEndpoint != "https://idp2.example.com/t" {
		t.Fatalf("token endpoint is %q", d.TokenEndpoint)
	}
}

func TestAProviderThatOnlyDoesFormPostIsRefusedByName(t *testing.T) {
	// LinkCtrl's application tree answers 403 to every cross-site request that
	// uses an unsafe method, before an add-on is entered, so a form_post callback
	// never arrives. It is a limitation to plan around and not a bug to report,
	// which is why it is named rather than discovered.
	h, p := newProviderSuite(t)
	h.idp.responseModes = []string{"form_post", "fragment"}
	d, err := p.Discovery()
	if err != nil {
		t.Fatal(err)
	}
	if err := d.CheckResponseMode(); err == nil {
		t.Fatal("a form_post-only provider was accepted")
	} else {
		mustContain(t, err.Error(), "form_post")
	}

	// A provider that advertises `query`, and one that advertises nothing, are
	// both fine: the field is optional and `query` is the flow's own default.
	h.idp.responseModes = []string{"query", "form_post"}
	if err := (Discovery{ResponseModes: h.idp.responseModes}).CheckResponseMode(); err != nil {
		t.Errorf("a provider advertising query was refused: %v", err)
	}
	if err := (Discovery{}).CheckResponseMode(); err != nil {
		t.Errorf("a provider advertising nothing was refused: %v", err)
	}
}

func TestAnEmptyKeySetIsRefused(t *testing.T) {
	h, p := newProviderSuite(t)
	d, err := p.Discovery()
	if err != nil {
		t.Fatal(err)
	}
	h.idp.emptyJWKS = true
	if _, err := p.Keys(d, true); err == nil {
		t.Fatal("an empty key set was accepted")
	} else {
		mustContain(t, err.Error(), "no keys in it")
	}
}

func TestAnHTTPErrorFromTheProviderIsAnOutcomeWithAStatus(t *testing.T) {
	h, p := newProviderSuite(t)
	h.idp.discoveryStatus = 500
	_, err := p.Discovery()
	if err == nil {
		t.Fatal("a 500 was accepted")
	}
	// The host reached who it was told to, so the outcome is `ok` and the status
	// is the origin's own. Reporting it as a fetch failure would blame the wrong
	// party.
	mustContain(t, err.Error(), "answered 500")
}

func TestTheCacheIsSkippedWhenTheOperatorTurnsItOff(t *testing.T) {
	h, _ := newProviderSuite(t)
	h.settings[SettingDiscoveryTTLSeconds] = "0"
	cfg, err := LoadConfig(h)
	if err != nil {
		t.Fatal(err)
	}
	p := NewProvider(h, NewStore(h), cfg)
	for range 3 {
		if _, err := p.Discovery(); err != nil {
			t.Fatal(err)
		}
	}
	if h.idp.discoveryFetches != 3 {
		t.Fatalf("with the TTL at zero the document was fetched %d times",
			h.idp.discoveryFetches)
	}
	if h.storage.counted("INSERT INTO documents") != 0 {
		t.Error("a document was cached with caching turned off")
	}
}
