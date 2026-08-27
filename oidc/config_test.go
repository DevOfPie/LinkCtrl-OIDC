package oidc

import (
	"errors"
	"testing"

	"github.com/DevOfPie/LinkCtrl/sdk"
)

func TestLoadConfigNamesEverythingMissing(t *testing.T) {
	h := newFakeHost(t)
	h.settings[SettingIssuer] = "https://idp.example.com"

	_, err := LoadConfig(h)
	var unconfigured *ErrUnconfigured
	if !errors.As(err, &unconfigured) {
		t.Fatalf("error is %v, want an *ErrUnconfigured", err)
	}
	// All three at once rather than the first: an operator filling a form in
	// should not have to submit it four times to find out what else it wants.
	want := []string{SettingClientID, SettingClientSecret, SettingRedirectURI}
	if len(unconfigured.Missing) != len(want) {
		t.Fatalf("missing is %v, want %v", unconfigured.Missing, want)
	}
	for i, name := range want {
		if unconfigured.Missing[i] != name {
			t.Errorf("missing[%d] is %q, want %q", i, unconfigured.Missing[i], name)
		}
	}
}

func TestARefusedConfigGrantIsNotADefault(t *testing.T) {
	// ErrDenied means this add-on did not declare config.read, or declared a key
	// the manifest does not carry. Reading it as "no value" would run the add-on
	// on defaults nobody chose.
	h := newFakeHost(t)
	h.noConfigGrant = true
	_, err := LoadConfig(h)
	mustErrorIs(t, err, sdk.ErrDenied)
}

func TestASettingWithNoValueIsNotAnError(t *testing.T) {
	h := newFakeHost(t)
	h.settings[SettingIssuer] = "https://idp.example.com"
	h.settings[SettingClientID] = "c"
	h.settings[SettingClientSecret] = "s"
	h.settings[SettingRedirectURI] = "https://links.example.com/addons/oidc/callback"

	cfg, err := LoadConfig(h)
	if err != nil {
		t.Fatal(err)
	}
	// The optional ones fall back rather than refusing: ErrNotFound is the
	// ordinary state of a declared setting with no value and no default.
	if cfg.Scopes != "openid profile email" {
		t.Errorf("scopes are %q", cfg.Scopes)
	}
	if cfg.AfterSignIn != "/dashboard" || cfg.AfterLink != "/dashboard" {
		t.Errorf("landings are %q and %q", cfg.AfterSignIn, cfg.AfterLink)
	}
	if cfg.ClockSkew != 60 || cfg.DiscoveryTTL != 900 {
		t.Errorf("skew %d ttl %d", cfg.ClockSkew, cfg.DiscoveryTTL)
	}
}

func TestCleartextIsRefusedBeforeAnythingIsSent(t *testing.T) {
	// The host refuses a cleartext *fetch* itself. The redirect_uri is never
	// fetched — it is handed to the provider and typed into a Location — so this
	// check is the only thing between an operator's typo and an authorization code
	// delivered over http.
	for _, tc := range []struct{ name, key, value string }{
		{"issuer", SettingIssuer, "http://idp.example.com"},
		{"redirect_uri", SettingRedirectURI, "http://links.example.com/addons/oidc/callback"},
		{"a redirect_uri that is only a path", SettingRedirectURI, "/addons/oidc/callback"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := newFakeHost(t)
			h.settings[SettingIssuer] = "https://idp.example.com"
			h.settings[SettingClientID] = "c"
			h.settings[SettingClientSecret] = "s"
			h.settings[SettingRedirectURI] = "https://links.example.com/addons/oidc/callback"
			h.settings[tc.key] = tc.value

			if _, err := LoadConfig(h); err == nil {
				t.Fatalf("accepted %s = %q", tc.key, tc.value)
			} else {
				mustContain(t, err.Error(), "absolute https URL")
			}
		})
	}
}

func TestTheIssuerIsNormalizedOnce(t *testing.T) {
	h := newFakeHost(t)
	h.settings[SettingIssuer] = "https://idp.example.com/"
	h.settings[SettingClientID] = "c"
	h.settings[SettingClientSecret] = "s"
	h.settings[SettingRedirectURI] = "https://links.example.com/addons/oidc/callback"

	cfg, err := LoadConfig(h)
	if err != nil {
		t.Fatal(err)
	}
	// The issuer is compared byte for byte against `iss` and joined onto a
	// well-known path. A trailing slash makes one of those two wrong.
	if cfg.Issuer != "https://idp.example.com" {
		t.Fatalf("issuer is %q", cfg.Issuer)
	}
	if cfg.Issuer+DiscoveryPath != "https://idp.example.com/.well-known/openid-configuration" {
		t.Fatalf("discovery URL is %q", cfg.Issuer+DiscoveryPath)
	}
}

func TestScopesAlwaysCarryOpenid(t *testing.T) {
	for _, tc := range []struct{ in, want string }{
		{"", "openid profile email"},
		{"profile email", "openid profile email"},
		{"openid groups", "openid groups"},
		{"  email   openid  ", "email openid"},
	} {
		if got := normalizeScopes(tc.in); got != tc.want {
			t.Errorf("normalizeScopes(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestALandingIsAPathOnThisInstance(t *testing.T) {
	// The host lets an add-on's Location be an absolute http(s) URL, because an
	// authentication add-on has to send somebody to a provider. That makes the
	// return leg the place an open redirect would live.
	for _, tc := range []struct{ in, want string }{
		{"", "/dashboard"},
		{"/links", "/links"},
		{"https://evil.test/", "/dashboard"},
		{"//evil.test/", "/dashboard"},
		{"/ok\r\nSet-Cookie: x=1", "/dashboard"},
		{"javascript:alert(1)", "/dashboard"},
	} {
		if got := safePath(tc.in, "/dashboard"); got != tc.want {
			t.Errorf("safePath(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestATypedNumberOutsideItsBoundsFallsBack(t *testing.T) {
	for _, tc := range []struct {
		in   string
		want int
	}{
		{"", 60}, {"nope", 60}, {"-1", 60}, {"601", 60}, {"0", 0}, {"120", 120},
	} {
		if got := boundedInt(tc.in, 60, 0, 600); got != tc.want {
			t.Errorf("boundedInt(%q) = %d, want %d", tc.in, got, tc.want)
		}
	}
}
