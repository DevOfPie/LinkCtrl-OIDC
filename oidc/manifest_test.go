package oidc

import (
	"encoding/json"
	"os"
	"regexp"
	"strings"
	"testing"

	"github.com/DevOfPie/LinkCtrl/sdk"
)

// The manifest is the one file in this repository the host reads before it reads
// a byte of wasm, and it is the one place where a mistake is a refusal at load
// rather than a failing request. So it is asserted against the code rather than
// reviewed: every rule below is one docs/addon-abi.md or the host's manifest
// validation states, and every cross-check is a fact that lives in two files.

type manifestSetting struct {
	Name    string   `json:"name"`
	Type    string   `json:"type"`
	Options []string `json:"options,omitempty"`
	Default string   `json:"default,omitempty"`
	Origin  bool     `json:"origin,omitempty"`
}

type manifest struct {
	SchemaVersion  int               `json:"schema_version"`
	Name           string            `json:"name"`
	Version        string            `json:"version"`
	ABIVersion     int               `json:"abi_version"`
	Module         string            `json:"module"`
	SHA256         string            `json:"sha256"`
	FailureClass   string            `json:"failure_class"`
	Permissions    []string          `json:"permissions"`
	CookiePrefixes []string          `json:"cookie_prefixes"`
	Settings       []manifestSetting `json:"settings"`
	Migrations     []any             `json:"migrations"`
}

func readManifest(t *testing.T) (manifest, string) {
	t.Helper()
	raw, err := os.ReadFile("../addon.json.in")
	if err != nil {
		t.Fatal(err)
	}
	var m manifest
	dec := json.NewDecoder(strings.NewReader(string(raw)))
	// The host refuses an unknown manifest field, so a template carrying one would
	// be refused at load. Read the same way here.
	dec.DisallowUnknownFields()
	if err := dec.Decode(&m); err != nil {
		t.Fatalf("addon.json.in: %v", err)
	}
	return m, string(raw)
}

func TestTheManifestAndTheCodeAgree(t *testing.T) {
	m, raw := readManifest(t)

	if m.SchemaVersion != 1 {
		t.Errorf("schema_version is %d; the host checks it for equality", m.SchemaVersion)
	}
	if m.Name != Name {
		t.Errorf("the manifest is named %q and the code is %q; the name is the schema, "+
			"the route prefix and the cookie namespace all at once", m.Name, Name)
	}
	if m.Version != Version {
		t.Errorf("the manifest says %q and the code says %q", m.Version, Version)
	}
	if m.ABIVersion != sdk.ABIGeneration {
		t.Errorf("abi_version is %d and this SDK's generation is %d; the host checks "+
			"the generation before it reads a byte of wasm", m.ABIVersion, sdk.ABIGeneration)
	}
	if m.Module != Name+".wasm" {
		t.Errorf("module is %q", m.Module)
	}
	if !strings.Contains(raw, "@SHA256@") {
		t.Error("the template carries no @SHA256@ placeholder, so `make build` has " +
			"nothing to substitute and the digest would be a stale literal")
	}
	// Declared honestly even though the host overrides it: an add-on holding
	// session.mint is required-class whatever the manifest says, because an
	// instance that booted without it is one whose external sign-in silently does
	// not exist.
	if m.FailureClass != "required" {
		t.Errorf("failure_class is %q; this add-on is on the authentication path",
			m.FailureClass)
	}
	if len(m.Migrations) != 0 {
		t.Error("this add-on ships migrations, which makes it uninstallable through " +
			"the manager and the API: an install bundle is exactly two files")
	}
}

// abiPermissions is the closed vocabulary, from docs/addon-abi.md. The host
// refuses a token outside it at load, so a typo here is not a failing call — it
// is an add-on that does not start.
var abiPermissions = map[string]bool{
	"config.read":            true,
	"storage.own_schema":     true,
	"routes.own_prefix":      true,
	"session.context":        true,
	"session.mint":           true,
	"redirect.observe":       true,
	"redirect.inline":        true,
	"redirect.rewrite_query": true,
	"network.fetch":          true,
}

func TestEveryPermissionIsOneTheAddonUsesAndNoneIsMissing(t *testing.T) {
	m, _ := readManifest(t)

	declared := map[string]bool{}
	for _, p := range m.Permissions {
		if !abiPermissions[p] {
			t.Errorf("%q is not in the ABI's vocabulary, which is closed: an unknown "+
				"token refuses the add-on at load", p)
		}
		if declared[p] {
			t.Errorf("%q is declared twice", p)
		}
		declared[p] = true
	}

	// What each grant buys this add-on, one line each, so that removing a call
	// site and leaving the grant behind fails here.
	want := map[string]string{
		"routes.own_prefix":  "http_request_read and http_response_write",
		"session.context":    "session_context, to know whether to link or to mint",
		"session.mint":       "session_mint and identity_link, which are one grant",
		"storage.own_schema": "storage_query and storage_exec, for the flow's own state",
		"config.read":        "config_get, for every setting an operator fills in",
		"network.fetch":      "network_fetch, for discovery, the key set and the exchange",
	}
	for p := range want {
		if !declared[p] {
			t.Errorf("%q is not declared and this add-on calls %s", p, want[p])
		}
	}
	for p := range declared {
		if _, used := want[p]; !used {
			t.Errorf("%q is declared and nothing in this add-on uses it; a grant an "+
				"operator hands over should be one that is spent", p)
		}
	}
	// The two redirect classes above all: this add-on is never on the redirect
	// path, and holding either would put it there.
	for _, never := range []string{"redirect.inline", "redirect.observe", "redirect.rewrite_query"} {
		if declared[never] {
			t.Errorf("%q is declared; this add-on exports no redirect handler and an "+
				"inline invocation could not fetch anyway", never)
		}
	}
}

func TestTheOriginSettingIsTheOnlyPlaceADestinationCanCome(t *testing.T) {
	m, _ := readManifest(t)

	origins := 0
	for _, s := range m.Settings {
		if !s.Origin {
			continue
		}
		origins++
		// Each of these is what makes "the manifest declares a need, never a
		// destination" structural. The host refuses the add-on at load for any of
		// them, so this test is the difference between finding out here and finding
		// out on somebody's instance.
		if s.Type != "text" {
			t.Errorf("the origin setting %q is type %q; an operator types an origin "+
				"into a text box and no other input carries one", s.Name, s.Type)
		}
		if s.Default != "" {
			t.Errorf("the origin setting %q carries a default, which would be a "+
				"destination this add-on's author chose", s.Name)
		}
		if len(s.Options) != 0 {
			t.Errorf("the origin setting %q carries options, which is the allowlist "+
				"this design refuses to have", s.Name)
		}
		if s.Name != SettingProviderOrigins {
			t.Errorf("the origin setting is %q and the code reads %q",
				s.Name, SettingProviderOrigins)
		}
	}
	if origins != 1 {
		t.Fatalf("%d settings are marked origin, want exactly 1", origins)
	}

	// And the other direction of the host's coherence rule: a field naming where
	// this add-on may reach is meaningless without the permission to reach at all.
	declared := false
	for _, p := range m.Permissions {
		if p == "network.fetch" {
			declared = true
		}
	}
	if !declared {
		t.Error("a setting is marked origin and network.fetch is not declared")
	}
	// Anywhere else a URL could hide. The whole point of the design is that there
	// is no host, pattern or URL in this file.
	for _, s := range m.Settings {
		if s.Default != "" && strings.Contains(s.Default, "://") {
			t.Errorf("setting %q defaults to %q, which is a destination in the manifest",
				s.Name, s.Default)
		}
	}
}

func TestTheSettingsAreTheOnesTheCodeReads(t *testing.T) {
	m, _ := readManifest(t)

	if len(m.Settings) != len(SettingNames) {
		t.Fatalf("the manifest declares %d settings and the code names %d",
			len(m.Settings), len(SettingNames))
	}
	for i, s := range m.Settings {
		if s.Name != SettingNames[i] {
			t.Errorf("setting %d is %q and the code's list has %q", i, s.Name, SettingNames[i])
		}
	}

	nameRe := regexp.MustCompile(`^[a-z][a-z0-9_]{1,30}$`)
	reserved := map[string]bool{"failure_class": true, "mfa_satisfied": true}
	for _, s := range m.Settings {
		if !nameRe.MatchString(s.Name) {
			t.Errorf("setting %q is not a usable setting name", s.Name)
		}
		if reserved[s.Name] {
			t.Errorf("setting %q is reserved; it is how an operator answers *about* "+
				"this add-on rather than a value the add-on reads", s.Name)
		}
		switch s.Type {
		case "text":
		case "secret":
			if s.Default != "" {
				t.Errorf("setting %q is a secret with a default, which is a secret every "+
					"installation of this add-on would share", s.Name)
			}
		case "toggle":
			if s.Default != "" && s.Default != "true" && s.Default != "false" {
				t.Errorf("setting %q is a toggle defaulting to %q", s.Name, s.Default)
			}
		case "select":
			if len(s.Options) < 2 {
				t.Errorf("setting %q is a select with %d options", s.Name, len(s.Options))
			}
		default:
			t.Errorf("setting %q is type %q, which is not one of the four", s.Name, s.Type)
		}
	}
}

func TestTheCookieNamespaceIsThisAddonsOwn(t *testing.T) {
	m, _ := readManifest(t)

	if len(m.CookiePrefixes) != 1 {
		t.Fatalf("cookie_prefixes is %v; this add-on sets one cookie", m.CookiePrefixes)
	}
	prefix := m.CookiePrefixes[0]
	if prefix != Name+"_" {
		t.Errorf("the prefix is %q and must begin with %q: a cookie namespace is "+
			"derived from the add-on's name, so none can be denied its own", prefix, Name+"_")
	}
	if !strings.HasPrefix(CookieFlow, prefix) {
		t.Errorf("the flow cookie is %q, outside the declared prefix %q — the host "+
			"refuses a cookie an add-on may not read, in both directions",
			CookieFlow, prefix)
	}
	for _, host := range []string{"linkctrl", "__Host-", "__Secure-"} {
		if strings.HasPrefix(prefix, host) || strings.HasPrefix(host, prefix) {
			t.Errorf("the prefix %q reaches this product's own cookie namespace", prefix)
		}
	}
}
