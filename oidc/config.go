package oidc

import (
	"errors"
	"fmt"
	"net/url"
	"strconv"
	"strings"

	"github.com/DevOfPie/LinkCtrl/sdk"
)

// The settings this add-on declares. Every one of these is a name in addon.json
// and a row the operator fills in on the Add-on manager's detail page, and the
// constants are here so the manifest and the code cannot disagree about a
// spelling. A test reads addon.json and asserts that this list and its settings
// array are the same set.
const (
	// SettingIssuer is the provider's issuer URL — the `iss` this add-on will
	// insist an ID token carries, and the base the discovery document is fetched
	// from. Exact string comparison, per OpenID Connect Core 3.1.3.7.
	SettingIssuer = "issuer"
	// SettingClientID is the client identifier the provider issued.
	SettingClientID = "client_id"
	// SettingClientSecret is the client secret, declared `secret` so the manager
	// does not echo it back. It is sent as a form field, because the ABI carries
	// no request header and client_secret_basic is therefore unreachable.
	SettingClientSecret = "client_secret"
	// SettingRedirectURI is the absolute URL of this add-on's callback route.
	//
	// **It is an operator's setting because it has to be.** The host knows its own
	// public base URL — LINKCTRL_APP_BASE_URL — and no ABI record carries it: the
	// request record has no Host header, no scheme and no absolute form, and Path
	// is relative to this add-on's prefix by design. So an add-on cannot construct
	// the redirect_uri it must send to the provider, and the operator types a
	// value their instance already knows.
	SettingRedirectURI = "redirect_uri"
	// SettingProviderOrigins is the origin-marked setting: the whole of how a
	// destination reaches the host. It carries no default and no options, and it
	// is the reason this add-on reaches nothing until it is configured.
	SettingProviderOrigins = "provider_origins"
	// SettingScopes is the scope string. `openid` is added if the operator drops it.
	SettingScopes = "scopes"
	// SettingAfterSignIn is where a minted session lands.
	SettingAfterSignIn = "after_sign_in"
	// SettingAfterLink is where a completed link lands.
	SettingAfterLink = "after_link"
	// SettingRequireVerifiedEmail refuses an assertion whose email the provider
	// did not verify. Off by default: the host matches on subject and issuer and
	// never on an email address, so this changes nothing about which account is
	// reached — it is an operator's policy about the claim, not a defence.
	SettingRequireVerifiedEmail = "require_verified_email"
	// SettingClockSkewSeconds is how far out the provider's clock may be.
	SettingClockSkewSeconds = "clock_skew_seconds"
	// SettingDiscoveryTTLSeconds is how long a discovery document and a key set
	// are kept in this add-on's own schema before they are fetched again.
	SettingDiscoveryTTLSeconds = "discovery_ttl_seconds"
)

// SettingNames is every declared setting, in manifest order. The manifest test
// compares against this.
var SettingNames = []string{
	SettingIssuer,
	SettingClientID,
	SettingClientSecret,
	SettingRedirectURI,
	SettingProviderOrigins,
	SettingScopes,
	SettingAfterSignIn,
	SettingAfterLink,
	SettingRequireVerifiedEmail,
	SettingClockSkewSeconds,
	SettingDiscoveryTTLSeconds,
}

// Config is this add-on's settings, read afresh for one invocation.
//
// Read once at the top of a call and never again, which is what the ABI asks
// for: a value is re-read at every config_get so that an operator's save reaches
// a module without a restart, and two reads inside one invocation that straddle
// a save can differ. A flow that compared a redirect_uri it built at the start
// against one it read at the end would be comparing two moments.
type Config struct {
	Issuer               string
	ClientID             string
	ClientSecret         string
	RedirectURI          string
	Scopes               string
	AfterSignIn          string
	AfterLink            string
	RequireVerifiedEmail bool
	ClockSkew            int
	DiscoveryTTL         int
}

// ErrUnconfigured is what LoadConfig answers when a setting this add-on cannot
// run without is empty. It carries the operator-facing sentence rather than a
// code, because the page it ends up on is read by the person who can fix it.
type ErrUnconfigured struct {
	Missing []string
}

func (e *ErrUnconfigured) Error() string {
	return "this add-on is not configured yet: " + strings.Join(e.Missing, ", ") +
		" have no value. Set them on the Add-on manager's detail page for this add-on."
}

// setting reads one declared setting.
//
// A declared setting with no value and no default is [sdk.ErrNotFound], which is
// not an error here — it is the ordinary state of a freshly installed add-on —
// so it comes back as the empty string. Anything else is reported: ErrDenied
// means this add-on did not declare `config.read` or did not declare the key,
// and both are publishing mistakes an operator should see rather than have
// silently rounded to a default.
func setting(h Host, key string) (string, error) {
	v, err := h.ConfigGet(key)
	switch {
	case err == nil:
		return strings.TrimSpace(v), nil
	case errors.Is(err, sdk.ErrNotFound):
		return "", nil
	default:
		return "", fmt.Errorf("reading the %q setting: %w", key, err)
	}
}

// LoadConfig reads every setting and refuses a configuration that cannot work.
func LoadConfig(h Host) (Config, error) {
	var c Config
	var err error
	read := func(key string, into *string) {
		if err != nil {
			return
		}
		*into, err = setting(h, key)
	}
	read(SettingIssuer, &c.Issuer)
	read(SettingClientID, &c.ClientID)
	read(SettingClientSecret, &c.ClientSecret)
	read(SettingRedirectURI, &c.RedirectURI)
	read(SettingScopes, &c.Scopes)
	read(SettingAfterSignIn, &c.AfterSignIn)
	read(SettingAfterLink, &c.AfterLink)
	var verified, skew, ttl string
	read(SettingRequireVerifiedEmail, &verified)
	read(SettingClockSkewSeconds, &skew)
	read(SettingDiscoveryTTLSeconds, &ttl)
	if err != nil {
		return Config{}, err
	}

	var missing []string
	for _, r := range []struct {
		name  string
		value string
	}{
		{SettingIssuer, c.Issuer},
		{SettingClientID, c.ClientID},
		{SettingClientSecret, c.ClientSecret},
		{SettingRedirectURI, c.RedirectURI},
	} {
		if r.value == "" {
			missing = append(missing, r.name)
		}
	}
	if len(missing) > 0 {
		return Config{}, &ErrUnconfigured{Missing: missing}
	}

	// The issuer is compared byte for byte against the `iss` claim and is joined
	// onto a well-known path, so a trailing slash would make one of those two
	// wrong. Normalized here rather than at each use.
	c.Issuer = strings.TrimSuffix(c.Issuer, "/")
	if err := checkHTTPS(c.Issuer, SettingIssuer); err != nil {
		return Config{}, err
	}
	if err := checkHTTPS(c.RedirectURI, SettingRedirectURI); err != nil {
		return Config{}, err
	}

	c.Scopes = normalizeScopes(c.Scopes)
	c.AfterSignIn = safePath(c.AfterSignIn, "/dashboard")
	c.AfterLink = safePath(c.AfterLink, "/dashboard")
	c.RequireVerifiedEmail = verified == "true"
	c.ClockSkew = boundedInt(skew, 60, 0, 600)
	c.DiscoveryTTL = boundedInt(ttl, 900, 0, 86400)
	return c, nil
}

// checkHTTPS refuses a setting that is not an absolute https URL.
//
// The host would refuse a cleartext fetch itself, with `invalid_request`, and
// this is here anyway: the redirect_uri is never fetched by the host — it is
// sent to the provider and typed into a Location header — so nothing but this
// check stands between an operator's typo and a code delivered over cleartext.
func checkHTTPS(raw, name string) error {
	u, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("the %q setting %q is not a URL: %w", name, raw, err)
	}
	if u.Scheme != "https" || u.Host == "" {
		return fmt.Errorf("the %q setting must be an absolute https URL, and %q is not",
			name, raw)
	}
	return nil
}

// normalizeScopes keeps the operator's list and guarantees `openid` is in it,
// because a request without it is an OAuth request and this add-on reads an ID
// token out of the answer.
func normalizeScopes(raw string) string {
	if raw == "" {
		raw = "openid profile email"
	}
	scopes := strings.Fields(raw)
	for _, s := range scopes {
		if s == "openid" {
			return strings.Join(scopes, " ")
		}
	}
	return strings.Join(append([]string{"openid"}, scopes...), " ")
}

// safePath bounds where a completed flow may land to a path on this instance.
//
// The host allows an add-on's Location to be an absolute http(s) URL, because an
// authentication add-on's whole job is to send somebody to a provider. That
// makes the *return* leg a place an open redirect would live: an operator who
// pasted an attacker's URL into after_sign_in would have configured one, and so
// would anything that let a query parameter reach this field. Only a
// same-instance path is accepted, and "//host" is refused explicitly — the host
// refuses it too, but a refusal at the call is a 502 for the visitor and this is
// a working page.
func safePath(raw, fallback string) string {
	if raw == "" || !strings.HasPrefix(raw, "/") || strings.HasPrefix(raw, "//") {
		return fallback
	}
	if strings.ContainsAny(raw, "\r\n\x00\\") {
		return fallback
	}
	return raw
}

// boundedInt reads a number an operator typed, and answers the fallback for
// anything it cannot use. Not an error: a mistyped skew should not stop sign-in,
// and the bounds are what stop a typo becoming a policy.
func boundedInt(raw string, fallback, low, high int) int {
	n, err := strconv.Atoi(raw)
	if err != nil || n < low || n > high {
		return fallback
	}
	return n
}
