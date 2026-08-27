package oidc

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"slices"
	"strings"
)

// Discovery is the provider's metadata document, in the fields this add-on uses.
type Discovery struct {
	Issuer                string   `json:"issuer"`
	AuthorizationEndpoint string   `json:"authorization_endpoint"`
	TokenEndpoint         string   `json:"token_endpoint"`
	JWKSURI               string   `json:"jwks_uri"`
	ChallengeMethods      []string `json:"code_challenge_methods_supported"`
	ResponseModes         []string `json:"response_modes_supported"`
}

// The cache keys, which are also what an operator sees on the status page.
const (
	docDiscovery = "discovery"
	docJWKS      = "jwks"
)

// DiscoveryPath is what is joined onto the issuer. OpenID Connect Discovery puts
// it after the issuer's own path, not at the root of the host, which matters for
// an issuer like https://example.com/realms/main.
const DiscoveryPath = "/.well-known/openid-configuration"

// Provider reads the two documents an authorization-code flow needs, through the
// add-on's own schema so that the ordinary callback spends one fetch and not
// three.
//
// A route handler is bounded by LINKCTRL_ADDON_ROUTE_DEADLINE — ten seconds by
// default and lower on some instances — and each fetch is bounded by
// LINKCTRL_ADDON_FETCH_TIMEOUT or by whatever is left of the route's, whichever
// ends first. The ABI says three fetches at the defaults fit and to budget as
// though the deadline were shorter; caching is how this add-on does that.
type Provider struct {
	h     Host
	store *Store
	cfg   Config
}

// NewProvider does no I/O.
func NewProvider(h Host, store *Store, cfg Config) *Provider {
	return &Provider{h: h, store: store, cfg: cfg}
}

// Discovery answers the metadata document, from the schema when it is fresh.
func (p *Provider) Discovery() (Discovery, error) {
	var d Discovery
	if body, err := p.cached(docDiscovery); err == nil && body != "" {
		if err := json.Unmarshal([]byte(body), &d); err == nil {
			if err := p.checkDiscovery(d); err == nil {
				return d, nil
			}
			// A cached document that no longer agrees with the settings — the operator
			// re-pointed `issuer` — is not an error, it is a stale cache. Dropped and
			// fetched again below.
			_ = p.store.ForgetDocument(docDiscovery)
		}
	}
	endpoint := p.cfg.Issuer + DiscoveryPath
	body, err := fetch(p.h, FetchRequest{URL: endpoint})
	if err != nil {
		return Discovery{}, err
	}
	if err := json.Unmarshal(body, &d); err != nil {
		return Discovery{}, fmt.Errorf("%s answered something that is not a discovery "+
			"document: %w", endpoint, err)
	}
	if err := p.checkDiscovery(d); err != nil {
		return Discovery{}, err
	}
	p.cache(docDiscovery, string(body))
	return d, nil
}

// checkDiscovery refuses a document that does not describe the configured issuer.
//
// The `issuer` comparison is OpenID Connect Discovery's own requirement and it
// is the one check that makes the rest of the document trustworthy: every
// endpoint below is read out of this file, so a document that belongs to
// somebody else is a token endpoint that belongs to somebody else. The host's
// origin allowlist is the second half of that — it refuses a redirect off the
// origin and refuses an endpoint on an origin the operator did not name — and
// neither half is sufficient alone.
func (p *Provider) checkDiscovery(d Discovery) error {
	if strings.TrimSuffix(d.Issuer, "/") != p.cfg.Issuer {
		return fmt.Errorf("the discovery document at %s names issuer %q, and this "+
			"add-on is configured for %q", p.cfg.Issuer+DiscoveryPath, d.Issuer, p.cfg.Issuer)
	}
	for _, e := range []struct{ name, value string }{
		{"authorization_endpoint", d.AuthorizationEndpoint},
		{"token_endpoint", d.TokenEndpoint},
		{"jwks_uri", d.JWKSURI},
	} {
		if e.value == "" {
			return fmt.Errorf("the discovery document has no %s", e.name)
		}
		u, err := url.Parse(e.value)
		if err != nil || u.Scheme != "https" || u.Host == "" {
			return fmt.Errorf("the discovery document's %s is %q, which is not an "+
				"absolute https URL", e.name, e.value)
		}
	}
	if len(d.ChallengeMethods) > 0 && !slices.Contains(d.ChallengeMethods, "S256") {
		return fmt.Errorf("the provider advertises code_challenge_methods_supported "+
			"%v and not S256; this add-on sends PKCE with S256 and does not fall back "+
			"to `plain`", d.ChallengeMethods)
	}
	return nil
}

// Keys answers the provider's key set, from the schema when it is fresh.
//
// refresh forces a fetch, which is what a token naming a `kid` the cached set
// does not carry means. It is a parameter rather than a retry loop because the
// caller gets exactly one refresh per callback: a token that names an unknown
// key twice is a token this add-on is not going to verify, and a loop would be a
// way to spend a route deadline on somebody else's rotation schedule.
func (p *Provider) Keys(d Discovery, refresh bool) (JWKS, error) {
	var set JWKS
	if !refresh {
		if body, err := p.cached(docJWKS); err == nil && body != "" {
			if err := json.Unmarshal([]byte(body), &set); err == nil && len(set.Keys) > 0 {
				return set, nil
			}
		}
	}
	body, err := fetch(p.h, FetchRequest{URL: d.JWKSURI})
	if err != nil {
		return JWKS{}, err
	}
	if err := json.Unmarshal(body, &set); err != nil {
		return JWKS{}, fmt.Errorf("%s answered something that is not a key set: %w",
			d.JWKSURI, err)
	}
	if len(set.Keys) == 0 {
		return JWKS{}, fmt.Errorf("%s answered a key set with no keys in it", d.JWKSURI)
	}
	p.cache(docJWKS, string(body))
	return set, nil
}

// cached reads a document, and treats every storage failure as a miss.
//
// A cache that can fail a sign-in is worse than no cache. The failure is logged,
// because an operator whose add-on has lost its schema should see it somewhere,
// and the flow continues to the fetch.
func (p *Provider) cached(name string) (string, error) {
	if p.cfg.DiscoveryTTL <= 0 {
		return "", nil
	}
	body, err := p.store.Document(name)
	if err != nil {
		p.warn("could not read the cached " + name + " document: " + err.Error())
		return "", err
	}
	return body, nil
}

// cache writes one, and a failure is logged and not returned, for the reason
// above: this add-on has already got what it needed from the network.
func (p *Provider) cache(name, body string) {
	if p.cfg.DiscoveryTTL <= 0 {
		return
	}
	if err := p.store.SaveDocument(name, body, p.cfg.DiscoveryTTL); err != nil {
		p.warn("could not cache the " + name + " document: " + err.Error())
	}
}

// ForgetKeys drops the cached key set, which is what a rotation needs.
func (p *Provider) ForgetKeys() {
	if err := p.store.ForgetDocument(docJWKS); err != nil {
		p.warn("could not drop the cached key set: " + err.Error())
	}
}

func (p *Provider) warn(message string) {
	_ = p.h.Log(LevelWarn, message)
}

// ErrFormPost is the one provider configuration this product cannot be used
// with, and it is named rather than discovered.
//
// LinkCtrl's application tree refuses every cross-site request that uses an
// unsafe method — `Sec-Fetch-Site: cross-site` and `same-site` are both 403,
// before the module is entered — so a `form_post` callback is a POST navigation
// that never arrives. There is no exemption: not a trusted origin the manifest
// names, not a declared callback path. A provider that offers only `form_post`
// is a provider to plan around before choosing it.
var ErrFormPost = errors.New("this provider supports only response_mode=form_post, " +
	"which arrives as a cross-site POST navigation and is refused by LinkCtrl before " +
	"an add-on is entered; OpenID Connect's authorization-code default is what works here")

// CheckResponseMode refuses a provider that cannot send a GET callback.
//
// Only refused when the provider *advertises* its modes and `query` is not among
// them: response_modes_supported is optional, and a document that omits it says
// nothing, since `query` is the authorization-code flow's default.
func (d Discovery) CheckResponseMode() error {
	if len(d.ResponseModes) == 0 {
		return nil
	}
	if slices.Contains(d.ResponseModes, "query") {
		return nil
	}
	return ErrFormPost
}
