package oidc

import (
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strconv"
	"strings"

	"github.com/DevOfPie/LinkCtrl/sdk"
)

// The paths this add-on serves, inside its own prefix. A request arrives with
// its path already relative to `/addons/oidc/`, so the module never learns which
// prefix it was mounted under — which is deliberate: the prefix is its name and
// it knows its name.
const (
	PathIndex    = "/"
	PathStart    = "/start"
	PathLink     = "/link"
	PathCallback = "/callback"
)

// Handle is the whole of a request, and it is what package main's export calls.
//
// It answers exactly once. A handler that returns without writing is a failure
// the host answers as one — there is no implicit empty page — and writing twice
// is ErrInvalid, so every path below produces one Response and this function is
// the only place that writes it.
func Handle(h Host) int32 {
	raw, err := h.HTTPRequestRead()
	if err != nil {
		// Outside a request, which for a route-serving module means package
		// initialization. Nothing to answer.
		_ = h.Log(LevelError, "no request to answer: "+err.Error())
		return -1
	}
	var req Request
	if err := json.Unmarshal(raw, &req); err != nil {
		_ = h.Log(LevelError, "the request record is not readable: "+err.Error())
		return -1
	}

	res := answer(h, req)
	body, err := json.Marshal(res)
	if err != nil {
		_ = h.Log(LevelError, "the response is not encodable: "+err.Error())
		return -1
	}
	if err := h.HTTPResponseWrite(body); err != nil {
		// The bounds on a response are checked when it is written, so this is the
		// host telling this add-on that what it built is outside them. Logged with
		// the status, and answered as a failure rather than retried with something
		// smaller: a second write is refused anyway.
		_ = h.Log(LevelError, "the host refused this response: "+err.Error())
		return -1
	}
	return 0
}

// answer routes one request and never returns an error, because a route handler
// has to produce a page even when everything went wrong.
func answer(h Host, req Request) Response {
	res, err := route(h, req)
	if err == nil {
		return res
	}
	return failure(h, req, err)
}

func route(h Host, req Request) (Response, error) {
	// The path first, before anything is read. A path this add-on does not serve
	// is a 404 whatever the settings say, and answering it with "not configured
	// yet" would send an operator to fix something that is not wrong.
	switch req.Path {
	case PathIndex, PathStart, PathLink, PathCallback:
	default:
		return Response{}, &notFound{path: req.Path}
	}

	store := NewStore(h)

	// Read once, at the top. The ABI is explicit that a setting is re-read at
	// every config_get so that an operator's save reaches a module without a
	// restart, and that two reads inside one invocation which straddle a save can
	// differ. A flow that built a redirect_uri at the start and compared it at the
	// end would be comparing two moments.
	cfg, err := LoadConfig(h)
	if err != nil {
		// The index page is the one that has to work while nothing is configured:
		// it is where an operator finds out what to fill in.
		if req.Path == PathIndex {
			return index(h, store, Config{}, err), nil
		}
		return Response{}, err
	}

	switch req.Path {
	case PathIndex:
		return index(h, store, cfg, nil), nil
	case PathStart:
		return start(h, store, cfg)
	case PathLink:
		return link(h, store, cfg)
	default:
		return callback(h, store, cfg, req)
	}
}

type notFound struct{ path string }

func (e *notFound) Error() string {
	return "this add-on serves " + PathIndex + ", " + PathStart + ", " + PathLink +
		" and " + PathCallback + ", and not " + e.path
}

// start begins a sign-in.
//
// Refused for somebody who is already signed in, and that refusal is this
// add-on's rather than the host's: `session_mint` would refuse it too — a mint
// is how somebody signs in, not how a browser changes who it is — but it would
// refuse it at the *callback*, after the visitor had been to the provider and
// back. Refusing here costs them the trip.
func start(h Host, store *Store, cfg Config) (Response, error) {
	who, err := whoami(h)
	if err != nil {
		return Response{}, err
	}
	if who.SignedIn {
		return Response{}, errors.New("somebody is already signed in on this browser. " +
			"Sign out first, or use " + PathLink + " to connect a provider to this account")
	}
	return Begin(h, store, cfg, ModeSignIn)
}

// link begins a linking flow, which requires the opposite.
func link(h Host, store *Store, cfg Config) (Response, error) {
	who, err := whoami(h)
	if err != nil {
		return Response{}, err
	}
	if !who.SignedIn {
		return Response{}, errors.New("linking connects a provider to the account that " +
			"is signed in, and nobody is. Sign in first")
	}
	return Begin(h, store, cfg, ModeLink)
}

// callback finishes a flow.
func callback(h Host, store *Store, cfg Config, req Request) (Response, error) {
	q, err := url.ParseQuery(req.Query)
	if err != nil {
		return Response{}, fmt.Errorf("the callback's query is not readable: %w", err)
	}
	// The provider's own refusal, which arrives as a redirect like a success does.
	// Reported before anything else is read: there is no code to exchange and the
	// provider has already said why.
	if e := q.Get("error"); e != "" {
		return Response{}, fmt.Errorf("the provider refused the sign-in: %s%s",
			e, describe(q.Get("error_description")))
	}
	code := q.Get("code")
	state := q.Get("state")
	if code == "" || state == "" {
		return Response{}, errors.New("the callback carries no code and state; this is " +
			"the authorization-code flow's redirect and not a page to visit")
	}

	handle := req.Cookies[CookieFlow]
	if handle == "" {
		return Response{}, ErrFlowGone
	}
	flow, err := store.ClaimFlow(handle)
	if err != nil {
		return Response{}, err
	}
	// The `state` check, in constant time, and it is what OAuth's state parameter
	// is for: the host's guarantee is that a link is only ever made for whoever is
	// signed in, in their own browser, at that moment — whether that browser meant
	// to be there is this add-on's to establish and nobody else's.
	if subtle.ConstantTimeCompare([]byte(state), []byte(flow.State)) != 1 {
		return Response{}, errors.New("the callback's state is not the one this flow " +
			"began with")
	}
	// The issuer the flow began against, compared to the one configured now. An
	// operator who re-pointed this add-on mid-flow would otherwise have a code
	// from one provider exchanged at another's token endpoint.
	if flow.Issuer != cfg.Issuer {
		return Response{}, errors.New("this sign-in began against a different provider " +
			"than the one configured now")
	}

	token, err := Exchange(h, store, cfg, flow, code)
	if err != nil {
		return Response{}, err
	}
	return Assert(h, cfg, flow.Mode, token)
}

// whoami reads the session context, treating a host that refuses the grant as an
// error rather than as nobody. An add-on that read "nobody is signed in" out of
// ErrDenied would offer to link an identity to an account it cannot see.
func whoami(h Host) (Session, error) {
	raw, err := h.SessionContextRead()
	if err != nil {
		return Session{}, fmt.Errorf("asking the host who is signed in: %w", err)
	}
	var s Session
	if err := json.Unmarshal(raw, &s); err != nil {
		return Session{}, fmt.Errorf("the session context is not readable: %w", err)
	}
	return s, nil
}

// index is the page an operator reads to find out whether this add-on works.
//
// It is text and it has no links in it, and that is the boundary rather than a
// choice: `content_type` is a closed vocabulary that does not include text/html,
// the host wraps the body in the dashboard's own page escaped, and
// `template_render` answers ErrNotAvailable on every host that has shipped. So
// an add-on cannot draw a button, and the paths below are written out for
// somebody to type or bookmark.
func index(h Host, store *Store, cfg Config, configErr error) Response {
	var b strings.Builder
	b.WriteString("LinkCtrl-OIDC " + Version + "\n")
	if v, err := hostABI(h); err == nil {
		b.WriteString("Host ABI: " + v + ", built against generation " +
			strconv.Itoa(sdk.ABIGeneration) + " (SDK " + sdk.ABIVersion + ")\n")
	}
	b.WriteString("\n")

	who, whoErr := whoami(h)
	switch {
	case whoErr != nil:
		b.WriteString("This add-on could not ask who is signed in: " + whoErr.Error() + "\n")
		return Response{Status: 500, Body: b.String()}
	case !who.SignedIn:
		// Nothing about the configuration for somebody who is not signed in. The
		// issuer and the client id are not secrets, and a page that hands an
		// anonymous visitor an instance's identity-provider configuration is a page
		// that helps somebody decide what to attack.
		b.WriteString("Sign in to LinkCtrl to see this add-on's status.\n\n" +
			"To sign in with the configured identity provider, go to " +
			addonPath(PathStart) + ".\n")
		return Response{Body: b.String()}
	}

	b.WriteString("Signed in as " + who.Email + " (" + who.Role + ").\n\n")
	if configErr != nil {
		b.WriteString("Not configured yet.\n" + configErr.Error() + "\n\n")
		b.WriteString(settingsHelp())
		return Response{Status: 503, Body: b.String()}
	}

	b.WriteString("issuer:        " + cfg.Issuer + "\n")
	b.WriteString("client_id:     " + cfg.ClientID + "\n")
	b.WriteString("redirect_uri:  " + cfg.RedirectURI + "\n")
	b.WriteString("scopes:        " + cfg.Scopes + "\n")
	b.WriteString("\n")

	// One fetch, on the one page whose job is to say whether the outbound half
	// works. It is the diagnostic an operator needs and the only place this add-on
	// spends a request's budget on something a visitor did not ask for.
	d, err := NewProvider(h, store, cfg).Discovery()
	if err != nil {
		b.WriteString("The provider's discovery document could not be read.\n")
		b.WriteString(explain(err))
		return Response{Status: 502, Body: b.String()}
	}
	b.WriteString("The provider answered. Endpoints in use:\n")
	b.WriteString("  authorization: " + d.AuthorizationEndpoint + "\n")
	b.WriteString("  token:         " + d.TokenEndpoint + "\n")
	b.WriteString("  keys:          " + d.JWKSURI + "\n\n")
	if err := d.CheckResponseMode(); err != nil {
		b.WriteString(err.Error() + "\n\n")
	}
	b.WriteString("Every one of those origins has to be named in this add-on's " +
		SettingProviderOrigins + " setting, separated by spaces. The host dials nothing else.\n\n")
	b.WriteString("Sign in:      " + addonPath(PathStart) + "\n")
	b.WriteString("Link this account: " + addonPath(PathLink) + "\n")
	return Response{Body: b.String()}
}

// addonPath spells a route of this add-on's as a visitor types it. The prefix is
// written out because a module is not told what it was mounted under and the
// host derives it from the name — so this constant and the manifest's `name` are
// the same fact in two places, which a test asserts.
func addonPath(path string) string { return "/addons/" + Name + strings.TrimSuffix(path, "/") }

func hostABI(h Host) (string, error) {
	// Not on the [Host] interface: it costs no permission, answers a constant, and
	// adding a method for it would put a line in the fake that proves nothing.
	// Read through the SDK directly, which off wasm says the host is not there.
	return sdk.HostABIVersion()
}

// settingsHelp is the four settings this add-on cannot run without, and the one
// that decides where it may reach. The optional ones are left out on purpose:
// this text is read by somebody looking at a page that does not work, and the
// list they need is the short one.
func settingsHelp() string {
	rows := []struct{ name, what string }{
		{SettingIssuer, "the provider's issuer URL, https, no trailing slash"},
		{SettingClientID, "the client identifier the provider issued"},
		{SettingClientSecret, "the client secret. It is sent as a form field, because " +
			"this ABI carries no request headers, so a provider that offers only " +
			"client_secret_basic cannot be used"},
		{SettingRedirectURI, "the absolute https URL of " + addonPath(PathCallback) +
			" on this instance. It is typed rather than derived because no ABI record " +
			"carries the instance's own scheme and host"},
		{SettingProviderOrigins, "every origin the provider serves discovery, the token " +
			"endpoint and the key set from, separated by spaces. The host dials nothing else"},
	}
	var b strings.Builder
	b.WriteString("Settings, on this add-on's page in the Add-on manager:\n")
	for _, r := range rows {
		b.WriteString("  " + r.name + "\n      " + r.what + "\n")
	}
	return b.String()
}

// failure turns an error into the page somebody sees, and picks the status from
// what kind of failure it was rather than answering 500 for everything.
func failure(h Host, req Request, err error) Response {
	status := 400
	var unconfigured *ErrUnconfigured
	var fe *FetchError
	var nf *notFound
	switch {
	case errors.As(err, &unconfigured):
		status = 503
	case errors.As(err, &fe):
		status = 502
	case errors.As(err, &nf):
		status = 404
	case errors.Is(err, sdk.ErrInternal):
		status = 500
	}

	// One line per failed request, at the level the failure deserves. The host
	// prefixes this add-on's name and neutralizes the message, and a message that
	// repeated the name would be noise.
	level := LevelWarn
	if status >= 500 {
		level = LevelError
	}
	_ = h.Log(level, req.Method+" "+req.Path+" failed: "+err.Error())

	body := "This sign-in did not complete.\n\n" + err.Error() + "\n"
	if extra := explain(err); extra != "" {
		body += "\n" + extra
	}
	// A failed callback leaves a cookie pointing at a flow that is already spent.
	// Cleared, so that a retry starts from nothing rather than from a handle whose
	// row is gone.
	var cookies []Cookie
	if req.Path == PathCallback {
		cookies = clearFlow()
	}
	return Response{Status: status, Body: body, SetCookie: cookies}
}

// explain is the operator-facing half: what to do about this failure, when the
// failure is one with a known fix.
func explain(err error) string {
	var fe *FetchError
	if errors.As(err, &fe) {
		if advice := fe.Advice(); advice != "" {
			return advice + "\n"
		}
		return ""
	}
	var unconfigured *ErrUnconfigured
	if errors.As(err, &unconfigured) {
		return settingsHelp()
	}
	if storageDenied(err) {
		return "This add-on's manifest declares storage.own_schema and the host refused " +
			"it, so the schema it keeps a flow's state in is not there.\n"
	}
	if errors.Is(err, sdk.ErrNotAvailable) {
		return "This host does not implement a function this add-on needs. The ABI " +
			"generation in addon.json is what the host checks at load, and a function " +
			"added in a later patch of the same generation is not covered by it.\n"
	}
	return ""
}

// itoa is here so that store.go does not import strconv for one call.
func itoa(n int) string { return strconv.Itoa(n) }
