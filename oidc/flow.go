package oidc

import (
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// FlowTTL is how long a visitor has between leaving for the provider and coming
// back. Ten minutes: long enough for a password, a second factor and a consent
// screen, short enough that an abandoned flow is not a row somebody can come
// back to tomorrow.
const FlowTTL = 600

// CookieFlow is the cookie that carries the handle to a flow.
//
// The name begins with this add-on's own name and an underscore, which the
// manifest declares as a `cookie_prefixes` entry and which is what makes the
// namespace this add-on's in both directions: the host will not hand it a cookie
// outside it and will not let it set one. What is in the cookie is a random
// handle and nothing else — the `state`, the `nonce` and the PKCE verifier are
// in the schema, where a visitor cannot choose them.
const CookieFlow = "oidc_flow"

// Random is 32 bytes from the operating system's entropy, through the host, as
// base64url.
//
// [sdk.RandomBytes] rather than crypto/rand, which the ABI says are the same
// source and the same bytes. The reason to use the documented spelling is that
// this is the one place where "the same bytes" has ever been false: until ABI
// 0.1.1 the runtime's default random source was a compile-time constant, so
// every module on every deployment drew the same nonce. Reading the ABI's own
// function is what makes the contract about entropy something this add-on relies
// on out loud.
func Random(h Host) (string, error) {
	b, err := h.RandomBytes(32)
	if err != nil {
		return "", fmt.Errorf("drawing random bytes: %w", err)
	}
	if len(b) != 32 {
		return "", fmt.Errorf("asked the host for 32 bytes and got %d", len(b))
	}
	return b64.EncodeToString(b), nil
}

// Now is the host's wall clock. Falls back to the module's own time.Now, which
// the ABI documents as the same clock, so a host that refuses the function does
// not stop a sign-in.
func Now(h Host) time.Time {
	raw, err := h.TimeNow()
	if err == nil {
		if t, err := time.Parse(time.RFC3339Nano, raw); err == nil {
			return t
		}
	}
	return time.Now()
}

// challenge is the S256 PKCE code challenge for a verifier.
func challenge(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	return b64.EncodeToString(sum[:])
}

// Begin starts a flow and answers the redirect that sends the visitor away.
func Begin(h Host, store *Store, cfg Config, mode string) (Response, error) {
	provider := NewProvider(h, store, cfg)
	d, err := provider.Discovery()
	if err != nil {
		return Response{}, err
	}
	if err := d.CheckResponseMode(); err != nil {
		return Response{}, err
	}
	// The key set is fetched here, before the visitor leaves, and not at the
	// callback where it is first needed.
	//
	// Two reasons and both are about somebody's time. An operator who named the
	// discovery origin and not the key set's — the case a provider spreading its
	// documents over three hostnames produces — finds out now instead of after a
	// round trip through a sign-in page. And the callback, which is the invocation
	// that also has to verify a signature and mint a session, is left spending its
	// route deadline on the token exchange alone.
	if _, err := provider.Keys(d, false); err != nil {
		return Response{}, err
	}

	// Swept here rather than on a schedule, because there is no schedule: the ABI
	// gives an add-on no timer, so the only moments this module runs are the ones
	// somebody asked it to. Starting a flow is the moment rows are created, which
	// makes it the moment worth spending on removing the dead ones.
	if err := store.Sweep(); err != nil {
		_ = h.Log(LevelWarn, "could not sweep expired flows: "+err.Error())
	}

	handle, err := Random(h)
	if err != nil {
		return Response{}, err
	}
	state, err := Random(h)
	if err != nil {
		return Response{}, err
	}
	nonce, err := Random(h)
	if err != nil {
		return Response{}, err
	}
	verifier, err := Random(h)
	if err != nil {
		return Response{}, err
	}

	if err := store.SaveFlow(Flow{
		Handle: handle, Mode: mode, State: state,
		Nonce: nonce, Verifier: verifier, Issuer: cfg.Issuer,
	}, FlowTTL); err != nil {
		return Response{}, fmt.Errorf("saving the flow: %w", err)
	}

	q := url.Values{}
	q.Set("response_type", "code")
	q.Set("client_id", cfg.ClientID)
	q.Set("redirect_uri", cfg.RedirectURI)
	q.Set("scope", cfg.Scopes)
	q.Set("state", state)
	q.Set("nonce", nonce)
	q.Set("code_challenge", challenge(verifier))
	q.Set("code_challenge_method", "S256")
	// `query` rather than the provider's default, said out loud. It is already the
	// authorization-code flow's default and saying it costs nothing; what it buys
	// is that a provider configured to prefer form_post for this client sends a
	// GET anyway, which is the only response mode that reaches an add-on here.
	q.Set("response_mode", "query")

	return Response{
		Location: joinQuery(d.AuthorizationEndpoint, q.Encode()),
		SetCookie: []Cookie{{
			Name:   CookieFlow,
			Value:  handle,
			MaxAge: FlowTTL,
		}},
	}, nil
}

// joinQuery appends a query to an endpoint that may already carry one, which
// OpenID Connect Core requires an authorization endpoint be allowed to.
func joinQuery(endpoint, query string) string {
	if strings.Contains(endpoint, "?") {
		return endpoint + "&" + query
	}
	return endpoint + "?" + query
}

// tokenResponse is the token endpoint's answer, in the fields this add-on reads.
// The access token is deliberately absent: this is an authentication flow and
// this add-on calls no userinfo endpoint, so a token it does not use is a token
// it does not want in its memory or its schema.
type tokenResponse struct {
	IDToken          string `json:"id_token"`
	TokenType        string `json:"token_type"`
	Error            string `json:"error"`
	ErrorDescription string `json:"error_description"`
}

// Exchange trades an authorization code for an ID token and verifies it.
//
// The exchange is `client_secret_post`, and that is the ABI's decision rather
// than this add-on's: the FetchRequest record carries no headers and the host
// sets exactly three, so there is no way to send an Authorization header and
// `client_secret_basic` is unreachable. A provider that offers only the basic
// form cannot be used, in the same way one that offers only form_post cannot.
func Exchange(h Host, store *Store, cfg Config, flow Flow, code string) (IDToken, error) {
	provider := NewProvider(h, store, cfg)
	d, err := provider.Discovery()
	if err != nil {
		return IDToken{}, err
	}

	form := url.Values{}
	form.Set("grant_type", "authorization_code")
	form.Set("code", code)
	form.Set("redirect_uri", cfg.RedirectURI)
	form.Set("client_id", cfg.ClientID)
	form.Set("client_secret", cfg.ClientSecret)
	form.Set("code_verifier", flow.Verifier)

	body, err := fetch(h, FetchRequest{
		URL: d.TokenEndpoint, Method: "POST", Body: form.Encode(),
	})
	if err != nil {
		// A token endpoint answers OAuth errors with a 400 and a JSON body, and the
		// host reports that as `ok` with the status — it reached who it was told to
		// and does not judge the answer. So the body is worth reading before the
		// status is reported, because "invalid_grant" is a better sentence than
		// "the token endpoint answered 400".
		var fe *FetchError
		if errors.As(err, &fe) && fe.Outcome == OutcomeOK {
			return IDToken{}, err
		}
		return IDToken{}, err
	}
	var tr tokenResponse
	if err := json.Unmarshal(body, &tr); err != nil {
		return IDToken{}, fmt.Errorf("%s answered something that is not a token response: %w",
			d.TokenEndpoint, err)
	}
	if tr.Error != "" {
		return IDToken{}, fmt.Errorf("the token endpoint refused the exchange: %s%s",
			tr.Error, describe(tr.ErrorDescription))
	}
	if tr.IDToken == "" {
		return IDToken{}, errors.New("the token endpoint answered no id_token; this " +
			"add-on requests the openid scope and reads an ID token, so a response " +
			"without one is a client configured for plain OAuth")
	}

	want := Expectations{
		Issuer:   cfg.Issuer,
		ClientID: cfg.ClientID,
		Nonce:    flow.Nonce,
		Now:      Now(h),
		Skew:     time.Duration(cfg.ClockSkew) * time.Second,
	}
	set, err := provider.Keys(d, false)
	if err != nil {
		return IDToken{}, err
	}
	token, err := VerifyIDToken(tr.IDToken, set, want)
	if err == nil {
		return token, nil
	}
	if !errors.Is(err, errUnknownKid) {
		return IDToken{}, err
	}
	// One refresh, and only for the failure a refresh can fix. A provider that has
	// rotated its keys since this add-on cached them names a `kid` the cached set
	// does not carry; anything else about the token is not going to be different
	// after another fetch, and a verifier that re-fetches on every failure is one
	// an attacker can point at somebody's key set.
	provider.ForgetKeys()
	set, err = provider.Keys(d, true)
	if err != nil {
		return IDToken{}, err
	}
	return VerifyIDToken(tr.IDToken, set, want)
}

func describe(s string) string {
	if s == "" {
		return ""
	}
	return " (" + s + ")"
}

// Assert hands a verified identity to the host, in whichever direction the flow
// was started for.
//
// The two directions have opposite requirements about a session and that is the
// whole of what stops either doing the other's job: `identity_link` is ErrDenied
// when nobody is signed in, and `session_mint` is ErrDenied when somebody is. So
// this function does not check who is signed in before calling — the host's
// answer is the authority, and a check here would be a second opinion that could
// disagree with it.
func Assert(h Host, cfg Config, mode string, token IDToken) (Response, error) {
	if cfg.RequireVerifiedEmail && !bool(token.EmailVerified) {
		return Response{}, fmt.Errorf("the provider did not verify %q, and this add-on's "+
			SettingRequireVerifiedEmail+" setting is on", token.Email)
	}
	claim, err := json.Marshal(token.AsClaim())
	if err != nil {
		return Response{}, fmt.Errorf("building the claim: %w", err)
	}

	switch mode {
	case ModeLink:
		if err := h.IdentityLink(claim); err != nil {
			return Response{}, fmt.Errorf("the host did not link this identity: %w", err)
		}
		_ = h.Log(LevelInfo, "linked an identity from "+token.Issuer)
		return Response{Location: cfg.AfterLink, SetCookie: clearFlow()}, nil

	case ModeSignIn:
		raw, err := h.SessionMint(claim)
		if err != nil {
			return Response{}, fmt.Errorf("the host did not mint a session: %w", err)
		}
		var minted Minted
		if err := json.Unmarshal(raw, &minted); err != nil {
			return Response{}, fmt.Errorf("the host's MintedSession is not readable: %w", err)
		}
		_ = h.Log(LevelInfo, "minted a session from "+token.Issuer+
			", expiring "+minted.ExpiresAt+
			", second factor required: "+strconv.FormatBool(minted.SecondFactorRequired))
		// The location is written either way. An account with a second factor
		// enrolled meets it *after* this call rather than instead of it: the host
		// replaces this response with its own prompt and sends the visitor here
		// afterwards. What is not replaced is the cookie below, so the flow's own
		// state is cleared for both kinds of account.
		return Response{Location: cfg.AfterSignIn, SetCookie: clearFlow()}, nil

	default:
		return Response{}, fmt.Errorf("the flow's mode is %q, which is neither %q nor %q",
			mode, ModeSignIn, ModeLink)
	}
}

// clearFlow deletes the flow cookie. A negative max_age is a deletion, and the
// magnitude reaches no arithmetic.
func clearFlow() []Cookie {
	return []Cookie{{Name: CookieFlow, Value: "", MaxAge: -1}}
}
