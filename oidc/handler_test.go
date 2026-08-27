package oidc

import (
	"encoding/json"
	"net/url"
	"strings"
	"testing"

	"github.com/DevOfPie/LinkCtrl/sdk"
)

// newSuite is a configured add-on, a configured provider, and nobody signed in.
func newSuite(t *testing.T) *fakeHost {
	t.Helper()
	h := newFakeHost(t)
	h.idp = newFakeIDP()
	h.mintAnswer = Minted{ExpiresAt: "2026-08-28T12:00:00Z"}
	return h.configured()
}

// call runs one request through the export the host calls, end to end, and
// answers what the module wrote. Each call is its own [Store], because a module
// gets a fresh instance per request and keeps nothing between two.
func call(t *testing.T, h *fakeHost, req Request) Response {
	t.Helper()
	h.request = &req
	h.written = Response{}
	h.writes = 0
	if got := Handle(h); got != 0 {
		t.Fatalf("the handler answered %d for %s %s; the log says %v",
			got, req.Method, req.Path, h.logs)
	}
	if h.writes != 1 {
		t.Fatalf("the handler wrote %d responses for %s and a response is one record",
			h.writes, req.Path)
	}
	return h.written
}

// authorizeQuery is what this add-on put in the URL it sent the visitor to.
func authorizeQuery(t *testing.T, res Response) url.Values {
	t.Helper()
	if res.Location == "" {
		t.Fatalf("expected a redirect to the provider, got status %d body %q",
			res.Status, res.Body)
	}
	u, err := url.Parse(res.Location)
	if err != nil {
		t.Fatalf("the Location is not a URL: %v", err)
	}
	return u.Query()
}

// flowCookie is the handle the response set, which the browser sends back.
func flowCookie(t *testing.T, res Response) string {
	t.Helper()
	for _, c := range res.SetCookie {
		if c.Name == CookieFlow {
			return c.Value
		}
	}
	t.Fatalf("no %s cookie in %v", CookieFlow, res.SetCookie)
	return ""
}

// signIn drives the whole flow and answers the callback's response.
func signIn(t *testing.T, h *fakeHost) Response {
	t.Helper()
	begin := call(t, h, Request{Method: "GET", Path: PathStart})
	q := authorizeQuery(t, begin)
	code := h.idp.authorize(q)
	return call(t, h, Request{
		Method:  "GET",
		Path:    PathCallback,
		Query:   url.Values{"code": {code}, "state": {q.Get("state")}}.Encode(),
		Cookies: map[string]string{CookieFlow: flowCookie(t, begin)},
	})
}

func TestSignInMintsASession(t *testing.T) {
	h := newSuite(t)
	res := signIn(t, h)

	if res.Location != "/dashboard" {
		t.Fatalf("callback answered status %d location %q body %q",
			res.Status, res.Location, res.Body)
	}
	if h.mintedClaim == nil {
		t.Fatal("nothing was asserted to the host")
	}
	if h.mintedClaim.Subject != "provider-subject-1" {
		t.Errorf("subject is %q", h.mintedClaim.Subject)
	}
	if h.mintedClaim.Issuer != h.idp.issuer {
		t.Errorf("issuer is %q, want %q", h.mintedClaim.Issuer, h.idp.issuer)
	}
	if h.mintedClaim.Email != "person@example.com" || !h.mintedClaim.EmailVerified {
		t.Errorf("email claim is %+v", h.mintedClaim)
	}
	if h.mintedClaim.DisplayName != "A Person" {
		t.Errorf("display name is %q", h.mintedClaim.DisplayName)
	}
	if len(h.mintedClaim.Groups) != 1 || h.mintedClaim.Groups[0] != "engineering" {
		t.Errorf("groups are %v", h.mintedClaim.Groups)
	}
	if h.linkedClaim != nil {
		t.Error("a sign-in linked an identity, which is the other function's job")
	}
	// The flow cookie is cleared on the way out, whether or not the account owes
	// a second factor: the host replaces the response and never the cookies.
	cleared := false
	for _, c := range res.SetCookie {
		if c.Name == CookieFlow && c.MaxAge < 0 {
			cleared = true
		}
	}
	if !cleared {
		t.Errorf("the flow cookie was not cleared: %v", res.SetCookie)
	}
}

func TestAuthorizationRequestCarriesPKCEAndAFreshStateAndNonce(t *testing.T) {
	h := newSuite(t)
	res := call(t, h, Request{Method: "GET", Path: PathStart})
	q := authorizeQuery(t, res)

	for _, want := range []struct{ key, value string }{
		{"response_type", "code"},
		{"client_id", h.idp.clientID},
		{"redirect_uri", h.settings[SettingRedirectURI]},
		{"code_challenge_method", "S256"},
		{"scope", "openid profile email"},
		{"response_mode", "query"},
	} {
		if got := q.Get(want.key); got != want.value {
			t.Errorf("%s is %q, want %q", want.key, got, want.value)
		}
	}
	if q.Get("state") == "" || q.Get("nonce") == "" || q.Get("code_challenge") == "" {
		t.Fatalf("state, nonce or challenge missing: %v", q)
	}
	if q.Get("state") == q.Get("nonce") {
		t.Error("the state and the nonce are the same value; they answer different questions")
	}
	// The challenge is a digest and not the verifier, which is the whole of PKCE:
	// what crosses the browser is not what proves possession.
	if q.Get("code_challenge") == q.Get("state") {
		t.Error("the code challenge is the state")
	}
	// The verifier never reaches the browser. It is in the schema, and the cookie
	// carries a handle to the row.
	handle := flowCookie(t, res)
	for _, row := range h.storage.flows {
		if strings.Contains(res.Location, row.verifier) {
			t.Error("the PKCE verifier is in the URL the visitor was sent to")
		}
		if row.verifier == handle {
			t.Error("the cookie carries the verifier rather than a handle to it")
		}
		if challenge(row.verifier) != q.Get("code_challenge") {
			t.Error("the challenge is not the digest of the stored verifier")
		}
	}
}

func TestTokenExchangeIsClientSecretPost(t *testing.T) {
	h := newSuite(t)
	signIn(t, h)

	form := h.idp.lastTokenForm
	if form == nil {
		t.Fatal("the token endpoint was never reached")
	}
	// The ABI carries no request headers, so client_secret_basic is unreachable
	// and the credentials travel in the form. This test is the one that would
	// fail if somebody "fixed" that by inventing a header field.
	for _, want := range []struct{ key, value string }{
		{"grant_type", "authorization_code"},
		{"client_id", h.idp.clientID},
		{"client_secret", h.idp.clientSecret},
		{"redirect_uri", h.settings[SettingRedirectURI]},
	} {
		if got := form.Get(want.key); got != want.value {
			t.Errorf("the token request's %s is %q, want %q", want.key, got, want.value)
		}
	}
	if form.Get("code_verifier") == "" {
		t.Error("the token request carries no code_verifier")
	}
}

func TestCallbackIsSingleUse(t *testing.T) {
	h := newSuite(t)
	begin := call(t, h, Request{Method: "GET", Path: PathStart})
	q := authorizeQuery(t, begin)
	code := h.idp.authorize(q)
	cookies := map[string]string{CookieFlow: flowCookie(t, begin)}
	callback := Request{
		Method:  "GET",
		Path:    PathCallback,
		Query:   url.Values{"code": {code}, "state": {q.Get("state")}}.Encode(),
		Cookies: cookies,
	}

	if res := call(t, h, callback); res.Location != "/dashboard" {
		t.Fatalf("the first callback did not succeed: %d %q", res.Status, res.Body)
	}
	posts := h.idp.tokenPosts

	res := call(t, h, callback)
	if res.Status != 400 {
		t.Fatalf("the replayed callback answered %d, want 400", res.Status)
	}
	mustContain(t, res.Body, "already been used")
	if h.idp.tokenPosts != posts {
		t.Error("the replayed callback reached the token endpoint; the flow is claimed " +
			"before anything is exchanged")
	}
	if h.sessionMints != 1 {
		t.Errorf("%d sessions were minted for one flow", h.sessionMints)
	}
}

func TestCallbackRefusesAForeignState(t *testing.T) {
	h := newSuite(t)
	begin := call(t, h, Request{Method: "GET", Path: PathStart})
	q := authorizeQuery(t, begin)
	code := h.idp.authorize(q)

	res := call(t, h, Request{
		Method:  "GET",
		Path:    PathCallback,
		Query:   url.Values{"code": {code}, "state": {"not-the-one"}}.Encode(),
		Cookies: map[string]string{CookieFlow: flowCookie(t, begin)},
	})
	if res.Status != 400 {
		t.Fatalf("answered %d, want 400", res.Status)
	}
	mustContain(t, res.Body, "state is not the one")
	if h.mintedClaim != nil {
		t.Fatal("a session was minted for a callback whose state did not match")
	}
}

func TestCallbackWithoutACookieIsRefused(t *testing.T) {
	h := newSuite(t)
	begin := call(t, h, Request{Method: "GET", Path: PathStart})
	q := authorizeQuery(t, begin)
	code := h.idp.authorize(q)

	res := call(t, h, Request{
		Method: "GET", Path: PathCallback,
		Query: url.Values{"code": {code}, "state": {q.Get("state")}}.Encode(),
	})
	if res.Status != 400 || h.mintedClaim != nil {
		t.Fatalf("answered %d and minted %v", res.Status, h.mintedClaim)
	}
	mustContain(t, res.Body, "did not start here")
}

func TestCallbackReportsTheProvidersOwnRefusal(t *testing.T) {
	h := newSuite(t)
	res := call(t, h, Request{
		Method: "GET", Path: PathCallback,
		Query: url.Values{
			"error":             {"access_denied"},
			"error_description": {"the user said no"},
		}.Encode(),
	})
	if res.Status != 400 {
		t.Fatalf("answered %d, want 400", res.Status)
	}
	mustContain(t, res.Body, "access_denied")
	mustContain(t, res.Body, "the user said no")
	if h.idp.tokenPosts != 0 {
		t.Error("a refused sign-in reached the token endpoint")
	}
}

func TestLinkingConnectsToTheSignedInAccount(t *testing.T) {
	h := newSuite(t)
	h.session = Session{SignedIn: true, UserID: "u-1", Email: "person@example.com", Role: "owner"}

	begin := call(t, h, Request{Method: "GET", Path: PathLink})
	q := authorizeQuery(t, begin)
	code := h.idp.authorize(q)
	res := call(t, h, Request{
		Method: "GET", Path: PathCallback,
		Query:   url.Values{"code": {code}, "state": {q.Get("state")}}.Encode(),
		Cookies: map[string]string{CookieFlow: flowCookie(t, begin)},
	})

	if res.Location != "/dashboard" {
		t.Fatalf("linking answered %d %q", res.Status, res.Body)
	}
	if h.linkedClaim == nil || h.linkedClaim.Subject != "provider-subject-1" {
		t.Fatalf("linked claim is %+v", h.linkedClaim)
	}
	if h.mintedClaim != nil {
		t.Error("linking minted a session, which is the other function's job")
	}
}

func TestTheModeIsTheFlowsAndNotTheMoments(t *testing.T) {
	// A link that begins while somebody is signed in and comes back after their
	// session ended must not turn into a sign-in. The mode is stored with the flow
	// for exactly this.
	h := newSuite(t)
	h.session = Session{SignedIn: true, UserID: "u-1"}
	begin := call(t, h, Request{Method: "GET", Path: PathLink})
	q := authorizeQuery(t, begin)
	code := h.idp.authorize(q)

	h.session = Session{}
	res := call(t, h, Request{
		Method: "GET", Path: PathCallback,
		Query:   url.Values{"code": {code}, "state": {q.Get("state")}}.Encode(),
		Cookies: map[string]string{CookieFlow: flowCookie(t, begin)},
	})
	if h.mintedClaim != nil {
		t.Fatal("a link whose session ended mid-flow minted a session")
	}
	if res.Status != 400 {
		t.Fatalf("answered %d, want the host's refusal to reach the page", res.Status)
	}
	mustContain(t, res.Body, "did not link")
}

func TestAnUnlinkedSubjectMintsNothing(t *testing.T) {
	h := newSuite(t)
	// The host's answer for a subject no account is linked to. It is ErrNotFound
	// and not ErrDenied, and the difference is what this add-on tells somebody.
	h.mintErr = sdk.ErrNotFound

	res := signIn(t, h)
	if res.Status != 400 {
		t.Fatalf("answered %d, want 400", res.Status)
	}
	if h.mintedClaim != nil {
		t.Fatal("the host refused and something was recorded anyway")
	}
	mustContain(t, res.Body, "did not mint a session")
}

func TestStartRefusesSomebodyAlreadySignedIn(t *testing.T) {
	h := newSuite(t)
	h.session = Session{SignedIn: true, UserID: "u-1"}

	res := call(t, h, Request{Method: "GET", Path: PathStart})
	if res.Status != 400 {
		t.Fatalf("answered %d, want 400", res.Status)
	}
	mustContain(t, res.Body, "already signed in")
	if h.idp.discoveryFetches != 0 {
		t.Error("a refusal that costs nothing spent a fetch anyway")
	}
}

func TestLinkRefusesNobody(t *testing.T) {
	h := newSuite(t)
	res := call(t, h, Request{Method: "GET", Path: PathLink})
	if res.Status != 400 {
		t.Fatalf("answered %d, want 400", res.Status)
	}
	mustContain(t, res.Body, "Sign in first")
}

func TestSecondFactorStillOwedIsCarriedThrough(t *testing.T) {
	h := newSuite(t)
	h.mintAnswer = Minted{ExpiresAt: "2026-08-28T12:00:00Z", SecondFactorRequired: true}

	res := signIn(t, h)
	// The response is written the same way: the host is what sends the visitor to
	// its own prompt first, and an add-on that branched on this field would be
	// deciding something that is not its decision. What the add-on does is say so.
	if res.Location != "/dashboard" {
		t.Fatalf("answered %d %q", res.Status, res.Body)
	}
	if !h.logged("second factor required: true") {
		t.Errorf("the log does not record the second factor: %v", h.logs)
	}
}

func TestAnUnconfiguredAddonSaysWhatToFillIn(t *testing.T) {
	h := newFakeHost(t)
	h.idp = newFakeIDP()
	h.session = Session{SignedIn: true, Email: "op@example.com", Role: "owner"}

	res := call(t, h, Request{Method: "GET", Path: PathIndex})
	if res.Status != 503 {
		t.Fatalf("the index answered %d, want 503", res.Status)
	}
	for _, want := range []string{SettingIssuer, SettingClientID, SettingClientSecret,
		SettingRedirectURI, SettingProviderOrigins} {
		mustContain(t, res.Body, want)
	}

	// And every other route refuses rather than half working.
	if got := call(t, h, Request{Method: "GET", Path: PathStart}); got.Status != 503 {
		t.Errorf("start answered %d, want 503", got.Status)
	}
}

func TestTheIndexTellsAnAnonymousVisitorNothingAboutTheConfiguration(t *testing.T) {
	h := newSuite(t)
	res := call(t, h, Request{Method: "GET", Path: PathIndex})
	if res.Status != 0 {
		t.Fatalf("answered %d", res.Status)
	}
	if strings.Contains(res.Body, h.idp.clientID) || strings.Contains(res.Body, h.idp.issuer) {
		t.Fatalf("an anonymous visitor was shown the configuration:\n%s", res.Body)
	}
	mustContain(t, res.Body, addonPath(PathStart))
}

func TestTheIndexProbesTheProviderForAnOperator(t *testing.T) {
	h := newSuite(t)
	h.session = Session{SignedIn: true, Email: "op@example.com", Role: "owner"}

	res := call(t, h, Request{Method: "GET", Path: PathIndex})
	if res.Status != 0 {
		t.Fatalf("answered %d: %s", res.Status, res.Body)
	}
	mustContain(t, res.Body, h.idp.tokenEndpoint)
	mustContain(t, res.Body, h.idp.jwksURI)
	mustContain(t, res.Body, SettingProviderOrigins)
}

func TestAnOriginTheOperatorDidNotNameIsNamedBack(t *testing.T) {
	h := newSuite(t)
	h.session = Session{SignedIn: true, Email: "op@example.com", Role: "owner"}
	// The provider spreads its key set over a second hostname, which the operator
	// has not named. This is the failure the ABI says an add-on has to explain,
	// because nothing else stands between an operator and an add-on that half works.
	h.idp.jwksURI = "https://keys.example.net/jwks.json"

	begin := call(t, h, Request{Method: "GET", Path: PathIndex})
	if !strings.Contains(begin.Body, "keys.example.net") {
		t.Errorf("the status page does not name the second origin:\n%s", begin.Body)
	}

	// And the sign-in is refused before the visitor is sent anywhere, because the
	// key set is read while starting the flow rather than at the callback.
	h.session = Session{}
	res := call(t, h, Request{Method: "GET", Path: PathStart})
	if res.Status != 502 {
		t.Fatalf("answered %d, want 502: %s", res.Status, res.Body)
	}
	if res.Location != "" {
		t.Fatalf("the visitor was sent to the provider anyway: %q", res.Location)
	}
	mustContain(t, res.Body, OutcomeOriginRefused)
	mustContain(t, res.Body, "https://keys.example.net")
	mustContain(t, res.Body, SettingProviderOrigins)
}

func TestNoOriginAtAllIsTheOrdinaryStateOfAFreshInstall(t *testing.T) {
	h := newSuite(t)
	h.origins = nil

	res := call(t, h, Request{Method: "GET", Path: PathStart})
	if res.Status != 502 {
		t.Fatalf("answered %d, want 502: %s", res.Status, res.Body)
	}
	mustContain(t, res.Body, OutcomeUnconfigured)
	mustContain(t, res.Body, SettingProviderOrigins)
}

func TestTheCallbackSpendsOneFetch(t *testing.T) {
	h := newSuite(t)
	begin := call(t, h, Request{Method: "GET", Path: PathStart})
	q := authorizeQuery(t, begin)
	code := h.idp.authorize(q)
	before := h.fetches

	call(t, h, Request{
		Method: "GET", Path: PathCallback,
		Query:   url.Values{"code": {code}, "state": {q.Get("state")}}.Encode(),
		Cookies: map[string]string{CookieFlow: flowCookie(t, begin)},
	})
	// Discovery and the key set are in the add-on's own schema by now, so the
	// callback spends its budget on the exchange alone. Three fetches fit at the
	// defaults and the deadline is lower on some instances.
	if got := h.fetches - before; got != 1 {
		t.Fatalf("the callback made %d outbound requests, want 1 (%d statements: %v)",
			got, len(h.storage.statements), h.storage.statements)
	}
}

func TestARotatedKeyIsFetchedExactlyOnceMore(t *testing.T) {
	h := newSuite(t)
	// Warm the cache with the key that is about to be rotated out.
	call(t, h, Request{Method: "GET", Path: PathStart})
	if h.idp.jwksFetches != 1 {
		t.Fatalf("the key set was fetched %d times while starting a flow, want 1",
			h.idp.jwksFetches)
	}

	h.idp.signKID = "key-2"
	h.idp.publishKID = "key-2"
	res := signIn(t, h)
	if res.Location != "/dashboard" {
		t.Fatalf("a rotated key broke the sign-in: %d %q", res.Status, res.Body)
	}
	if h.idp.jwksFetches != 2 {
		t.Errorf("the key set was fetched %d times: one to warm the cache and one "+
			"refresh when the token named a key that cache did not carry",
			h.idp.jwksFetches)
	}

	// And a token naming a key nobody publishes does not spend a second refresh.
	h.session = Session{}
	h.sessionMints = 0
	h.idp.signKID = "key-3"
	before := h.idp.jwksFetches
	res = signIn(t, h)
	if res.Status != 400 {
		t.Fatalf("an unknown key was accepted: %d %q", res.Status, res.Body)
	}
	if got := h.idp.jwksFetches - before; got != 1 {
		t.Errorf("an unknown key cost %d refetches, want exactly 1", got)
	}
}

func TestAnUnknownPathIs404(t *testing.T) {
	h := newSuite(t)
	res := call(t, h, Request{Method: "GET", Path: "/anything"})
	if res.Status != 404 {
		t.Fatalf("answered %d, want 404", res.Status)
	}

	// And still 404 on an add-on nobody has configured. The path is decided
	// before the settings are read, because a path this add-on does not serve is
	// not a configuration problem and sending an operator to fix one wastes their
	// afternoon.
	blank := newFakeHost(t)
	blank.idp = newFakeIDP()
	if got := call(t, blank, Request{Method: "GET", Path: "/anything"}); got.Status != 404 {
		t.Fatalf("an unconfigured add-on answered %d for an unknown path, want 404",
			got.Status)
	}
}

func TestTheHandlerAnswersOutsideARequestWithoutWriting(t *testing.T) {
	h := newSuite(t)
	h.request = nil
	if got := Handle(h); got != -1 {
		t.Fatalf("answered %d outside a request, want -1", got)
	}
	if h.writes != 0 {
		t.Fatal("something was written outside a request")
	}
}

func TestARefusedGrantReachesTheOperatorsPage(t *testing.T) {
	for _, tc := range []struct {
		name string
		set  func(*fakeHost)
		want string
	}{
		{"storage", func(h *fakeHost) { h.noStorageGrant = true }, "storage.own_schema"},
		{"fetch", func(h *fakeHost) { h.noFetchGrant = true }, "refused the request"},
		{"session", func(h *fakeHost) { h.noSessionGrant = true }, "who is signed in"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := newSuite(t)
			tc.set(h)
			res := call(t, h, Request{Method: "GET", Path: PathStart})
			if res.Status < 400 {
				t.Fatalf("answered %d", res.Status)
			}
			mustContain(t, res.Body, tc.want)
		})
	}
}

func TestEveryResponseIsSomethingTheHostAccepts(t *testing.T) {
	// The fake refuses what the real host refuses — text/html, a 3xx status with a
	// body, a cookie outside the declared namespace, a lifetime over 400 days — so
	// a page this add-on builds that the host would turn away fails here. Driven
	// over every route, including the failing ones.
	h := newSuite(t)
	h.session = Session{SignedIn: true, Email: "op@example.com", Role: "owner"}
	for _, path := range []string{PathIndex, PathStart, PathLink, PathCallback, "/nope"} {
		res := call(t, h, Request{Method: "GET", Path: path})
		if res.ContentType != "" && res.ContentType != "text/plain" &&
			res.ContentType != "application/json" {
			t.Errorf("%s answered content_type %q", path, res.ContentType)
		}
		if res.Status >= 300 && res.Status < 400 {
			t.Errorf("%s answered status %d, and a redirect from an add-on is the "+
				"host's 302 with the status left unset", path, res.Status)
		}
		for _, c := range res.SetCookie {
			if !strings.HasPrefix(c.Name, Name+"_") {
				t.Errorf("%s set %q, outside this add-on's namespace", path, c.Name)
			}
		}
	}
}

func TestNothingOfTheHostsLeaksIntoAPage(t *testing.T) {
	h := newSuite(t)
	res := signIn(t, h)

	blob := res.Body + res.Location + toJSON(res.SetCookie)
	for _, secret := range []string{h.idp.clientSecret, h.settings[SettingClientSecret]} {
		if strings.Contains(blob, secret) {
			t.Fatalf("the client secret reached the response: %s", blob)
		}
	}
	// And the flow's own secrets, which are the schema's and not the browser's.
	for _, row := range h.storage.flows {
		if row.verifier != "" && strings.Contains(blob, row.verifier) {
			t.Fatal("the PKCE verifier reached the response")
		}
	}
	// Nor into the log, which an operator reads and this add-on has no permission
	// to redact anything from.
	for _, line := range h.logs {
		if strings.Contains(line, h.idp.clientSecret) {
			t.Fatalf("the client secret reached the log: %s", line)
		}
	}
}

func TestAClaimIsWhatTheAbiSaysItIs(t *testing.T) {
	h := newSuite(t)
	signIn(t, h)
	raw, err := json.Marshal(h.mintedClaim)
	if err != nil {
		t.Fatal(err)
	}
	var fields map[string]any
	if err := json.Unmarshal(raw, &fields); err != nil {
		t.Fatal(err)
	}
	allowed := map[string]bool{
		"subject": true, "issuer": true, "email": true,
		"email_verified": true, "display_name": true, "groups": true,
	}
	for name := range fields {
		if !allowed[name] {
			t.Errorf("the claim carries %q, which SessionClaim does not declare", name)
		}
	}
}
