package oidc

import (
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/DevOfPie/LinkCtrl/sdk"
)

// This file is the host, as a test double.
//
// Every method answers the way docs/addon-abi.md says the real one does,
// including which of the SDK's five statuses it fails with — a fake that
// answered ErrInternal where the host answers ErrDenied would let this add-on's
// branching pass a test and fail an instance. The storage half is an
// interpreter for the statements this add-on issues, so the single-use claim is
// exercised as a primary-key violation rather than as a flag somebody set; the
// SQL those statements are written in is checked against a real Postgres by
// store_sql_test.go, which is a different claim and is made separately.

// fakeHost implements [Host].
type fakeHost struct {
	t *testing.T

	// settings is what config_get answers. A key absent from the map and present
	// in declared is ErrNotFound; a key absent from declared is ErrDenied, which
	// is what the host answers for a setting the manifest does not declare.
	settings map[string]string
	declared map[string]bool
	// noConfigGrant makes every config_get ErrDenied, which is a manifest that did
	// not declare config.read.
	noConfigGrant bool

	// session is what session_context answers.
	session Session
	// noSessionGrant makes session_context ErrDenied.
	noSessionGrant bool

	// storage is the schema.
	storage *fakeStorage
	// noStorageGrant makes every statement ErrDenied.
	noStorageGrant bool

	// idp answers network_fetch, subject to origins.
	idp *fakeIDP
	// origins is what the operator named. Empty is the ordinary state of a
	// freshly installed add-on and produces the `unconfigured` outcome.
	origins []string
	// noFetchGrant makes network_fetch ErrDenied, which is the answer an inline
	// redirect invocation gets and the answer an undeclared permission gets.
	noFetchGrant bool
	// fetches counts outbound requests, because the route deadline is spent on
	// them and "the callback makes one fetch" is a claim worth asserting.
	fetches int

	// request is what http_request_read answers.
	request *Request
	// written is what the module answered, and writes is how many times, because
	// a second write is ErrInvalid and a handler that writes none is a failure.
	written Response
	writes  int

	// mint and link record what was asserted.
	mintedClaim  *Claim
	linkedClaim  *Claim
	mintAnswer   Minted
	mintErr      error
	linkErr      error
	sessionMints int

	// now is the clock both time_now and the storage's now() read.
	now time.Time

	logs []string
}

func newFakeHost(t *testing.T) *fakeHost {
	t.Helper()
	h := &fakeHost{
		t:        t,
		settings: map[string]string{},
		declared: map[string]bool{},
		storage:  newFakeStorage(),
		now:      time.Date(2026, 8, 27, 12, 0, 0, 0, time.UTC),
	}
	for _, name := range SettingNames {
		h.declared[name] = true
	}
	h.storage.clock = func() time.Time { return h.now }
	return h
}

// configured fills in a working configuration against the test provider.
func (h *fakeHost) configured() *fakeHost {
	h.settings[SettingIssuer] = h.idp.issuer
	h.settings[SettingClientID] = h.idp.clientID
	h.settings[SettingClientSecret] = h.idp.clientSecret
	h.settings[SettingRedirectURI] = "https://links.example.com/addons/oidc/callback"
	h.settings[SettingProviderOrigins] = h.idp.origin()
	h.origins = []string{h.idp.origin()}
	return h
}

func (h *fakeHost) Log(level, message string) error {
	switch level {
	case sdk.LevelDebug, sdk.LevelInfo, sdk.LevelWarn, sdk.LevelError:
	default:
		return sdk.ErrInvalid
	}
	if len(message) > 4096 {
		message = message[:4096]
	}
	h.logs = append(h.logs, level+": "+message)
	return nil
}

func (h *fakeHost) logged(substr string) bool {
	for _, l := range h.logs {
		if strings.Contains(l, substr) {
			return true
		}
	}
	return false
}

func (h *fakeHost) ConfigGet(key string) (string, error) {
	if h.noConfigGrant {
		return "", sdk.ErrDenied
	}
	if !h.declared[key] {
		// The host scopes the function to the add-on's own declared settings; a key
		// outside them is ErrDenied and not ErrNotFound.
		return "", sdk.ErrDenied
	}
	v, ok := h.settings[key]
	if !ok {
		return "", sdk.ErrNotFound
	}
	return v, nil
}

// randomState makes the fake's entropy deterministic and still distinct per
// call, so a test can assert that a state and a nonce are not the same value.
var randomCounter int

func (h *fakeHost) RandomBytes(count int32) ([]byte, error) {
	if count < 1 || count > 4096 {
		return nil, sdk.ErrInvalid
	}
	randomCounter++
	out := make([]byte, count)
	for i := range out {
		out[i] = byte(randomCounter*31 + i*7)
	}
	return out, nil
}

func (h *fakeHost) TimeNow() (string, error) {
	return h.now.Format(time.RFC3339Nano), nil
}

func (h *fakeHost) StorageQuery(sql string, args []byte) ([]byte, error) {
	if h.noStorageGrant {
		return nil, sdk.ErrDenied
	}
	return h.storage.query(sql, args)
}

func (h *fakeHost) StorageExec(sql string, args []byte) error {
	if h.noStorageGrant {
		return sdk.ErrDenied
	}
	return h.storage.exec(sql, args)
}

func (h *fakeHost) HTTPRequestRead() ([]byte, error) {
	if h.request == nil {
		return nil, sdk.ErrNotFound
	}
	return json.Marshal(h.request)
}

func (h *fakeHost) HTTPResponseWrite(raw []byte) error {
	if h.writes > 0 {
		return sdk.ErrInvalid
	}
	var r Response
	if err := json.Unmarshal(raw, &r); err != nil {
		return sdk.ErrInvalid
	}
	// The bounds the host checks at the moment of the write, in the two shapes
	// this add-on could plausibly get wrong.
	if r.ContentType != "" && r.ContentType != "text/plain" && r.ContentType != "application/json" {
		return sdk.ErrInvalid
	}
	if r.Status >= 300 && r.Status < 400 {
		return sdk.ErrInvalid
	}
	for _, c := range r.SetCookie {
		if !strings.HasPrefix(c.Name, Name+"_") {
			return sdk.ErrInvalid
		}
		if c.MaxAge > 400*24*60*60 {
			return sdk.ErrInvalid
		}
	}
	h.written = r
	h.writes++
	return nil
}

func (h *fakeHost) SessionContextRead() ([]byte, error) {
	if h.noSessionGrant {
		return nil, sdk.ErrDenied
	}
	return json.Marshal(h.session)
}

func (h *fakeHost) SessionMint(raw []byte) ([]byte, error) {
	var c Claim
	if err := json.Unmarshal(raw, &c); err != nil {
		return nil, sdk.ErrInvalid
	}
	if c.Subject == "" || c.Issuer == "" {
		return nil, sdk.ErrInvalid
	}
	if h.session.SignedIn {
		// A mint is how somebody signs in and not how a browser changes who it is.
		return nil, sdk.ErrDenied
	}
	if h.mintErr != nil {
		return nil, h.mintErr
	}
	h.sessionMints++
	if h.sessionMints > 1 {
		return nil, sdk.ErrInvalid
	}
	h.mintedClaim = &c
	return json.Marshal(h.mintAnswer)
}

func (h *fakeHost) IdentityLink(raw []byte) error {
	var c Claim
	if err := json.Unmarshal(raw, &c); err != nil {
		return sdk.ErrInvalid
	}
	if !h.session.SignedIn {
		// The mirror requirement: a subject can only be linked while its owner is
		// in front of the browser.
		return sdk.ErrDenied
	}
	if h.linkErr != nil {
		return h.linkErr
	}
	h.linkedClaim = &c
	return nil
}

func (h *fakeHost) NetworkFetch(raw []byte) ([]byte, error) {
	if h.noFetchGrant {
		return nil, sdk.ErrDenied
	}
	var req FetchRequest
	if err := json.Unmarshal(raw, &req); err != nil {
		return nil, sdk.ErrInvalid
	}
	h.fetches++
	res := h.fetchOutcome(req)
	return json.Marshal(res)
}

// fetchOutcome is the host's own policy, in the order it applies it.
func (h *fakeHost) fetchOutcome(req FetchRequest) FetchResponse {
	if !strings.HasPrefix(req.URL, "https://") {
		return FetchResponse{Outcome: "invalid_request"}
	}
	if req.Method != "" && req.Method != "GET" && req.Method != "POST" {
		return FetchResponse{Outcome: "invalid_request"}
	}
	if req.Method != "POST" && req.Body != "" {
		// A body on a GET is refused rather than dropped.
		return FetchResponse{Outcome: "invalid_request"}
	}
	if len(h.origins) == 0 {
		return FetchResponse{Outcome: OutcomeUnconfigured}
	}
	origin := originOf(req.URL)
	allowed := false
	for _, o := range h.origins {
		if o == origin {
			allowed = true
		}
	}
	if !allowed {
		return FetchResponse{Outcome: OutcomeOriginRefused}
	}
	status, contentType, body := h.idp.serve(req)
	return FetchResponse{
		Outcome: OutcomeOK, Status: status, ContentType: contentType, Body: body,
	}
}

// --- the storage interpreter -------------------------------------------------

type flowRow struct {
	mode, state, nonce, verifier, issuer string
	expiresAt                            time.Time
}

type docRow struct {
	body      string
	expiresAt time.Time
}

type fakeStorage struct {
	created bool
	flows   map[string]flowRow
	spent   map[string]time.Time
	docs    map[string]docRow
	clock   func() time.Time
	// statements is every statement that reached the schema, for the tests that
	// assert how many round trips a request costs.
	statements []string
}

func newFakeStorage() *fakeStorage {
	return &fakeStorage{
		flows: map[string]flowRow{},
		spent: map[string]time.Time{},
		docs:  map[string]docRow{},
		clock: time.Now,
	}
}

var spaces = regexp.MustCompile(`\s+`)

// expiring reports whether a statement filters on the expiry, so that a
// statement which stopped doing so is a behaviour change here rather than one
// this interpreter papers over.
func expiring(sql string) bool { return strings.Contains(sql, "expires_at > now()") }

func normalize(sql string) string {
	return strings.TrimSpace(spaces.ReplaceAllString(sql, " "))
}

func decodeArgs(raw []byte) ([]string, error) {
	if len(raw) == 0 {
		return nil, nil
	}
	var out []string
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, sdk.ErrInvalid
	}
	return out, nil
}

// ttl reads a "N seconds" interval argument the way the statements build one.
func ttl(s string) time.Duration {
	n, _ := strconv.Atoi(s)
	return time.Duration(n) * time.Second
}

func (s *fakeStorage) exec(sql string, raw []byte) error {
	n := normalize(sql)
	s.statements = append(s.statements, n)
	if strings.Contains(n, ";") {
		// One statement per call: the host parses through the extended protocol, so
		// a payload carrying two commands is refused.
		return sdk.ErrInvalid
	}
	a, err := decodeArgs(raw)
	if err != nil {
		return err
	}
	switch {
	case strings.HasPrefix(n, "CREATE TABLE IF NOT EXISTS"):
		s.created = true
		return nil
	}
	if !s.created {
		// The relation does not exist. The error text never crosses the boundary,
		// so what a module sees is the status and nothing else.
		return sdk.ErrInvalid
	}
	switch {
	case strings.HasPrefix(n, "INSERT INTO flows"):
		if len(a) != 7 {
			return sdk.ErrInvalid
		}
		if _, clash := s.flows[a[0]]; clash {
			return sdk.ErrInvalid
		}
		s.flows[a[0]] = flowRow{
			mode: a[1], state: a[2], nonce: a[3], verifier: a[4], issuer: a[5],
			expiresAt: s.clock().Add(ttl(a[6])),
		}
		return nil
	case strings.HasPrefix(n, "INSERT INTO spent"):
		if len(a) != 1 {
			return sdk.ErrInvalid
		}
		if _, clash := s.spent[a[0]]; clash {
			// The unique violation this add-on's single-use claim is built on.
			return sdk.ErrInvalid
		}
		s.spent[a[0]] = s.clock()
		return nil
	case strings.HasPrefix(n, "DELETE FROM flows WHERE handle"):
		delete(s.flows, a[0])
		return nil
	case strings.HasPrefix(n, "DELETE FROM flows WHERE expires_at"):
		for k, v := range s.flows {
			if v.expiresAt.Before(s.clock()) {
				delete(s.flows, k)
			}
		}
		return nil
	case strings.HasPrefix(n, "DELETE FROM spent WHERE spent_at"):
		for k, v := range s.spent {
			if v.Before(s.clock().Add(-time.Hour)) {
				delete(s.spent, k)
			}
		}
		return nil
	case strings.HasPrefix(n, "INSERT INTO documents"):
		if len(a) != 3 {
			return sdk.ErrInvalid
		}
		s.docs[a[0]] = docRow{body: a[1], expiresAt: s.clock().Add(ttl(a[2]))}
		return nil
	case strings.HasPrefix(n, "DELETE FROM documents"):
		delete(s.docs, a[0])
		return nil
	}
	return sdk.ErrInvalid
}

func (s *fakeStorage) query(sql string, raw []byte) ([]byte, error) {
	n := normalize(sql)
	s.statements = append(s.statements, n)
	if strings.Contains(n, ";") {
		return nil, sdk.ErrInvalid
	}
	if strings.HasPrefix(n, "INSERT") || strings.HasPrefix(n, "DELETE") ||
		strings.HasPrefix(n, "UPDATE") || strings.HasPrefix(n, "CREATE") {
		// A query cannot write: storage_query runs in a READ ONLY transaction.
		return nil, sdk.ErrInvalid
	}
	a, err := decodeArgs(raw)
	if err != nil {
		return nil, err
	}
	if !s.created {
		return nil, sdk.ErrInvalid
	}
	switch {
	case strings.HasPrefix(n, "SELECT 1 FROM flows"):
		return []byte(`[]`), nil
	case strings.HasPrefix(n, "SELECT mode, state, nonce, verifier, issuer FROM flows"):
		row, ok := s.flows[a[0]]
		// The expiry is applied because the statement asks for it, not because
		// this interpreter has an opinion: a statement that dropped the predicate
		// must be visible here as a row that comes back.
		if !ok || (expiring(n) && !row.expiresAt.After(s.clock())) {
			return []byte(`[]`), nil
		}
		return json.Marshal([]map[string]string{{
			"mode": row.mode, "state": row.state, "nonce": row.nonce,
			"verifier": row.verifier, "issuer": row.issuer,
		}})
	case strings.HasPrefix(n, "SELECT body FROM documents"):
		row, ok := s.docs[a[0]]
		if !ok || (expiring(n) && !row.expiresAt.After(s.clock())) {
			return []byte(`[]`), nil
		}
		return json.Marshal([]map[string]string{{"body": row.body}})
	}
	return nil, sdk.ErrInvalid
}

// counted is how many statements of a shape reached the schema.
func (s *fakeStorage) counted(prefix string) int {
	n := 0
	for _, stmt := range s.statements {
		if strings.HasPrefix(stmt, prefix) {
			n++
		}
	}
	return n
}

// mustErrorIs fails the test unless err wraps target.
func mustErrorIs(t *testing.T, err, target error) {
	t.Helper()
	if !errors.Is(err, target) {
		t.Fatalf("error is %v, want one wrapping %v", err, target)
	}
}

func mustContain(t *testing.T, got, want string) {
	t.Helper()
	if !strings.Contains(got, want) {
		t.Fatalf("got %q, which does not contain %q", got, want)
	}
}

var _ = fmt.Sprintf
