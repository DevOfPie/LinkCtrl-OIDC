// Package oidc is the whole of this add-on's behaviour, written so that it can
// be run and tested off wasm.
//
// # Why the logic is not in package main
//
// A LinkCtrl add-on is a wasip1 reactor: the host instantiates it, calls an
// exported function, and the only way in or out is the generated SDK. Every SDK
// function compiles for any GOOS and answers "the host is not there" off wasip1,
// which is honest and untestable — a test that called [sdk.NetworkFetch] would
// assert on that sentence and nothing else.
//
// So this package reaches the host through [Host], an interface with one method
// per SDK function it uses. Package main implements it in eleven lines of
// forwarding under a wasip1 build tag; the tests implement it with a fake that
// serves a real identity provider's documents and a real signing key. The
// behaviour under test is therefore the behaviour that ships, and the part that
// is not covered is the forwarding, which has nothing in it to get wrong.
//
// # The records are written out here
//
// LinkCtrl's ABI records are a documented JSON shape and not a Go type another
// repository can import — the SDK carries the functions and the statuses, and
// deliberately not the records, so that an add-on declares the fields it reads
// and ignores the rest. That is the publisher's position the first-party
// examples take and this add-on takes it too. Every struct below is one record
// from docs/addon-abi.md, with the fields this add-on actually uses.
package oidc

import "github.com/DevOfPie/LinkCtrl/sdk"

// Request is the ABI's HTTPRequest record.
//
// Path is relative to this add-on's own prefix and always begins with "/", so
// the callback arrives as "/callback" rather than as "/addons/oidc/callback".
// There is no header map and no client address in any spelling; the cookies are
// the ones whose names begin with a prefix the manifest declared.
type Request struct {
	Method         string            `json:"method"`
	Path           string            `json:"path"`
	Query          string            `json:"query"`
	Cookies        map[string]string `json:"cookies"`
	ContentType    string            `json:"content_type"`
	AcceptLanguage string            `json:"accept_language"`
	Body           string            `json:"body"`
	BodyBase64     bool              `json:"body_base64"`
}

// Cookie is one entry of HTTPResponse's set_cookie array. MaxAge is seconds:
// zero is a session cookie, negative deletes, and the host refuses anything over
// 400 days. The name must begin with one of the manifest's cookie_prefixes.
type Cookie struct {
	Name   string `json:"name"`
	Value  string `json:"value"`
	MaxAge int    `json:"max_age,omitempty"`
}

// Response is the ABI's HTTPResponse record.
//
// ContentType empty is the ordinary case and means the host wraps Body in the
// dashboard's own page, escaped. text/html is refused by the host, which is what
// makes "an add-on cannot inject markup" a property of the boundary; every page
// this add-on draws is therefore text.
type Response struct {
	Status      int      `json:"status,omitempty"`
	ContentType string   `json:"content_type,omitempty"`
	Location    string   `json:"location,omitempty"`
	SetCookie   []Cookie `json:"set_cookie,omitempty"`
	Body        string   `json:"body,omitempty"`
}

// FetchRequest is the ABI's FetchRequest record: a URL whose origin the operator
// authorized, a method from a closed pair, and a form-encoded body. There is no
// header map, which is why the token exchange below is client_secret_post.
type FetchRequest struct {
	URL    string `json:"url"`
	Method string `json:"method,omitempty"`
	Body   string `json:"body,omitempty"`
}

// FetchResponse is the ABI's FetchResponse record. Outcome is the first thing to
// read: everything else is empty unless it is [OutcomeOK], and Status is the
// origin's own — a 404 or a 500 is still an `ok` outcome.
type FetchResponse struct {
	Outcome     string `json:"outcome"`
	Status      int    `json:"status,omitempty"`
	ContentType string `json:"content_type,omitempty"`
	Body        string `json:"body,omitempty"`
	BodyBase64  bool   `json:"body_base64,omitempty"`
}

// The fetch outcomes this add-on branches on. The vocabulary is closed and
// larger than this; everything not named here is reported to the operator by its
// own word rather than flattened, because the host publishes the same word as a
// counter label and a log line an operator can match against a dashboard is
// worth more than a sentence this add-on invented.
const (
	// OutcomeOK means a response arrived, whatever its status code was.
	OutcomeOK = "ok"
	// OutcomeUnconfigured means the operator has named no origin for this add-on.
	// It is the ordinary state of a freshly installed copy and gets its own page.
	OutcomeUnconfigured = "unconfigured"
	// OutcomeOriginRefused means the URL's origin is not one the operator named —
	// the case an issuer whose token endpoint lives on a second hostname produces,
	// and the one worth naming a fix for.
	OutcomeOriginRefused = "origin_refused"
)

// Session is the ABI's SessionContext record: who is signed in on the request
// this add-on is answering, and never a cookie, a token or a session row.
type Session struct {
	SignedIn       bool   `json:"signed_in"`
	UserID         string `json:"user_id"`
	Email          string `json:"email"`
	DisplayName    string `json:"display_name"`
	WorkspaceID    string `json:"workspace_id"`
	OrganizationID string `json:"organization_id"`
	Role           string `json:"role"`
}

// Claim is the ABI's SessionClaim record: this add-on's assertion that somebody
// authenticated. It is a claim and not a session — the host decides whether an
// account exists for the subject and how long the session lives.
type Claim struct {
	Subject       string   `json:"subject"`
	Issuer        string   `json:"issuer"`
	Email         string   `json:"email,omitempty"`
	EmailVerified bool     `json:"email_verified,omitempty"`
	DisplayName   string   `json:"display_name,omitempty"`
	Groups        []string `json:"groups,omitempty"`
}

// Minted is the ABI's MintedSession record. SecondFactorRequired is the field a
// callback has to read before it decides where to send somebody: an account with
// TOTP enrolled meets the factor after this add-on's assertion rather than
// instead of it, and the host sends the visitor to its own prompt ahead of
// whatever location this add-on wrote.
type Minted struct {
	ExpiresAt            string `json:"expires_at"`
	SecondFactorRequired bool   `json:"second_factor_required"`
}

// Host is every host function this add-on calls, and nothing else.
//
// One method per SDK function, with the SDK's own signature, so that the wasm
// implementation is forwarding and the fake in the tests is the only other one
// that can exist. The errors are the SDK's sentinels — [sdk.ErrDenied],
// [sdk.ErrNotFound], [sdk.ErrInvalid], [sdk.ErrNotAvailable], [sdk.ErrInternal] —
// and this package compares with errors.Is, so a fake that answers the wrong one
// fails the test rather than passing it.
type Host interface {
	Log(level, message string) error
	ConfigGet(key string) (string, error)
	RandomBytes(count int32) ([]byte, error)
	TimeNow() (string, error)
	StorageQuery(sql string, args []byte) ([]byte, error)
	StorageExec(sql string, args []byte) error
	HTTPRequestRead() ([]byte, error)
	HTTPResponseWrite(response []byte) error
	SessionContextRead() ([]byte, error)
	SessionMint(claim []byte) ([]byte, error)
	IdentityLink(claim []byte) error
	NetworkFetch(request []byte) ([]byte, error)
}

// The log levels, re-exported so that this package does not import the SDK at
// every call site for a string constant.
const (
	LevelDebug = sdk.LevelDebug
	LevelInfo  = sdk.LevelInfo
	LevelWarn  = sdk.LevelWarn
	LevelError = sdk.LevelError
)
