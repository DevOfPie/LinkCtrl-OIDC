package oidc

import (
	"encoding/json"
	"errors"
	"fmt"

	"github.com/DevOfPie/LinkCtrl/sdk"
)

// Store is this add-on's Postgres schema, which the host owns and gives it.
//
// # Why there is storage at all
//
// A module cannot keep state between two requests: its memory is new every time,
// because the host makes an instance per request. An authorization-code flow is
// two requests — the browser leaves for the provider and comes back — and what
// has to survive between them is the PKCE verifier, the `state` and the `nonce`.
// The ABI's own advice is the design here: keep a flow's state in the schema and
// a key to it in a cookie, because a cookie is about 3 KiB shared across
// everything this add-on ever sets and is under the visitor's hand besides.
//
// # Why the tables are created from the module
//
// LinkCtrl runs an add-on's migrations for it — goose SQL in a `migrations/`
// directory, each file named in the manifest with its digest — and that is the
// better shape. It is not available to an add-on that wants to be installable:
// an install bundle is *exactly two files*, the manifest and the module, and the
// API's upload carries the same pair, so an add-on that ships DDL can only be
// put in place by hand in LINKCTRL_ADDONS_DIR. The first-party `pageviews`
// example makes the same trade and says so.
//
// So the DDL is here, idempotent, and run at most once per invocation — after a
// probe, so that the ordinary request pays one round trip rather than three.
type Store struct {
	h       Host
	checked bool
}

// NewStore does no I/O. The schema is reached at the first statement.
func NewStore(h Host) *Store { return &Store{h: h} }

// schema is the DDL, one statement per entry because the host parses through
// Postgres's extended protocol and a payload carrying two commands is refused.
var schema = []string{
	// A flow in progress. Deliberately not indexed on anything but the handle: a
	// row is written once, read once and deleted, and the sweep below is a range
	// scan over a table that holds a few minutes of sign-ins.
	`CREATE TABLE IF NOT EXISTS flows (
		handle     text PRIMARY KEY,
		mode       text NOT NULL,
		state      text NOT NULL,
		nonce      text NOT NULL,
		verifier   text NOT NULL,
		issuer     text NOT NULL,
		expires_at timestamptz NOT NULL
	)`,
	// The single-use record, and it is a separate table for a reason worth
	// reading. `storage_exec` answers an error or nothing — no row count, no
	// RETURNING, and `storage_query` runs READ ONLY so it cannot write — so there
	// is no way to express *read this row and consume it* as one statement. A
	// SELECT followed by a DELETE is two calls with a window between them, and the
	// window is exactly where a replayed callback would fit.
	//
	// An INSERT of the handle into a table whose primary key is that handle *is*
	// atomic: the first caller writes the row, the second gets a unique violation,
	// and Postgres decided which was which. That is what claimFlow does, and it is
	// the whole of why this table exists.
	`CREATE TABLE IF NOT EXISTS spent (
		handle   text PRIMARY KEY,
		spent_at timestamptz NOT NULL DEFAULT now()
	)`,
	// The provider's documents, so that a callback spends one fetch on the token
	// exchange rather than three on discovery, the key set and the exchange. The
	// route deadline is ten seconds by default and lower on some instances, and
	// the ABI says to budget as though it were shorter than the default.
	`CREATE TABLE IF NOT EXISTS documents (
		name       text PRIMARY KEY,
		body       text NOT NULL,
		expires_at timestamptz NOT NULL
	)`,
}

// The statements this add-on issues, named so that store_sql_test.go can put
// each one through a real Postgres. The fake host in the unit tests interprets
// them; only a real server can say whether they are valid SQL, and the two
// claims are made separately because they are different claims.
const (
	// sqlProbe is the cheap question "are the tables there?". One round trip in
	// the steady state, against three if the DDL were run unconditionally.
	sqlProbe = `SELECT 1 FROM flows LIMIT 1`

	sqlInsertFlow = `INSERT INTO flows (handle, mode, state, nonce, verifier, issuer, expires_at)
		 VALUES ($1, $2, $3, $4, $5, $6, now() + ($7 || ' seconds')::interval)`

	// sqlClaimFlow is the whole of this add-on's single-use guarantee.
	sqlClaimFlow = `INSERT INTO spent (handle) VALUES ($1)`

	sqlSelectFlow = `SELECT mode, state, nonce, verifier, issuer
		   FROM flows
		  WHERE handle = $1 AND expires_at > now()`

	sqlDeleteFlow = `DELETE FROM flows WHERE handle = $1`

	sqlSweepFlows = `DELETE FROM flows WHERE expires_at < now()`

	sqlSweepSpent = `DELETE FROM spent WHERE spent_at < now() - interval '1 hour'`

	sqlSelectDocument = `SELECT body FROM documents WHERE name = $1 AND expires_at > now()`

	sqlUpsertDocument = `INSERT INTO documents (name, body, expires_at)
		 VALUES ($1, $2, now() + ($3 || ' seconds')::interval)
		 ON CONFLICT (name) DO UPDATE
		    SET body = excluded.body, expires_at = excluded.expires_at`

	sqlDeleteDocument = `DELETE FROM documents WHERE name = $1`
)

// ensure creates the tables if the probe said they are not there.
//
// checked is a field of an instance whose memory is new for every request, so
// this is once per request and not once per process. That is the honest cost of
// having no load-time hook a route-serving add-on can tell apart from a request:
// `http_request_read` answers ErrNotFound during package initialization whether
// the instance is the host's load-time one or a request's, so an add-on cannot
// do start-up work exactly once.
func (s *Store) ensure() error {
	if s.checked {
		return nil
	}
	s.checked = true
	// The probe. One statement in the steady state; three more only on the first
	// request after an install.
	if _, err := s.h.StorageQuery(sqlProbe, nil); err == nil {
		return nil
	}
	for _, stmt := range schema {
		if err := s.h.StorageExec(stmt, nil); err != nil {
			return fmt.Errorf("creating this add-on's tables: %w", err)
		}
	}
	return nil
}

// args marshals positional arguments the way the ABI carries them: a JSON array
// of strings, numbers, booleans and nulls. Everything this add-on passes is a
// string and every statement casts what it needs — an object or an array inside
// the array is ErrInvalid, and a number's Postgres type is not something a JSON
// document decides, so a cast in the statement is the shape that has one answer.
func args(values ...string) []byte {
	raw, err := json.Marshal(values)
	if err != nil {
		// Unreachable: a []string always marshals. Returning nil rather than
		// panicking, because a trap in a guest is a 502 for somebody's request.
		return nil
	}
	return raw
}

func (s *Store) exec(sql string, a []byte) error {
	if err := s.ensure(); err != nil {
		return err
	}
	return s.h.StorageExec(sql, a)
}

func (s *Store) query(sql string, a []byte) ([]byte, error) {
	if err := s.ensure(); err != nil {
		return nil, err
	}
	return s.h.StorageQuery(sql, a)
}

// Flow is what has to survive the visitor's trip to the provider.
type Flow struct {
	Handle   string
	Mode     string
	State    string
	Nonce    string
	Verifier string
	Issuer   string
}

// The two things a flow can be. The mode is stored rather than inferred from
// whether somebody is signed in at the callback, because those are two different
// moments: a session that expired mid-flow would silently turn a link into a
// sign-in, and one that began mid-flow would turn a sign-in into a link.
const (
	// ModeSignIn asserts the identity to the host and asks for a session.
	ModeSignIn = "signin"
	// ModeLink connects the identity to whoever is already signed in.
	ModeLink = "link"
)

// SaveFlow writes a flow and gives it a lifetime.
func (s *Store) SaveFlow(f Flow, ttlSeconds int) error {
	return s.exec(sqlInsertFlow,
		args(f.Handle, f.Mode, f.State, f.Nonce, f.Verifier, f.Issuer, itoa(ttlSeconds)))
}

// ErrFlowGone is a callback whose flow is not there: never started on this
// instance, already spent, or expired. One error for all three deliberately —
// telling a caller which would tell them whether a handle they guessed exists.
var ErrFlowGone = errors.New("this sign-in did not start here, or it has already been used")

// ClaimFlow consumes a flow exactly once and hands back what it held.
//
// The claim is the INSERT and not the SELECT. Postgres decides which of two
// concurrent callbacks owns the handle, because only one of them can write the
// primary key; the loser is refused before it has read a verifier. A SELECT-then-
// DELETE would leave both of them holding the same PKCE verifier for as long as
// the two statements are apart.
//
// A unique violation reaches this module as [sdk.ErrInvalid] with no detail: the
// ABI never lets a Postgres message cross, because one names tables and
// constraints. So *any* failure of this INSERT is read as "somebody else has it",
// which is the safe direction — the cost of being wrong is a sign-in the visitor
// retries, and the cost of guessing the other way is a replayable callback.
func (s *Store) ClaimFlow(handle string) (Flow, error) {
	if err := s.exec(sqlClaimFlow, args(handle)); err != nil {
		return Flow{}, ErrFlowGone
	}
	raw, err := s.query(sqlSelectFlow, args(handle))
	if err != nil {
		return Flow{}, fmt.Errorf("reading the flow: %w", err)
	}
	var rows []struct {
		Mode     string `json:"mode"`
		State    string `json:"state"`
		Nonce    string `json:"nonce"`
		Verifier string `json:"verifier"`
		Issuer   string `json:"issuer"`
	}
	if err := json.Unmarshal(raw, &rows); err != nil {
		return Flow{}, fmt.Errorf("reading the flow: %w", err)
	}
	if len(rows) != 1 {
		return Flow{}, ErrFlowGone
	}
	// Best effort, and it is only tidying: the row is already unusable, because
	// its handle is in `spent`. A failure here is not the visitor's problem.
	_ = s.exec(sqlDeleteFlow, args(handle))
	r := rows[0]
	return Flow{
		Handle: handle, Mode: r.Mode, State: r.State,
		Nonce: r.Nonce, Verifier: r.Verifier, Issuer: r.Issuer,
	}, nil
}

// Sweep drops what has expired. Called from the route that starts a flow, which
// is the only one that has time to spare and the one whose rate is the rate rows
// are created at. Nothing caps how much an add-on stores and an operator watches
// linkctrl_addon_schema_bytes, so growing without bound is this add-on's to
// defend and it does not.
func (s *Store) Sweep() error {
	if err := s.exec(sqlSweepFlows, nil); err != nil {
		return err
	}
	// Kept an hour past any flow's own life, so that a replay arriving after the
	// flow row is gone still meets a spent handle rather than a missing one. Both
	// answer ErrFlowGone; the difference is only which statement says so.
	return s.exec(sqlSweepSpent, nil)
}

// Document reads a cached provider document, or "" when there is none that is
// still fresh.
func (s *Store) Document(name string) (string, error) {
	raw, err := s.query(sqlSelectDocument, args(name))
	if err != nil {
		return "", err
	}
	var rows []struct {
		Body string `json:"body"`
	}
	if err := json.Unmarshal(raw, &rows); err != nil {
		return "", err
	}
	if len(rows) != 1 {
		return "", nil
	}
	return rows[0].Body, nil
}

// SaveDocument caches one, replacing whatever was there.
func (s *Store) SaveDocument(name, body string, ttlSeconds int) error {
	return s.exec(sqlUpsertDocument, args(name, body, itoa(ttlSeconds)))
}

// ForgetDocument drops one, which is what a key set that did not carry the `kid`
// an ID token named needs before it is fetched again.
func (s *Store) ForgetDocument(name string) error {
	return s.exec(sqlDeleteDocument, args(name))
}

// storageDenied reports whether an error is the host refusing the grant rather
// than the statement being wrong. The two are distinguishable on purpose — the
// ABI says so — and this add-on tells an operator which they have.
func storageDenied(err error) bool { return errors.Is(err, sdk.ErrDenied) }
