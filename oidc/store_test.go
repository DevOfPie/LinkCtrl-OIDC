package oidc

import (
	"errors"
	"testing"
	"time"

	"github.com/DevOfPie/LinkCtrl/sdk"
)

func newStoreSuite(t *testing.T) (*fakeHost, *Store) {
	t.Helper()
	h := newFakeHost(t)
	h.idp = newFakeIDP()
	return h, NewStore(h)
}

func aFlow() Flow {
	return Flow{
		Handle: "handle-1", Mode: ModeSignIn, State: "state-1",
		Nonce: "nonce-1", Verifier: "verifier-1", Issuer: "https://idp.example.com",
	}
}

func TestTheTablesAreMadeOnceAndThenProbedOnce(t *testing.T) {
	h, s := newStoreSuite(t)
	if err := s.SaveFlow(aFlow(), FlowTTL); err != nil {
		t.Fatal(err)
	}
	if got := h.storage.counted("CREATE TABLE"); got != len(schema) {
		t.Fatalf("%d tables were created, want %d", got, len(schema))
	}
	if got := h.storage.counted("SELECT 1 FROM flows"); got != 1 {
		t.Fatalf("the probe ran %d times in one invocation", got)
	}

	// A second statement in the same invocation pays nothing more, because
	// `checked` is a field of an instance and an instance is one request.
	before := len(h.storage.statements)
	if _, err := s.ClaimFlow("handle-1"); err != nil {
		t.Fatal(err)
	}
	for _, stmt := range h.storage.statements[before:] {
		mustNotHavePrefix(t, stmt, "CREATE TABLE")
		mustNotHavePrefix(t, stmt, "SELECT 1 FROM flows")
	}

	// And a new instance — the next request — probes once and creates nothing.
	next := NewStore(h)
	if err := next.SaveFlow(Flow{Handle: "handle-2"}, FlowTTL); err != nil {
		t.Fatal(err)
	}
	if got := h.storage.counted("CREATE TABLE"); got != len(schema) {
		t.Fatalf("the tables were created again: %d statements", got)
	}
	if got := h.storage.counted("SELECT 1 FROM flows"); got != 2 {
		t.Fatalf("the probe ran %d times across two requests", got)
	}
}

func TestAFlowIsClaimedExactlyOnce(t *testing.T) {
	h, s := newStoreSuite(t)
	if err := s.SaveFlow(aFlow(), FlowTTL); err != nil {
		t.Fatal(err)
	}

	got, err := s.ClaimFlow("handle-1")
	if err != nil {
		t.Fatal(err)
	}
	if got.Verifier != "verifier-1" || got.Nonce != "nonce-1" || got.Mode != ModeSignIn {
		t.Fatalf("claimed %+v", got)
	}

	// The claim is the INSERT into `spent` and not the SELECT, so a second caller
	// is refused before it has read a verifier. `storage_exec` answers no row
	// count and `storage_query` cannot write, so this is the only atomic shape
	// available.
	_, err = s.ClaimFlow("handle-1")
	if !errors.Is(err, ErrFlowGone) {
		t.Fatalf("the second claim answered %v, want ErrFlowGone", err)
	}
	// Even with the row put back, the handle stays spent.
	if err := s.SaveFlow(aFlow(), FlowTTL); err != nil {
		t.Fatal(err)
	}
	if _, err := s.ClaimFlow("handle-1"); !errors.Is(err, ErrFlowGone) {
		t.Fatalf("a spent handle was claimed again: %v", err)
	}
	_ = h
}

func TestAnExpiredFlowIsGone(t *testing.T) {
	h, s := newStoreSuite(t)
	if err := s.SaveFlow(aFlow(), 60); err != nil {
		t.Fatal(err)
	}
	h.now = h.now.Add(61 * time.Second)
	if _, err := s.ClaimFlow("handle-1"); !errors.Is(err, ErrFlowGone) {
		t.Fatalf("an expired flow was claimed: %v", err)
	}
}

func TestAHandleNobodyStartedIsTheSameAnswerAsASpentOne(t *testing.T) {
	// One error for never-started, already-used and expired, deliberately:
	// telling a caller which would tell them whether a handle they guessed exists.
	_, s := newStoreSuite(t)
	if _, err := s.ClaimFlow("invented"); !errors.Is(err, ErrFlowGone) {
		t.Fatalf("answered %v", err)
	}
}

func TestSweepRemovesWhatIsPast(t *testing.T) {
	h, s := newStoreSuite(t)
	if err := s.SaveFlow(aFlow(), 60); err != nil {
		t.Fatal(err)
	}
	if err := s.SaveFlow(Flow{Handle: "long"}, 3600); err != nil {
		t.Fatal(err)
	}
	if _, err := s.ClaimFlow("handle-1"); err != nil {
		t.Fatal(err)
	}

	h.now = h.now.Add(2 * time.Hour)
	if err := s.Sweep(); err != nil {
		t.Fatal(err)
	}
	if len(h.storage.flows) != 0 {
		t.Errorf("flows left after the sweep: %v", h.storage.flows)
	}
	if len(h.storage.spent) != 0 {
		t.Errorf("spent handles left after the sweep: %v", h.storage.spent)
	}
}

func TestSpentHandlesOutliveTheFlowsTheyRefuse(t *testing.T) {
	// A replay arriving after the flow row is gone still has to meet a spent
	// handle rather than a missing one, which is what the extra hour buys.
	h, s := newStoreSuite(t)
	if err := s.SaveFlow(aFlow(), 60); err != nil {
		t.Fatal(err)
	}
	if _, err := s.ClaimFlow("handle-1"); err != nil {
		t.Fatal(err)
	}
	h.now = h.now.Add(30 * time.Minute)
	if err := s.Sweep(); err != nil {
		t.Fatal(err)
	}
	if len(h.storage.spent) != 1 {
		t.Fatal("the spent handle was swept while a replay could still arrive")
	}
}

func TestADocumentRoundTrips(t *testing.T) {
	h, s := newStoreSuite(t)
	if err := s.SaveDocument("discovery", `{"issuer":"x"}`, 900); err != nil {
		t.Fatal(err)
	}
	body, err := s.Document("discovery")
	if err != nil {
		t.Fatal(err)
	}
	if body != `{"issuer":"x"}` {
		t.Fatalf("read back %q", body)
	}
	// Replaced rather than duplicated.
	if err := s.SaveDocument("discovery", `{"issuer":"y"}`, 900); err != nil {
		t.Fatal(err)
	}
	if body, _ := s.Document("discovery"); body != `{"issuer":"y"}` {
		t.Fatalf("read back %q after replacing", body)
	}
	if err := s.ForgetDocument("discovery"); err != nil {
		t.Fatal(err)
	}
	if body, _ := s.Document("discovery"); body != "" {
		t.Fatalf("read back %q after forgetting", body)
	}
	h.now = h.now.Add(time.Hour)
}

func TestARefusedStorageGrantIsDistinguishable(t *testing.T) {
	// ErrDenied from a statement is the boundary and ErrInvalid is the statement,
	// and the ABI says the two are different on purpose. An add-on that could not
	// tell them apart would tell an operator to check their SQL.
	h, s := newStoreSuite(t)
	h.noStorageGrant = true
	err := s.SaveFlow(aFlow(), FlowTTL)
	if !storageDenied(err) {
		t.Fatalf("error is %v, want one wrapping sdk.ErrDenied", err)
	}
	mustErrorIs(t, err, sdk.ErrDenied)
}

func mustNotHavePrefix(t *testing.T, got, prefix string) {
	t.Helper()
	if len(got) >= len(prefix) && got[:len(prefix)] == prefix {
		t.Fatalf("an extra %q statement ran: %q", prefix, got)
	}
}
