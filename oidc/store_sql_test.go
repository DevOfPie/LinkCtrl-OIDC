package oidc

import (
	"os"
	"os/exec"
	"strconv"
	"strings"
	"testing"
)

// This file puts every statement this add-on issues through a real Postgres.
//
// # Why it is separate from store_test.go
//
// Those tests assert *behaviour* — a flow is claimed once, a spent handle
// outlives the row it refuses — against a fake host that interprets the
// statements. That fake cannot say whether `now() + ($7 || ' seconds')::interval`
// is valid SQL, whether a column exists, or whether the unique violation the
// single-use claim rests on is a violation Postgres actually raises. Only a
// server can, and those are different claims, so they are made separately.
//
// # Why psql and not a driver
//
// This repository depends on the LinkCtrl SDK and the Go standard library, and
// the SDK's own claim is that an add-on needs nothing else. A Postgres driver in
// go.mod would be a test dependency in the file an operator reads to check that
// sentence. `psql` is already on the machine that runs Postgres.
//
// Set OIDC_TEST_PSQL_DSN to run it. CI does; a developer without a server gets a
// skip and the unit tests.

func psqlDSN(t *testing.T) string {
	t.Helper()
	dsn := os.Getenv("OIDC_TEST_PSQL_DSN")
	if dsn == "" {
		t.Skip("OIDC_TEST_PSQL_DSN is not set; the SQL is checked against a real " +
			"Postgres in CI and skipped here")
	}
	if _, err := exec.LookPath("psql"); err != nil {
		t.Skip("psql is not on PATH")
	}
	return dsn
}

// psql runs one script and answers stdout, failing the test on any error —
// ON_ERROR_STOP is what turns a statement Postgres refused into a failure rather
// than into a notice nobody reads.
func psql(t *testing.T, dsn, script string) string {
	t.Helper()
	cmd := exec.Command("psql", dsn, "-v", "ON_ERROR_STOP=1",
		"--no-psqlrc", "--quiet", "--tuples-only", "--no-align", "-f", "-")
	cmd.Stdin = strings.NewReader(script)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("psql failed: %v\n--- script ---\n%s\n--- output ---\n%s",
			err, script, out)
	}
	return string(out)
}

// psqlExpectingFailure is the other half: a statement Postgres must refuse.
func psqlExpectingFailure(t *testing.T, dsn, script string) string {
	t.Helper()
	cmd := exec.Command("psql", dsn, "-v", "ON_ERROR_STOP=1",
		"--no-psqlrc", "--quiet", "--tuples-only", "--no-align", "-f", "-")
	cmd.Stdin = strings.NewReader(script)
	out, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatalf("psql accepted a script that should have been refused:\n%s\n%s",
			script, out)
	}
	return string(out)
}

// scratch is a schema of this test's own, dropped and made fresh, standing in
// for the schema the host gives an add-on. `search_path` is set to it alone,
// which is what the host pins per statement — so an unqualified name resolving
// here is the same fact as one resolving on an instance.
func scratch(t *testing.T, dsn string) string {
	t.Helper()
	name := "addon_oidc_test"
	psql(t, dsn, "DROP SCHEMA IF EXISTS "+name+" CASCADE; CREATE SCHEMA "+name+";")
	t.Cleanup(func() {
		psql(t, dsn, "DROP SCHEMA IF EXISTS "+name+" CASCADE;")
	})
	return "SET search_path TO " + name + ";\n"
}

// ddl is the add-on's own schema, as the module would create it.
func ddl(prelude string) string {
	return prelude + strings.Join(schema, ";\n") + ";\n"
}

func TestTheDDLIsValidPostgres(t *testing.T) {
	dsn := psqlDSN(t)
	prelude := scratch(t, dsn)
	psql(t, dsn, ddl(prelude))

	// Idempotent, because it runs on the first request after every install and
	// there is no load-time hook a route-serving add-on can tell apart from one.
	psql(t, dsn, ddl(prelude))

	out := psql(t, dsn, prelude+
		`SELECT string_agg(tablename, ',' ORDER BY tablename) FROM pg_tables `+
		`WHERE schemaname = 'addon_oidc_test';`)
	if got := strings.TrimSpace(out); got != "documents,flows,spent" {
		t.Fatalf("the schema holds %q", got)
	}
}

// preparable is every statement, with the parameter types Postgres should see.
// PREPARE parses and plans, so it catches a syntax error, a column that is not
// there and a cast that does not exist — before any row is written.
var preparable = []struct {
	name   string
	sql    string
	params int
}{
	{"probe", sqlProbe, 0},
	{"insert flow", sqlInsertFlow, 7},
	{"claim flow", sqlClaimFlow, 1},
	{"select flow", sqlSelectFlow, 1},
	{"delete flow", sqlDeleteFlow, 1},
	{"sweep flows", sqlSweepFlows, 0},
	{"sweep spent", sqlSweepSpent, 0},
	{"select document", sqlSelectDocument, 1},
	{"upsert document", sqlUpsertDocument, 3},
	{"delete document", sqlDeleteDocument, 1},
}

func TestEveryStatementParsesAndPlans(t *testing.T) {
	dsn := psqlDSN(t)
	prelude := scratch(t, dsn)

	var script strings.Builder
	script.WriteString(ddl(prelude))
	for i, p := range preparable {
		script.WriteString("PREPARE p" + strconv.Itoa(i))
		if p.params > 0 {
			// Every argument this add-on passes is a string, because the ABI carries
			// arguments as a JSON array and a number's Postgres type is not something
			// a JSON document decides. The casts are in the statements.
			script.WriteString("(" + strings.TrimSuffix(
				strings.Repeat("text,", p.params), ",") + ")")
		}
		script.WriteString(" AS " + p.sql + ";\n")
	}
	psql(t, dsn, script.String())
}

func TestAReplayedClaimIsAUniqueViolation(t *testing.T) {
	// The whole of this add-on's single-use guarantee, against the server that
	// provides it. `storage_exec` answers no row count and `storage_query` runs
	// READ ONLY, so an INSERT whose primary key collides is the only atomic way to
	// express *consume this exactly once*.
	dsn := psqlDSN(t)
	prelude := scratch(t, dsn)
	psql(t, dsn, ddl(prelude))

	claim := "PREPARE c(text) AS " + sqlClaimFlow + ";\n"
	psql(t, dsn, prelude+claim+"EXECUTE c('handle-1');")
	out := psqlExpectingFailure(t, dsn, prelude+claim+"EXECUTE c('handle-1');")
	if !strings.Contains(out, "duplicate key") && !strings.Contains(out, "unique") {
		t.Fatalf("the second claim failed for some other reason:\n%s", out)
	}
}

func TestTheFlowRoundTripsThroughARealServer(t *testing.T) {
	dsn := psqlDSN(t)
	prelude := scratch(t, dsn)
	psql(t, dsn, ddl(prelude))

	// Two flows: one live, one whose interval was negative, which is what an
	// expired row is. Nothing sweeps between them — the `expires_at > now()` in
	// the select is what makes the second invisible, and a sweep that had run
	// would hide which of the two did the work.
	script := prelude +
		"PREPARE ins(text,text,text,text,text,text,text) AS " + sqlInsertFlow + ";\n" +
		"PREPARE sel(text) AS " + sqlSelectFlow + ";\n" +
		"EXECUTE ins('h1','signin','st','no','ver','https://idp.example.com','600');\n" +
		"EXECUTE ins('h2','link','st2','no2','ver2','https://idp.example.com','-1');\n" +
		"SELECT 'live:' || mode || ':' || verifier FROM flows WHERE handle='h1';\n" +
		"EXECUTE sel('h1');\n" +
		"EXECUTE sel('h2');\n"

	out := psql(t, dsn, script)
	if !strings.Contains(out, "live:signin:ver") {
		t.Fatalf("the row did not come back:\n%s", out)
	}
	if !strings.Contains(out, "signin|st|no|ver|https://idp.example.com") {
		t.Fatalf("the select did not answer the flow's own columns:\n%s", out)
	}
	if strings.Contains(out, "link|st2") {
		t.Fatalf("an expired flow was selected:\n%s", out)
	}

	psql(t, dsn, prelude+"PREPARE d(text) AS "+sqlDeleteFlow+";\nEXECUTE d('h1');")
	out = psql(t, dsn, prelude+"SELECT count(*) FROM flows WHERE handle='h1';")
	if strings.TrimSpace(out) != "0" {
		t.Fatalf("the flow was not deleted: %q", out)
	}
}

func TestTheDocumentCacheUpsertsAndExpires(t *testing.T) {
	dsn := psqlDSN(t)
	prelude := scratch(t, dsn)
	psql(t, dsn, ddl(prelude))

	script := prelude +
		"PREPARE up(text,text,text) AS " + sqlUpsertDocument + ";\n" +
		"PREPARE get(text) AS " + sqlSelectDocument + ";\n" +
		"EXECUTE up('discovery','{\"issuer\":\"one\"}','900');\n" +
		"EXECUTE up('discovery','{\"issuer\":\"two\"}','900');\n" +
		"SELECT 'rows:' || count(*) FROM documents;\n" +
		"EXECUTE get('discovery');\n" +
		"EXECUTE up('stale','x','-1');\n" +
		"EXECUTE get('stale');\n"
	out := psql(t, dsn, script)
	if !strings.Contains(out, "rows:1") {
		t.Fatalf("the upsert duplicated rather than replaced:\n%s", out)
	}
	if !strings.Contains(out, `"issuer":"two"`) {
		t.Fatalf("the second write did not replace the first:\n%s", out)
	}
	if strings.Contains(out, "\nx\n") {
		t.Fatalf("an expired document was served:\n%s", out)
	}
}

func TestAQueryCannotWriteAndAStatementIsOne(t *testing.T) {
	// Two bounds the host enforces and this add-on must stay inside: a
	// `storage_query` runs READ ONLY, and one statement per call.
	dsn := psqlDSN(t)
	prelude := scratch(t, dsn)
	psql(t, dsn, ddl(prelude))

	out := psqlExpectingFailure(t, dsn, prelude+
		"BEGIN READ ONLY;\n"+sqlSweepFlows+";\n")
	if !strings.Contains(strings.ToLower(out), "read-only") {
		t.Fatalf("a write inside a READ ONLY transaction failed for another reason:\n%s", out)
	}

	for _, p := range preparable {
		if strings.Contains(p.sql, ";") {
			t.Errorf("%s carries a semicolon; the host parses through the extended "+
				"protocol and a payload with two commands is refused", p.name)
		}
	}
}
