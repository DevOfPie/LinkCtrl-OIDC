package main

import (
	"os"
	"strings"
	"testing"
)

// The export's name is a literal, and it has to be.
//
// A //go:wasmexport directive cannot take a constant, so the string in main.go is
// the only place the name `linkctrl_http_handle` is written — and the host looks
// it up by that exact spelling. A typo produces an add-on that loads, holds
// `routes.own_prefix`, and answers nothing, which is the quietest possible
// failure. Reading the file is a poor test and it is better than the alternative,
// which is no test at all: the directive is invisible to the type checker and the
// wasip1 build succeeds without it.
func TestTheExportIsSpelledTheWayTheHostLooksItUp(t *testing.T) {
	raw, err := os.ReadFile("main.go")
	if err != nil {
		t.Fatal(err)
	}
	const directive = "//go:wasmexport linkctrl_http_handle"

	// Whole lines, compared for equality. Contains would accept
	// `linkctrl_http_handler`, which is a name the host does not look up and a
	// substring test cannot tell from the one it does.
	found := 0
	exports := 0
	for _, line := range strings.Split(string(raw), "\n") {
		if !strings.HasPrefix(line, "//go:wasmexport") {
			continue
		}
		exports++
		if strings.TrimRight(line, " \t\r") == directive {
			found++
		}
	}
	if found != 1 {
		t.Fatalf("main.go carries %d lines that are exactly %q", found, directive)
	}
	// And exactly the one export. The other two are the redirect classes, whose
	// grants this add-on does not declare — a module that exported one and did not
	// declare the grant would be logged and ignored, and one that declared it
	// could not fetch anyway.
	if exports != 1 {
		t.Fatalf("main.go carries %d exports, want 1", exports)
	}
	src := string(raw)
	for _, never := range []string{"linkctrl_redirect_observe", "linkctrl_redirect_inline"} {
		if strings.Contains(src, never) {
			t.Errorf("main.go mentions %s; this add-on is never on the redirect path", never)
		}
	}
}
