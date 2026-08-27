//go:build !wasip1

package main

import (
	"fmt"
	"os"

	"github.com/DevOfPie/LinkCtrl-OIDC/oidc"
)

// main off wasm says what this program is and refuses to pretend.
//
// It exists so that `go build ./...`, `go vet ./...` and every editor work in
// this repository without a build tag dance — the package would otherwise have
// no files at all outside wasip1 — and it prints the build line rather than
// exiting silently, because somebody who ran it wanted a module.
func main() {
	fmt.Fprintf(os.Stderr,
		"LinkCtrl-OIDC %s is a LinkCtrl add-on and runs inside a LinkCtrl host.\n"+
			"Build it with:\n\n"+
			"    GOOS=wasip1 GOARCH=wasm go build -buildmode=c-shared -o oidc.wasm .\n\n"+
			"or with `make build`, which also writes addon.json with the module's digest.\n",
		oidc.Version)
	os.Exit(2)
}
