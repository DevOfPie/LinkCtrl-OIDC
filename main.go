//go:build wasip1

// Command oidc is LinkCtrl's OpenID Connect relying party, as a wasm add-on.
//
// # What it is
//
// An add-on that signs somebody into LinkCtrl with an external identity
// provider: discovery, the authorization-code flow with PKCE, a callback on this
// add-on's own route, an ID token verified against the provider's key set, and
// an assertion handed to the host — which decides whether an account exists for
// the subject and writes the cookie itself. This module never sees a session, a
// token of the host's, or a cookie of anybody's but its own.
//
// # Why this file is nine functions of forwarding
//
// Everything above lives in the [oidc] package, which reaches the host through
// an interface. This file is the wasip1 half: the exports the host calls, and a
// [oidc.Host] implemented over the generated SDK. It is deliberately empty of
// judgement, because it is the one part of this add-on that cannot be tested —
// every SDK function compiles for any GOOS and answers "the host is not there"
// off wasip1, so a test of this file would be a test of that sentence.
//
// # Building it
//
//	GOOS=wasip1 GOARCH=wasm go build -buildmode=c-shared -o oidc.wasm .
//
// which is a *reactor*: package initialization runs when the host instantiates
// the module and it then stays alive to be called into, rather than running main
// and exiting. `make build` does that and writes addon.json with the module's
// digest in it.
package main

import (
	"github.com/DevOfPie/LinkCtrl-OIDC/oidc"
	"github.com/DevOfPie/LinkCtrl/sdk"
)

// host is [oidc.Host] over the SDK. Every method is one call and nothing else:
// the retry on a short buffer, the status decoding and the memory are the SDK's.
type host struct{}

func (host) Log(level, message string) error         { return sdk.Log(level, message) }
func (host) ConfigGet(key string) (string, error)    { return sdk.ConfigGet(key) }
func (host) RandomBytes(count int32) ([]byte, error) { return sdk.RandomBytes(count) }
func (host) TimeNow() (string, error)                { return sdk.TimeNow() }
func (host) HTTPRequestRead() ([]byte, error)        { return sdk.HTTPRequestRead() }
func (host) HTTPResponseWrite(r []byte) error        { return sdk.HTTPResponseWrite(r) }
func (host) SessionContextRead() ([]byte, error)     { return sdk.SessionContextRead() }
func (host) SessionMint(c []byte) ([]byte, error)    { return sdk.SessionMint(c) }
func (host) IdentityLink(c []byte) error             { return sdk.IdentityLink(c) }
func (host) NetworkFetch(r []byte) ([]byte, error)   { return sdk.NetworkFetch(r) }

func (host) StorageQuery(sql string, args []byte) ([]byte, error) {
	return sdk.StorageQuery(sql, args)
}
func (host) StorageExec(sql string, args []byte) error { return sdk.StorageExec(sql, args) }

// handle is the export the host calls per request to one of this add-on's
// routes. The name is the literal `linkctrl_http_handle` because a
// //go:wasmexport directive cannot take a constant.
//
//go:wasmexport linkctrl_http_handle
func handle() int32 { return oidc.Handle(host{}) }

// main is required by the toolchain even for a reactor: with -buildmode=c-shared
// the entry point is _initialize, which runs package initialization and returns.
//
// **There is deliberately nothing in it, and nothing in an init either.** A
// route-serving module is instantiated once per request and its initialization
// runs before the request is attached, so work done here is work done on every
// request, ahead of LINKCTRL_ADDON_ROUTE_DEADLINE and before this add-on knows
// whether the request needs it. What has to happen once — creating the tables —
// happens at the first statement that needs them.
func main() {}
