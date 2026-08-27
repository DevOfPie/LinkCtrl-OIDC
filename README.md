# LinkCtrl-OIDC

An OpenID Connect relying party for [LinkCtrl](https://github.com/DevOfPie/LinkCtrl),
as a wasm add-on. Somebody signs into LinkCtrl with your identity provider;
LinkCtrl decides whether they have an account and writes the cookie.

It is also the worked example the add-on ABI was built toward. It consumes the
published SDK and nothing else — `go.sum` is two lines, and CI fails if a third
package reaches the build graph — so every constraint in
[docs/addon-abi.md](https://github.com/DevOfPie/LinkCtrl/blob/main/docs/addon-abi.md)
is met here the way a publisher outside that repository would have to meet it.

## What it does

| Route | Is |
| --- | --- |
| `/addons/oidc/` | Status. What is configured, what the provider answered, which origins have to be authorized. Shows nothing to a visitor who is not signed in |
| `/addons/oidc/start` | Begins a sign-in. Redirects to the provider with PKCE, `state` and `nonce` |
| `/addons/oidc/link` | Begins a linking flow for whoever is signed in |
| `/addons/oidc/callback` | The provider's redirect. Exchanges the code, verifies the ID token, and asserts to the host |

**Linking comes first.** LinkCtrl matches an external identity to an account
through a table it owns, and an assertion about a subject nobody has linked mints
nothing. Matching on an email address is refused by design — it is the classic
account-takeover shape — so the first thing a person does is sign in with a
password and visit `/addons/oidc/link`.

## What it needs from you before it works

An add-on that talks outward **does not work when it is installed; it works when
it is configured.** Five settings, on this add-on's page in LinkCtrl's Add-on
manager:

| Setting | Is |
| --- | --- |
| `issuer` | The provider's issuer URL, `https`, no trailing slash. Compared byte for byte against the ID token's `iss`, and the base the discovery document is fetched from |
| `client_id` | The client identifier the provider issued |
| `client_secret` | The client secret. Sent as a form field — see [what the ABI decides](#what-the-abi-decides-and-what-it-refuses) |
| `redirect_uri` | The absolute `https` URL of `/addons/oidc/callback` **on this instance**, which is also what you register with the provider |
| `provider_origins` | Every origin the provider serves discovery, the token endpoint and the key set from, separated by spaces |

`provider_origins` is the one that catches people out, and it is the design
rather than a rough edge. **This add-on's manifest declares that it talks to
something and cannot name what**; the operator names it, and the host dials
nothing else. A provider that spreads its documents across hostnames needs all of
them written down — Google, for instance, is two:

```
https://accounts.google.com https://www.googleapis.com
```

Until the field is filled in, every outbound call answers `unconfigured` and
nothing leaves the machine. The status page says so, and names the origin that
was refused when one is.

Six more settings have defaults and are optional: `scopes`
(`openid profile email`), `after_sign_in` and `after_link` (`/dashboard`),
`require_verified_email` (`false`), `clock_skew_seconds` (`60`) and
`discovery_ttl_seconds` (`900`).

## Installing

Download the release bundle and its digest, and give both to the Add-on manager,
or `POST /api/v1/addons`. **Read the digest from the release page's
`SHA256SUMS`, not from wherever you found the link** — the host refuses to write
anything unless the bundle hashes to what you typed, which is the whole of what
makes a URL install safe, and a digest read off the same page as the address
proves nothing about either.

The manifest inside the bundle names the module's own digest, which the host
checks separately before it instantiates anything.

**This add-on is `required`-class**, and the host would force that anyway: an
add-on holding `session.mint` decides who is signed in, so an instance that
booted without it is an instance whose external sign-in silently does not exist.
An operator who wants the other behaviour sets
`LINKCTRL_ADDON_OIDC_FAILURE_CLASS=degrade`, and the documented consequence is
that external sign-in disappears while local sign-in continues.

## What it may do, and nothing else

```
routes.own_prefix     serve /addons/oidc/
session.context       ask who is signed in
session.mint          assert an identity, and link one — two functions, one grant
storage.own_schema    a flow's state, and the provider's documents
config.read           the settings above
network.fetch         discovery, the key set and the token exchange
```

Six grants, and a test in this repository fails if the manifest declares one
nothing calls or omits one something does. Neither redirect class is declared:
this add-on is never on the path a visitor's redirect takes.

What it never gets, because the boundary does not carry them: a visitor's
address, a cookie of LinkCtrl's, a session token, or anything about another
add-on's schema.

## What the ABI decides, and what it refuses

Four of this add-on's shapes are the host's decisions rather than its author's,
and each is worth knowing before you choose a provider.

**`response_mode=form_post` cannot be used.** LinkCtrl's application tree answers
403 to every cross-site request that uses an unsafe method, before an add-on is
entered, so a POST callback from the provider's origin never arrives. There is no
exemption — not a trusted origin, not a declared callback path. A provider that
offers only `form_post` cannot be used with LinkCtrl at all. This add-on asks for
`query` explicitly and refuses a provider whose metadata says it does not offer
it.

**The token exchange is `client_secret_post`.** The ABI's fetch record carries no
headers and the host sets exactly three, so there is no way to send an
`Authorization` header. A provider that requires `client_secret_basic` cannot be
used either.

**`redirect_uri` is typed and not derived.** The request record has no `Host`
header, no scheme and a path relative to this add-on's own prefix, so a module
cannot construct its own absolute URL. Your instance knows its base URL and this
add-on cannot ask it.

**There is no "Sign in with…" button anywhere.** `content_type` is a closed
vocabulary without `text/html`, the host wraps and escapes an add-on's body, and
`template_render` answers `ErrNotAvailable` on every host released so far. So the
only page this add-on can draw is text, and a sign-in begins by visiting
`/addons/oidc/start` — a link you put somewhere yourself, or a bookmark.

## Security

- **PKCE with `S256`**, and no fallback to `plain`. A provider that advertises
  its supported methods and does not include `S256` is refused.
- **`state` and `nonce` are drawn separately** from the host's entropy and kept
  in this add-on's schema, not in the browser. The cookie carries a random handle
  and nothing else, so a visitor cannot choose either value.
- **A flow is consumed exactly once**, by a primary-key collision rather than by
  a read followed by a delete. A replayed callback is refused before the token
  endpoint is reached.
- **The ID token's signature is checked before any claim is read.** `none` and
  the HMAC family are refused as families; a token whose `kid` the cached key set
  does not carry buys exactly one refetch and no more.
- **`iss` is compared exactly**, `aud` must name this client, `azp` is required
  when there is more than one audience, `exp` and `iat` are checked against the
  host's clock with the operator's skew, and `nonce` is compared in constant time
  against the value this flow began with.
- **`after_sign_in` and `after_link` are paths on this instance.** The host lets
  an add-on redirect off-origin — it has to, to reach a provider — so the return
  leg is bounded here instead.
- **The client secret never reaches a page or a log**, which a test asserts by
  searching everything this add-on writes.

## Building it

```console
$ make check          # gofmt, vet on both targets, tests, and the wasm build
$ make build          # oidc.wasm, and addon.json with its digest
$ make bundle         # dist/linkctrl-oidc-<version>.tar.gz and SHA256SUMS
```

The build is reproducible: `-trimpath`, and a tar with fixed ordering, ownership
and mtime. CI builds twice and fails if the two digests differ.

`OIDC_TEST_PSQL_DSN` runs the SQL tests, which put every statement this add-on
issues through a real Postgres. Without it they skip and say so.

`./scripts/sabotage.sh` breaks each claim the suite makes in turn and asserts the
named test goes red, then restores the code by a counter-edit and asserts the
file is byte-identical. CI runs it. A test that has never failed is a test nobody
has evidence about.

## Layout

```
main.go            the wasip1 export and eleven lines of forwarding to the SDK
main_other.go      what running it off wasm says
oidc/abi.go        the ABI's records, written out, and the Host interface
oidc/config.go     the settings, and what a configuration must be
oidc/fetch.go      one outbound request, and what an outcome means to an operator
oidc/provider.go   discovery and the key set, cached in this add-on's schema
oidc/jose.go       a JWS verifier and a JWK reader, standard library only
oidc/idtoken.go    every claim OpenID Connect requires of an ID token
oidc/store.go      the flow's state, and the statements it is kept with
oidc/flow.go       the two legs: begin, and exchange
oidc/handler.go    the routes, and the pages a failure produces
```

The logic is in a package that reaches the host through an interface, so it is
tested against a fake host and a fake identity provider that signs real tokens
with real keys. The wasm half is forwarding, which is the part that cannot be
tested — every SDK function compiles for any GOOS and answers "the host is not
there" off wasip1.

## Licence

MIT. See [LICENSE](LICENSE).
