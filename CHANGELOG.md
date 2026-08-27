# Changelog

Every notable change to this add-on, in the format of
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/). This add-on's version
is its own and is not LinkCtrl's, and it is not the ABI's either: the manifest's
`abi_version` is the generation this module was built against, and it moves for
different reasons than the number below.

## [Unreleased]

## [0.1.0] — 2026-08-27

The first release: an OpenID Connect relying party as a LinkCtrl add-on.

### Added

- **Sign-in through an external identity provider.** Discovery, the
  authorization-code flow with PKCE (`S256`, and no fallback to `plain`), a
  callback on this add-on's own route, an ID token verified against the
  provider's published key set, and an assertion handed to the host through
  `session_mint`. The host decides whether an account exists for the subject and
  writes the cookie; this add-on never sees a session or a token of LinkCtrl's.
- **Identity linking**, through `identity_link`: somebody already signed in
  connects a provider to their account. It is the precondition for signing in —
  an assertion about a subject nobody has linked mints nothing — and the two
  functions have opposite requirements about a session, which is what stops
  either doing the other's job.
- **An ID token verifier** written against the standard library: `RS256`,
  `RS384`, `RS512`, `PS256`, `PS384`, `PS512` and the `ES` family. `none` and the
  HMAC family are refused as families rather than case by case. Every claim
  OpenID Connect Core 3.1.3.7 requires is checked, in that order, after the
  signature and never before it.
- **A status page** at `/addons/oidc/`, which fetches the provider's discovery
  document and names the origins an operator has to authorize. It is the page
  that says what is not configured yet; a visitor who is not signed in is shown
  nothing about the configuration.
- **Flow state in this add-on's own Postgres schema**, with a random handle in a
  cookie. Consumption is atomic — a primary-key collision on an insert — because
  `storage_exec` answers no row count and `storage_query` cannot write, so there
  is no way to express *read this row and consume it* in one statement.
- **The provider's documents are cached** in the same schema, so the callback
  spends one outbound request on the token exchange rather than three. A token
  naming a key the cached set does not carry buys exactly one refetch.
- **A checksummed release**: the manifest names the module's digest, which the
  host verifies before it writes anything at install, and the bundle carries its
  own digest, published here and in `SHA256SUMS` rather than on the page its URL
  is on. The build is reproducible — `-trimpath`, and a tar with a fixed
  ordering, ownership and mtime — so somebody else can produce the same bytes.

### Notes for an operator

- **The provider must support `response_mode=query`.** A `form_post` callback is
  a cross-site POST navigation, and LinkCtrl's application tree answers 403 to
  every cross-site request that uses an unsafe method, before an add-on is
  entered. There is no exemption to ask for. A provider that offers only
  `form_post` cannot be used with LinkCtrl at all.
- **The token exchange is `client_secret_post`.** LinkCtrl's add-on ABI carries
  no request headers — the host sets `Accept`, `Content-Type` and its own
  `User-Agent`, and nothing else — so there is no way to send an `Authorization`
  header and `client_secret_basic` is unreachable.
- **`redirect_uri` is typed rather than derived.** No ABI record carries the
  instance's own scheme and host, so this add-on cannot construct the URL it must
  send to the provider.
- **There is no "Sign in with…" button.** An add-on may not choose `text/html`
  and `template_render` is not implemented on any released host, so the only
  page this add-on can draw is text the host wraps and escapes. Sign-in starts by
  visiting `/addons/oidc/start`.

[Unreleased]: https://github.com/DevOfPie/LinkCtrl-OIDC/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/DevOfPie/LinkCtrl-OIDC/releases/tag/v0.1.0
