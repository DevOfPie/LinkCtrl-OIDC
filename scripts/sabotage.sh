#!/usr/bin/env bash
# Sabotage every claim this repository's tests make, one at a time.
#
# # Why this exists
#
# A test that has never failed is a test nobody has evidence about. The gate this
# repository is held to is *sabotage-verified tests*: for each claim, break the
# code that makes it true, watch the named test go red, and put the code back by
# a counter-edit rather than by a checkout — so that what is restored is what was
# there and the restoration itself is checked.
#
# # How it works
#
# Each row below is a claim, the file it lives in, the exact text to replace, the
# text to replace it with, and the test that must fail. The script applies one
# mutation, runs that test, asserts a non-zero exit, then applies the reverse
# replacement and asserts the file is byte-identical to what it started as. A row
# whose test *passes* under sabotage is a failure of this script, and it says so.
#
# The counter-edit is the point. `git checkout` would restore the file without
# proving the mutation was reversible, and a mutation that could not be reversed
# is one that changed something other than what the row claims.
#
#   ./scripts/sabotage.sh              every row
#   ./scripts/sabotage.sh single-use   the rows whose name matches
#
# Rows that need a Postgres are skipped without OIDC_TEST_PSQL_DSN, which is the
# same condition the tests themselves skip on.

set -uo pipefail
cd "$(dirname "$0")/.."

declare -i ran=0 failed=0 skipped=0
filter="${1:-}"

# apply replaces the first occurrence of $2 with $3 in $1, and fails loudly if
# the text is not there — a row that has drifted from the code must not pass by
# mutating nothing.
apply() {
  python3 - "$@" <<'PY'
import sys
path, old, new = sys.argv[1], sys.argv[2], sys.argv[3]
s = open(path).read()
n = s.count(old)
if n == 0:
    sys.stderr.write("not found in %s:\n%s\n" % (path, old))
    sys.exit(2)
if n > 1:
    # A row that matches twice would be reversed onto the wrong occurrence, and
    # the reversal would still look like a success. Refuse rather than guess.
    sys.stderr.write("found %d times in %s; make the row unique:\n%s\n" % (n, path, old))
    sys.exit(3)
open(path, "w").write(s.replace(old, new, 1))
PY
}

row() {
  local name="$1" file="$2" old="$3" new="$4" test="$5" needs="${6:-}"
  if [ -n "$filter" ] && [[ "$name" != *"$filter"* ]]; then return; fi
  if [ "$needs" = "postgres" ] && [ -z "${OIDC_TEST_PSQL_DSN:-}" ]; then
    printf 'SKIP  %-38s (needs OIDC_TEST_PSQL_DSN)\n' "$name"
    skipped+=1
    return
  fi

  local before after
  before=$(sha256sum "$file")
  if ! apply "$file" "$old" "$new"; then
    printf 'ERROR %-38s the row does not match the code\n' "$name"
    failed+=1
    return
  fi

  ran+=1
  if go test ./... -run "$test" -count=1 >/tmp/sabotage.$$ 2>&1; then
    printf 'GREEN %-38s %s passed while sabotaged\n' "$name" "$test"
    sed 's/^/      /' /tmp/sabotage.$$ | head -20
    failed+=1
  else
    printf 'RED   %-38s %s\n' "$name" "$test"
  fi
  rm -f /tmp/sabotage.$$

  # The counter-edit, and the check that it was one.
  if ! apply "$file" "$new" "$old"; then
    printf 'ERROR %-38s could not be reversed; %s is now wrong\n' "$name" "$file"
    exit 1
  fi
  after=$(sha256sum "$file")
  if [ "$before" != "$after" ]; then
    printf 'ERROR %-38s the counter-edit did not restore %s\n' "$name" "$file"
    exit 1
  fi
}

# --- the verifier ------------------------------------------------------------

row 'hmac-family-refused' oidc/jose.go \
  'case "RS256", "PS256", "ES256":' \
  'case "RS256", "PS256", "ES256", "HS256":' \
  TestTheAlgorithmVocabularyIsAnAllowlist

row 'unknown-kid-is-its-own-answer' oidc/jose.go \
  '		return JWK{}, errUnknownKid
	}
	switch len(usable) {' \
  '		if len(usable) > 0 {
			return usable[0], nil
		}
		return JWK{}, errUnknownKid
	}
	switch len(usable) {' \
  TestAnUnknownKidIsItsOwnAnswer

row 'ambiguous-key-set-refused' oidc/jose.go \
  '	default:
		return JWK{}, errors.New("the token names no kid and the key set holds several "' \
  '	default:
		return usable[0], errors.New("")
	case -1:
		return JWK{}, errors.New("the token names no kid and the key set holds several "' \
  TestATokenWithNoKidNeedsAnUnambiguousKeySet

row 'ecdsa-signature-width' oidc/jose.go \
  '		if len(j.signature) != 2*size {' \
  '		if len(j.signature) > 2*size {' \
  TestAnECDSASignatureIsReadAtTheCurvesWidth

row 'ec-coordinate-width' oidc/jose.go \
  '	if len(b) != size {' \
  '	if len(b) > size {' \
  TestAMalformedKeyIsRefusedRatherThanGuessedAt

# --- the claim set -----------------------------------------------------------

row 'issuer-compared-exactly' oidc/idtoken.go \
  '	if t.Issuer != want.Issuer {' \
  '	if !strings.HasPrefix(want.Issuer, t.Issuer) {' \
  TestEveryRequiredClaimIsChecked

row 'audience-names-this-client' oidc/idtoken.go \
  '	if !t.Audience.has(want.ClientID) {' \
  '	if false {' \
  TestEveryRequiredClaimIsChecked

row 'azp-when-several-audiences' oidc/idtoken.go \
  '	if len(t.Audience) > 1 && t.AuthorizedTo != want.ClientID {' \
  '	if false {' \
  TestEveryRequiredClaimIsChecked

row 'expiry-is-checked' oidc/idtoken.go \
  '	if want.Now.After(time.Unix(t.Expiry, 0).Add(want.Skew)) {' \
  '	if false {' \
  TestEveryRequiredClaimIsChecked

row 'nonce-binds-the-flow' oidc/idtoken.go \
  '	if subtle.ConstantTimeCompare([]byte(t.Nonce), []byte(want.Nonce)) != 1 {' \
  '	if false {' \
  TestEveryRequiredClaimIsChecked

row 'signature-before-claims' oidc/idtoken.go \
  '	payload, err := j.verify(set)
	if err != nil {
		return IDToken{}, fmt.Errorf("the ID token: %w", err)
	}' \
  '	payload := j.payload' \
  TestTheSignatureIsCheckedBeforeAnyClaimIsRead

# --- the flow ----------------------------------------------------------------

row 'pkce-challenge-is-a-digest' oidc/flow.go \
  '	sum := sha256.Sum256([]byte(verifier))
	return b64.EncodeToString(sum[:])' \
  '	return verifier' \
  TestAuthorizationRequestCarriesPKCEAndAFreshStateAndNonce

row 'state-checked-at-the-callback' oidc/handler.go \
  '	if subtle.ConstantTimeCompare([]byte(state), []byte(flow.State)) != 1 {' \
  '	if false {' \
  TestCallbackRefusesAForeignState

row 'flow-claimed-exactly-once' oidc/store.go \
  '	if err := s.exec(sqlClaimFlow, args(handle)); err != nil {
		return Flow{}, ErrFlowGone
	}' \
  '	_ = s.exec(sqlClaimFlow, args(handle))' \
  'TestCallbackIsSingleUse|TestAFlowIsClaimedExactlyOnce'

row 'expired-flow-is-gone' oidc/store.go \
  '		  WHERE handle = $1 AND expires_at > now()`' \
  '		  WHERE handle = $1`' \
  TestAnExpiredFlowIsGone

row 'mode-is-the-flows' oidc/flow.go \
  '	switch mode {
	case ModeLink:' \
  '	switch mode {
	case "never":' \
  TestLinkingConnectsToTheSignedInAccount

row 'sign-in-refuses-a-session' oidc/handler.go \
  '	if who.SignedIn {
		return Response{}, errors.New("somebody is already signed in on this browser. "' \
  '	if false {
		return Response{}, errors.New("somebody is already signed in on this browser. "' \
  TestStartRefusesSomebodyAlreadySignedIn

row 'link-refuses-nobody' oidc/handler.go \
  '	if !who.SignedIn {
		return Response{}, errors.New("linking connects a provider to the account that "' \
  '	if false {
		return Response{}, errors.New("linking connects a provider to the account that "' \
  TestLinkRefusesNobody

row 'one-refresh-for-a-rotation' oidc/flow.go \
  '	if !errors.Is(err, errUnknownKid) {
		return IDToken{}, err
	}' \
  '	if err != nil { // sabotaged
		return IDToken{}, err
	}' \
  TestARotatedKeyIsFetchedExactlyOnceMore

# --- the configuration -------------------------------------------------------

row 'cleartext-refused' oidc/config.go \
  '	if u.Scheme != "https" || u.Host == "" {' \
  '	if u.Host == "" {' \
  TestCleartextIsRefusedBeforeAnythingIsSent

row 'landing-is-a-path-here' oidc/config.go \
  '	if raw == "" || !strings.HasPrefix(raw, "/") || strings.HasPrefix(raw, "//") {
		return fallback
	}' \
  '	if raw == "" {
		return fallback
	}' \
  TestALandingIsAPathOnThisInstance

row 'refused-grant-is-not-a-default' oidc/config.go \
  '	case errors.Is(err, sdk.ErrNotFound):
		return "", nil' \
  '	case err != nil:
		return "", nil' \
  TestARefusedConfigGrantIsNotADefault

row 'discovery-names-the-issuer' oidc/provider.go \
  '	if strings.TrimSuffix(d.Issuer, "/") != p.cfg.Issuer {' \
  '	if false {' \
  TestDiscoveryMustDescribeTheConfiguredIssuer

row 'anonymous-sees-no-configuration' oidc/handler.go \
  '	case !who.SignedIn:' \
  '	case false:' \
  TestTheIndexTellsAnAnonymousVisitorNothingAboutTheConfiguration

row 'a-failed-fetch-is-not-a-document' oidc/fetch.go \
  '	if res.Outcome != OutcomeOK {
		return nil, &FetchError{URL: req.URL, Outcome: res.Outcome}
	}' \
  '	_ = res.Outcome' \
  'TestNoOriginAtAllIsTheOrdinaryStateOfAFreshInstall'

# --- the manifest ------------------------------------------------------------

row 'manifest-declares-what-it-uses' addon.json.in \
  '    "network.fetch"' \
  '    "redirect.observe"' \
  TestEveryPermissionIsOneTheAddonUsesAndNoneIsMissing

row 'origin-setting-carries-no-default' addon.json.in \
  '      "name": "provider_origins",
      "type": "text",
      "origin": true' \
  '      "name": "provider_origins",
      "type": "text",
      "default": "https://idp.example.com",
      "origin": true' \
  TestTheOriginSettingIsTheOnlyPlaceADestinationCanCome

row 'cookie-namespace-is-this-addons' addon.json.in \
  '    "oidc_"' \
  '    "oidc_x"' \
  TestTheCookieNamespaceIsThisAddonsOwn

row 'abi-generation-is-the-sdks' addon.json.in \
  '  "abi_version": 1,' \
  '  "abi_version": 2,' \
  TestTheManifestAndTheCodeAgree

# --- the module's own boundary ------------------------------------------------

row 'export-is-spelled-right' main.go \
  '//go:wasmexport linkctrl_http_handle' \
  '//go:wasmexport linkctrl_http_handler' \
  TestTheExportIsSpelledTheWayTheHostLooksItUp

# --- the SQL, against a real server ------------------------------------------

row 'single-use-is-a-unique-violation' oidc/store.go \
  '	`CREATE TABLE IF NOT EXISTS spent (
		handle   text PRIMARY KEY,' \
  '	`CREATE TABLE IF NOT EXISTS spent (
		handle   text,' \
  TestAReplayedClaimIsAUniqueViolation postgres

row 'the-ddl-is-valid-postgres' oidc/store.go \
  '		expires_at timestamptz NOT NULL
	)`,
	// The single-use record' \
  '		expires_at timestampz NOT NULL
	)`,
	// The single-use record' \
  TestTheDDLIsValidPostgres postgres

# Every counter-edit has landed. A green suite here is what says the tree this
# script hands back is the tree it was given.
echo
if ! go test ./... -count=1 >/tmp/sabotage-final.$$ 2>&1; then
  echo 'ERROR the suite is not green after the counter-edits:'
  sed 's/^/      /' /tmp/sabotage-final.$$
  rm -f /tmp/sabotage-final.$$
  exit 1
fi
rm -f /tmp/sabotage-final.$$

printf 'sabotaged %d claim(s), %d skipped, %d did not go red; the suite is green again\n' \
  "$ran" "$skipped" "$failed"
exit $((failed > 0))
