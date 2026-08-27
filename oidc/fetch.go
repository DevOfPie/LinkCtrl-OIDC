package oidc

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
)

// FetchError is an outbound request that did not produce a document.
//
// Outcome is the host's own word, from the closed vocabulary, and it is kept
// verbatim: an operator sees the same string as the `outcome` label of
// linkctrl_addon_fetch_total, so a page of this add-on's that says
// `origin_refused` is a page they can match against their dashboard. Status is
// the origin's own when the outcome was `ok` and the code was not a success.
type FetchError struct {
	URL     string
	Outcome string
	Status  int
}

func (e *FetchError) Error() string {
	if e.Outcome == OutcomeOK {
		return fmt.Sprintf("%s answered %d", e.URL, e.Status)
	}
	return fmt.Sprintf("the host did not reach %s: %s", e.URL, e.Outcome)
}

// Advice is what an operator can do about this outcome, in one sentence, or "".
//
// Written here rather than at the two call sites because the fix for each
// outcome is a property of the outcome. Only the ones this add-on's own shape
// can explain are covered; anything else is reported by its word, which is the
// word the host's log and metric use.
func (e *FetchError) Advice() string {
	switch e.Outcome {
	case OutcomeUnconfigured:
		return "Fill in this add-on's " + SettingProviderOrigins + " setting: the manifest " +
			"declares that it talks to something and the operator names what."
	case OutcomeOriginRefused:
		return "Add " + originOf(e.URL) + " to this add-on's " + SettingProviderOrigins +
			" setting. A provider that spreads discovery, the token endpoint and the " +
			"key set across three hostnames needs all three named, separated by spaces."
	case "address_refused":
		return "The name resolved to an address this host will not dial. Grep the " +
			"instance's log for address_rule= to see which rule refused it."
	case "redirect_refused":
		return "The provider redirected off the origin it started on, which the host " +
			"does not follow. Point " + SettingIssuer + " at the origin that answers directly."
	case "timeout":
		return "The provider did not answer inside LINKCTRL_ADDON_FETCH_TIMEOUT, or " +
			"inside what was left of LINKCTRL_ADDON_ROUTE_DEADLINE."
	case "too_large":
		return "The document was larger than LINKCTRL_ADDON_FETCH_MAX_BYTES."
	case "class_refused":
		return "This add-on fetched from something other than a route handler, which " +
			"is a bug in the add-on rather than in the configuration."
	}
	return ""
}

// originOf is the scheme, host and port of a URL, which is the unit the operator
// names. Written by hand rather than through net/url so that a URL this add-on
// could not parse still produces something readable to put in front of somebody.
func originOf(raw string) string {
	rest, ok := strings.CutPrefix(raw, "https://")
	if !ok {
		return raw
	}
	host, _, _ := strings.Cut(rest, "/")
	return "https://" + host
}

// fetch makes one outbound request and hands back the body.
//
// The outcome is the first thing read, per the ABI: everything else in the
// record is empty unless it says `ok`, and a 404 or a 500 from the other end is
// still `ok` because the host reached who it was told to and does not judge the
// answer. So an unsuccessful status is turned into an error here, where this
// add-on does judge it.
func fetch(h Host, req FetchRequest) ([]byte, error) {
	raw, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("building the fetch request: %w", err)
	}
	answer, err := h.NetworkFetch(raw)
	if err != nil {
		// A status rather than an outcome. `network.fetch` undeclared, or an inline
		// redirect invocation, which this add-on has no export for and cannot be in.
		return nil, fmt.Errorf("the host refused the request to %s: %w", req.URL, err)
	}
	var res FetchResponse
	if err := json.Unmarshal(answer, &res); err != nil {
		return nil, fmt.Errorf("the host's answer for %s is not a FetchResponse: %w", req.URL, err)
	}
	if res.Outcome != OutcomeOK {
		return nil, &FetchError{URL: req.URL, Outcome: res.Outcome}
	}
	if res.Status < 200 || res.Status > 299 {
		return nil, &FetchError{URL: req.URL, Outcome: OutcomeOK, Status: res.Status}
	}
	if res.BodyBase64 {
		// True exactly when the response's own bytes were not valid UTF-8. A JSON
		// document is UTF-8 by definition, so this is a provider answering something
		// that is not one — decoded anyway, because the parse error that follows
		// names the real problem better than a refusal here would.
		body, err := base64.StdEncoding.DecodeString(res.Body)
		if err != nil {
			return nil, fmt.Errorf("%s answered a body the host marked base64 and that "+
				"does not decode: %w", req.URL, err)
		}
		return body, nil
	}
	return []byte(res.Body), nil
}

// fetchJSON fetches and parses in one step.
func fetchJSON(h Host, req FetchRequest, into any) error {
	body, err := fetch(h, req)
	if err != nil {
		return err
	}
	if err := json.Unmarshal(body, into); err != nil {
		return fmt.Errorf("%s answered something that is not JSON: %w", req.URL, err)
	}
	return nil
}
