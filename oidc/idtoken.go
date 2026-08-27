package oidc

import (
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"time"
)

// IDToken is the claim set this add-on reads out of a verified ID token.
//
// The fields are the ones OpenID Connect Core requires plus the three this
// add-on turns into a SessionClaim. Everything else the provider sent is
// ignored, which is the same position the records take: read what you use.
type IDToken struct {
	Issuer        string   `json:"iss"`
	Subject       string   `json:"sub"`
	Audience      audience `json:"aud"`
	AuthorizedTo  string   `json:"azp"`
	Expiry        int64    `json:"exp"`
	IssuedAt      int64    `json:"iat"`
	Nonce         string   `json:"nonce"`
	Email         string   `json:"email"`
	EmailVerified verified `json:"email_verified"`
	Name          string   `json:"name"`
	Groups        []string `json:"groups"`
}

// audience is `aud`, which JSON Web Token says is a string or an array of them.
type audience []string

func (a *audience) UnmarshalJSON(data []byte) error {
	var one string
	if err := json.Unmarshal(data, &one); err == nil {
		*a = audience{one}
		return nil
	}
	var many []string
	if err := json.Unmarshal(data, &many); err != nil {
		return errors.New("aud is neither a string nor an array of strings")
	}
	*a = many
	return nil
}

func (a audience) has(want string) bool {
	for _, v := range a {
		if v == want {
			return true
		}
	}
	return false
}

// verified is `email_verified`, which providers spell as a boolean and, in
// violation of the specification and in the field, as the strings "true" and
// "false".
//
// Accepting the string form is a deliberate choice and it is the *safe*
// direction only because of what this add-on does with the answer: the host
// matches an account on subject and issuer and never on an email address, so a
// wrong reading here changes nothing about who is signed in. It gates one
// optional operator policy. A product that matched on email would have to refuse
// the string form outright.
type verified bool

func (v *verified) UnmarshalJSON(data []byte) error {
	var b bool
	if err := json.Unmarshal(data, &b); err == nil {
		*v = verified(b)
		return nil
	}
	var s string
	if err := json.Unmarshal(data, &s); err == nil {
		*v = verified(s == "true")
		return nil
	}
	return errors.New("email_verified is neither a boolean nor a string")
}

// Expectations is what a token has to agree with. Every field is required —
// there is no zero value that means "do not check", because a check that can be
// skipped by leaving a struct field unset is a check that gets skipped.
type Expectations struct {
	Issuer   string
	ClientID string
	Nonce    string
	Now      time.Time
	Skew     time.Duration
}

// VerifyIDToken checks the signature and then every claim OpenID Connect Core
// 3.1.3.7 requires of one, in that order.
//
// Signature first, deliberately: a claim read out of a document nobody signed is
// not evidence of anything, and reading claims before verifying is how a
// verifier ends up branching on an attacker's `iss`.
func VerifyIDToken(token string, set JWKS, want Expectations) (IDToken, error) {
	j, err := parseJWS(token)
	if err != nil {
		return IDToken{}, fmt.Errorf("the ID token: %w", err)
	}
	payload, err := j.verify(set)
	if err != nil {
		return IDToken{}, fmt.Errorf("the ID token: %w", err)
	}
	var t IDToken
	if err := json.Unmarshal(payload, &t); err != nil {
		return IDToken{}, fmt.Errorf("the ID token's payload is not a claim set: %w", err)
	}

	// 2. iss, compared exactly. The specification says exactly, and it means it:
	// a prefix or a suffix comparison here is a provider allowlist with a hole in
	// it, and the issuer is half of the key the host looks an account link up by.
	if t.Issuer != want.Issuer {
		return IDToken{}, fmt.Errorf("the ID token's issuer is %q and this add-on is "+
			"configured for %q", t.Issuer, want.Issuer)
	}
	// 3. aud must contain the client_id.
	if !t.Audience.has(want.ClientID) {
		return IDToken{}, fmt.Errorf("the ID token's audience %v does not name this "+
			"client", []string(t.Audience))
	}
	// 4-5. With more than one audience, azp is required and must be this client.
	if len(t.Audience) > 1 && t.AuthorizedTo != want.ClientID {
		return IDToken{}, errors.New("the ID token names several audiences and its azp " +
			"is not this client")
	}
	if t.AuthorizedTo != "" && t.AuthorizedTo != want.ClientID {
		return IDToken{}, errors.New("the ID token's azp is not this client")
	}
	// 9. exp, with the operator's skew.
	if t.Expiry == 0 {
		return IDToken{}, errors.New("the ID token has no expiry")
	}
	if want.Now.After(time.Unix(t.Expiry, 0).Add(want.Skew)) {
		return IDToken{}, fmt.Errorf("the ID token expired at %s",
			time.Unix(t.Expiry, 0).UTC().Format(time.RFC3339))
	}
	// 10. iat. A token issued in the future is a clock this add-on cannot reason
	// about; a token issued long ago is not refused here, because `exp` is the
	// claim that says when it stops being one.
	if t.IssuedAt == 0 {
		return IDToken{}, errors.New("the ID token has no iat")
	}
	if time.Unix(t.IssuedAt, 0).After(want.Now.Add(want.Skew)) {
		return IDToken{}, fmt.Errorf("the ID token was issued at %s, which is ahead of "+
			"this instance's clock by more than the configured skew",
			time.Unix(t.IssuedAt, 0).UTC().Format(time.RFC3339))
	}
	// 11. nonce, in constant time. It is the binding between this token and the
	// browser that started the flow, and it is stored in this add-on's schema
	// rather than in the cookie so that a visitor cannot choose it.
	if want.Nonce == "" {
		return IDToken{}, errors.New("this add-on started no nonce for the flow")
	}
	if subtle.ConstantTimeCompare([]byte(t.Nonce), []byte(want.Nonce)) != 1 {
		return IDToken{}, errors.New("the ID token's nonce is not the one this flow began " +
			"with, so the token was minted for a different sign-in")
	}
	// The subject is the whole of what the host matches an account on, together
	// with the issuer, so an empty one is refused here rather than sent to
	// session_mint to be refused there.
	if t.Subject == "" {
		return IDToken{}, errors.New("the ID token names no subject")
	}
	return t, nil
}

// AsClaim is the SessionClaim this token becomes.
//
// The issuer is the token's, which by the time this is called has been compared
// exactly against the configured one — so it is the same string either way, and
// taking it from the token is what makes that sentence checkable rather than
// assumed.
func (t IDToken) AsClaim() Claim {
	return Claim{
		Subject:       t.Subject,
		Issuer:        t.Issuer,
		Email:         t.Email,
		EmailVerified: bool(t.EmailVerified),
		DisplayName:   t.Name,
		Groups:        t.Groups,
	}
}
