package oidc

import (
	"testing"
	"time"
)

var testNow = time.Date(2026, 8, 27, 12, 0, 0, 0, time.UTC)

func goodExpectations() Expectations {
	return Expectations{
		Issuer:   "https://idp.example.com",
		ClientID: "linkctrl",
		Nonce:    "the-nonce",
		Now:      testNow,
		Skew:     60 * time.Second,
	}
}

func goodClaims() map[string]any {
	return map[string]any{
		"iss":            "https://idp.example.com",
		"sub":            "subject-1",
		"aud":            "linkctrl",
		"exp":            testNow.Add(5 * time.Minute).Unix(),
		"iat":            testNow.Unix(),
		"nonce":          "the-nonce",
		"email":          "person@example.com",
		"email_verified": true,
		"name":           "A Person",
	}
}

func verifyClaims(t *testing.T, mutate func(map[string]any), want Expectations) (IDToken, error) {
	t.Helper()
	claims := goodClaims()
	if mutate != nil {
		mutate(claims)
	}
	token := signJWT("RS256", testRSAKey, "k", claims)
	return VerifyIDToken(token, keySet("k", false), want)
}

func TestAWellFormedIDTokenVerifies(t *testing.T) {
	got, err := verifyClaims(t, nil, goodExpectations())
	if err != nil {
		t.Fatal(err)
	}
	if got.Subject != "subject-1" || got.Issuer != "https://idp.example.com" {
		t.Fatalf("got %+v", got)
	}
	claim := got.AsClaim()
	if claim.Subject != "subject-1" || !claim.EmailVerified || claim.DisplayName != "A Person" {
		t.Fatalf("claim is %+v", claim)
	}
}

func TestEveryRequiredClaimIsChecked(t *testing.T) {
	for _, tc := range []struct {
		name   string
		mutate func(map[string]any)
		want   func(Expectations) Expectations
		expect string
	}{
		{
			name:   "an issuer that is not the configured one",
			mutate: func(c map[string]any) { c["iss"] = "https://idp.example.com.evil.test" },
			expect: "issuer is",
		},
		{
			name:   "an issuer that is a prefix of the configured one",
			mutate: func(c map[string]any) { c["iss"] = "https://idp.example.com/other" },
			expect: "issuer is",
		},
		{
			name:   "an audience that is somebody else's client",
			mutate: func(c map[string]any) { c["aud"] = "another-client" },
			expect: "does not name this client",
		},
		{
			name: "several audiences with no azp",
			mutate: func(c map[string]any) {
				c["aud"] = []string{"linkctrl", "another-client"}
			},
			expect: "azp is not this client",
		},
		{
			name: "several audiences with somebody else's azp",
			mutate: func(c map[string]any) {
				c["aud"] = []string{"linkctrl", "another"}
				c["azp"] = "another"
			},
			expect: "azp is not this client",
		},
		{
			name:   "an azp naming another client",
			mutate: func(c map[string]any) { c["azp"] = "another" },
			expect: "azp is not this client",
		},
		{
			name:   "no expiry at all",
			mutate: func(c map[string]any) { delete(c, "exp") },
			expect: "no expiry",
		},
		{
			name:   "an expiry further past than the skew",
			mutate: func(c map[string]any) { c["exp"] = testNow.Add(-2 * time.Minute).Unix() },
			expect: "expired at",
		},
		{
			name:   "no iat",
			mutate: func(c map[string]any) { delete(c, "iat") },
			expect: "no iat",
		},
		{
			name:   "issued further ahead than the skew",
			mutate: func(c map[string]any) { c["iat"] = testNow.Add(2 * time.Minute).Unix() },
			expect: "ahead of",
		},
		{
			name:   "a nonce from another flow",
			mutate: func(c map[string]any) { c["nonce"] = "somebody-elses-nonce" },
			expect: "not the one this flow began with",
		},
		{
			name:   "no nonce at all",
			mutate: func(c map[string]any) { delete(c, "nonce") },
			expect: "not the one this flow began with",
		},
		{
			name:   "no subject",
			mutate: func(c map[string]any) { delete(c, "sub") },
			expect: "names no subject",
		},
		{
			name:   "an empty subject",
			mutate: func(c map[string]any) { c["sub"] = "" },
			expect: "names no subject",
		},
		{
			name:   "a flow this add-on started no nonce for",
			want:   func(e Expectations) Expectations { e.Nonce = ""; return e },
			expect: "started no nonce",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			want := goodExpectations()
			if tc.want != nil {
				want = tc.want(want)
			}
			_, err := verifyClaims(t, tc.mutate, want)
			if err == nil {
				t.Fatal("verified an ID token that should have been refused")
			}
			mustContain(t, err.Error(), tc.expect)
		})
	}
}

func TestTheSkewIsAppliedInBothDirections(t *testing.T) {
	want := goodExpectations()
	// Thirty seconds past, inside a sixty-second skew.
	if _, err := verifyClaims(t, func(c map[string]any) {
		c["exp"] = testNow.Add(-30 * time.Second).Unix()
	}, want); err != nil {
		t.Errorf("a token thirty seconds past inside a sixty-second skew was refused: %v", err)
	}
	// Thirty seconds ahead, inside the same skew.
	if _, err := verifyClaims(t, func(c map[string]any) {
		c["iat"] = testNow.Add(30 * time.Second).Unix()
	}, want); err != nil {
		t.Errorf("a token issued thirty seconds ahead inside the skew was refused: %v", err)
	}
	// And with no skew configured, the same token is refused.
	want.Skew = 0
	if _, err := verifyClaims(t, func(c map[string]any) {
		c["exp"] = testNow.Add(-30 * time.Second).Unix()
	}, want); err == nil {
		t.Error("a past token was accepted with no skew configured")
	}
}

func TestAudienceIsAStringOrAnArray(t *testing.T) {
	for _, tc := range []struct {
		name   string
		aud    any
		azp    string
		refuse bool
	}{
		{name: "one, as a string", aud: "linkctrl"},
		{name: "one, as an array", aud: []string{"linkctrl"}},
		{name: "several, with azp", aud: []string{"linkctrl", "other"}, azp: "linkctrl"},
		{name: "an object", aud: map[string]any{"client": "linkctrl"}, refuse: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := verifyClaims(t, func(c map[string]any) {
				c["aud"] = tc.aud
				if tc.azp != "" {
					c["azp"] = tc.azp
				}
			}, goodExpectations())
			if tc.refuse && err == nil {
				t.Fatal("an aud that is neither a string nor an array was accepted")
			}
			if !tc.refuse && err != nil {
				t.Fatalf("a valid aud was refused: %v", err)
			}
		})
	}
}

func TestEmailVerifiedIsReadInBothSpellings(t *testing.T) {
	// The specification says boolean and providers ship the string. Accepting both
	// is safe only because the host matches an account on subject and issuer and
	// never on an email address; a product that matched on email could not.
	for _, tc := range []struct {
		value any
		want  bool
	}{
		{true, true}, {false, false}, {"true", true}, {"false", false},
	} {
		got, err := verifyClaims(t, func(c map[string]any) {
			c["email_verified"] = tc.value
		}, goodExpectations())
		if err != nil {
			t.Fatalf("%v: %v", tc.value, err)
		}
		if bool(got.EmailVerified) != tc.want {
			t.Errorf("email_verified %v read as %v, want %v",
				tc.value, bool(got.EmailVerified), tc.want)
		}
	}
	if _, err := verifyClaims(t, func(c map[string]any) {
		c["email_verified"] = 1
	}, goodExpectations()); err == nil {
		t.Error("email_verified as a number was accepted")
	}
}

func TestTheSignatureIsCheckedBeforeAnyClaimIsRead(t *testing.T) {
	// A claim read out of a document nobody signed is not evidence of anything,
	// and a verifier that branched on an unverified `iss` is one an attacker
	// chooses the branch of. The token below has a perfect claim set and the
	// wrong signature, and the error names the signature.
	token := signJWT("RS256", testRSAKey, "wrong-key", goodClaims())
	_, err := VerifyIDToken(token, keySet("right-key", false), goodExpectations())
	if err == nil {
		t.Fatal("an unsigned-for-us token verified")
	}
	mustContain(t, err.Error(), "the key set does not carry")
}
