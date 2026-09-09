package main

import (
	"encoding/json"
	"net"
	"net/http"
	"net/url"
	"strings"
	"testing"
)

// The observation log is meant to be pasted into a report. A leak here is the
// one defect in this throwaway program that would actually matter, so these
// are the only tests it has.

const secret = "s3cret-token-value"

func TestRedactValues(t *testing.T) {
	for _, tc := range []struct {
		name string
		in   url.Values
		keep []string // parameters whose value must survive
	}{
		{"authorization request", url.Values{
			"client_id": {"abc"}, "resource": {"https://example.com/mcp"},
			"code_challenge": {"chal"}, "state": {"xyz"},
		}, []string{"abc", "https://example.com/mcp", "chal", "xyz"}},
		{"token request", url.Values{
			"grant_type": {"authorization_code"}, "code": {secret},
			"code_verifier": {secret}, "client_secret": {secret},
		}, []string{"authorization_code"}},
		{"refresh request", url.Values{
			"grant_type": {"refresh_token"}, "refresh_token": {secret},
		}, []string{"refresh_token"}}, // the grant_type value, not the token
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := json.Marshal(redactValues(tc.in))
			if err != nil {
				t.Fatal(err)
			}
			if strings.Contains(string(got), secret) {
				t.Fatalf("secret survived redaction: %s", got)
			}
			for _, want := range tc.keep {
				if !strings.Contains(string(got), want) {
					t.Errorf("expected %q to be recorded, got %s", want, got)
				}
			}
		})
	}
}

func TestRedactHeaders(t *testing.T) {
	h := http.Header{}
	h.Set("Authorization", "Bearer "+secret)
	h.Set("Cookie", secret)
	h.Set("Mcp-Method", "tools/call")
	h.Set("MCP-Protocol-Version", "2025-06-18")

	got, _ := json.Marshal(redactHeaders(h))
	if strings.Contains(string(got), secret) {
		t.Fatalf("secret survived redaction: %s", got)
	}
	// The scheme is worth keeping; the credential is not.
	if !strings.Contains(string(got), "Bearer sha256:") {
		t.Errorf("expected the bearer scheme and a fingerprint, got %s", got)
	}
	for _, want := range []string{"tools/call", "2025-06-18"} {
		if !strings.Contains(string(got), want) {
			t.Errorf("expected %q to be recorded, got %s", want, got)
		}
	}
}

func TestRedactJSONRecurses(t *testing.T) {
	body := []byte(`{"a":{"b":[{"access_token":"` + secret + `"}]},"client_name":"Some Client"}`)
	got, _ := json.Marshal(redactBody("application/json", body))
	if strings.Contains(string(got), secret) {
		t.Fatalf("nested secret survived redaction: %s", got)
	}
	if !strings.Contains(string(got), "Some Client") {
		t.Errorf("expected non-secret fields to survive, got %s", got)
	}
}

func TestRedactBodyNeverEchoesUnknownContent(t *testing.T) {
	for _, ct := range []string{"text/plain", "application/octet-stream", ""} {
		got, _ := json.Marshal(redactBody(ct, []byte(secret)))
		if strings.Contains(string(got), secret) {
			t.Fatalf("content-type %q echoed the body: %s", ct, got)
		}
	}
}

func TestFingerprintIsStableAndDistinguishing(t *testing.T) {
	a, b := Fingerprint("token-one"), Fingerprint("token-two")
	if a == b {
		t.Fatal("different tokens must fingerprint differently, or rotation cannot be observed")
	}
	if a != Fingerprint("token-one") {
		t.Fatal("the same token must fingerprint identically, or reuse cannot be observed")
	}
	if strings.Contains(a, "token-one") {
		t.Fatalf("fingerprint leaks the value: %s", a)
	}
	if Fingerprint("") != "" {
		t.Fatal("an absent value should fingerprint to nothing, not to a hash of the empty string")
	}
}

func TestRedirectAllowed(t *testing.T) {
	registered := []string{"https://claude.ai/api/mcp/auth_callback", "http://localhost/callback"}
	for _, tc := range []struct {
		presented string
		want      bool
		how       string
	}{
		{"https://claude.ai/api/mcp/auth_callback", true, "exact"},
		{"https://claude.ai/api/mcp/auth_callback/", false, ""},
		{"https://evil.example/cb", false, ""},
		{"http://localhost:3118/callback", true, "loopback-port-ignored"},
		{"http://localhost:3118/other", false, ""},
		{"https://localhost:3118/callback", false, ""}, // scheme must still match
	} {
		got, how := redirectAllowed(registered, tc.presented)
		if got != tc.want || (tc.want && how != tc.how) {
			t.Errorf("redirectAllowed(%q) = %v/%q, want %v/%q", tc.presented, got, how, tc.want, tc.how)
		}
	}
}

// The cases below were all reproduced by a reviewer against the first version
// of the redactor. Each one is a path by which a secret reached the log.

func TestRedactionLeaksFoundInReview(t *testing.T) {
	for _, tc := range []struct {
		name string
		got  func() any
	}{
		{"cookie is a list of pairs, not a scheme and a credential", func() any {
			h := http.Header{}
			h.Set("Cookie", "session="+secret+"; other=x")
			return redactHeaders(h)
		}},
		{"referer carries the callback query", func() any {
			h := http.Header{}
			h.Set("Referer", "https://example.com/callback?code="+secret)
			return redactHeaders(h)
		}},
		{"client_assertion is a credential", func() any {
			return redactValues(url.Values{"client_assertion": {secret}})
		}},
		{"a secret nested inside a URL-valued parameter", func() any {
			return redactValues(url.Values{"redirect_uri": {"https://example.com/cb?token=" + secret}})
		}},
		{"an event written directly, bypassing the request redactors", func() any {
			return scrub("redirect_uri", "https://example.com/cb?access_token="+secret)
		}},
		{"a secret nested in a structure written directly", func() any {
			return scrub("document", map[string]any{
				"redirect_uris": []any{"https://example.com/cb?code=" + secret},
				"client_secret": secret,
			})
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			b, _ := json.Marshal(tc.got())
			if strings.Contains(string(b), secret) {
				t.Fatalf("secret survived: %s", b)
			}
		})
	}
}

func TestScrubURLKeepsWhatIsNotSecret(t *testing.T) {
	in := "https://example.com/cb?state=abc&code=" + secret + "&resource=https%3A%2F%2Fx%2Fmcp"
	got := scrubURL(in)
	if strings.Contains(got, secret) {
		t.Fatalf("secret survived: %s", got)
	}
	for _, want := range []string{"state=abc", "example.com/cb"} {
		if !strings.Contains(got, want) {
			t.Errorf("expected %q to survive, got %s", want, got)
		}
	}
}

func TestPublicIPExcludesCarrierGradeNAT(t *testing.T) {
	for _, tc := range []struct {
		ip   string
		want bool
	}{
		{"93.184.216.34", true},
		{"100.64.0.1", false}, // carrier-grade NAT; no net.IP predicate excludes it
		{"100.128.0.1", true}, // just outside 100.64.0.0/10
		{"10.0.0.1", false},
		{"127.0.0.1", false},
		{"169.254.169.254", false}, // cloud metadata
		{"192.168.1.1", false},
	} {
		if got := publicIP(net.ParseIP(tc.ip)); got != tc.want {
			t.Errorf("publicIP(%s) = %v, want %v", tc.ip, got, tc.want)
		}
	}
}

// Redaction runs in layers, and the layers must not eat each other. This one
// cost a false observation: an Authorization header redacted by redactHeaders
// was fingerprinted a second time by scrub, and the resulting line looked like
// the client had presented a 29-character credential.
func TestRedactionIsIdempotent(t *testing.T) {
	h := http.Header{}
	h.Set("Authorization", "Bearer "+secret)

	once := redactHeaders(h)
	twice := scrub("headers", once).(map[string]any)

	got, _ := json.Marshal(twice)
	if strings.Contains(string(got), secret) {
		t.Fatalf("secret survived: %s", got)
	}
	if once["Authorization"] != twice["Authorization"] {
		t.Errorf("second pass changed the value: %q became %q", once["Authorization"], twice["Authorization"])
	}
	if !strings.HasPrefix(twice["Authorization"].(string), "Bearer sha256:") {
		t.Errorf("the scheme and the fingerprint must both survive, got %q", twice["Authorization"])
	}
	// And the fingerprint must still identify the token, or rotation cannot be
	// followed across requests.
	if !strings.Contains(twice["Authorization"].(string), Fingerprint(secret)) {
		t.Errorf("fingerprint no longer identifies the credential: %q", twice["Authorization"])
	}
}
