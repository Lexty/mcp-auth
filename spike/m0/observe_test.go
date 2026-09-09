package main

import (
	"encoding/json"
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
