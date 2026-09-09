package main

import (
	"bytes"
	"context"
	crand "crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"
)

// The spike exists to record what a real MCP client actually does. Everything
// interesting is therefore written to one JSONL file, and the redaction rules
// below are the part that must not be got wrong: an observation log that leaks
// a token is worse than no observation log, because it will be pasted into a
// chat window by someone reporting a result.

// secretParams are query or form parameters whose value is never recorded.
var secretParams = map[string]bool{
	"client_secret":             true,
	"code":                      true,
	"code_verifier":             true,
	"access_token":              true,
	"refresh_token":             true,
	"token":                     true,
	"id_token":                  true,
	"id_token_hint":             true,
	"registration_access_token": true,
	"assertion":                 true,
	"client_assertion":          true,
	"subject_token":             true,
	"actor_token":               true,
	"password":                  true,
	"authorization":             true,
	"apikey":                    true,
	"api_key":                   true,
	"secret":                    true,
}

// Deliberately not secrets: "session" and "sid". The gateway's own session
// identifier is a correlation key that the canonical audit schema requires
// recording, not a credential presented for authentication. Fingerprinting it
// would defeat the only thing it is for.

// secretHeaders are headers whose value is never recorded.
var secretHeaders = map[string]bool{
	"authorization":       true,
	"proxy-authorization": true,
	"cookie":              true,
	"set-cookie":          true,
	"x-api-key":           true,
}

// responseHeadersRecorded is an allow list. The log has to show what was
// actually sent — WWW-Authenticate and Location are evidence — but recording
// every response header invites the next leak.
var responseHeadersRecorded = []string{
	"WWW-Authenticate", "Location", "Content-Type", "Cache-Control", "X-Frame-Options",
}

// Fingerprint turns a secret into something that can be compared across
// requests without being reversible. This is what answers "did the client
// present the rotated refresh token or the old one?" — the single question
// that decides whether one-time rotation is usable at all.
func Fingerprint(s string) string {
	if s == "" {
		return ""
	}
	sum := sha256.Sum256([]byte(s))
	return fmt.Sprintf("sha256:%x len=%d", sum[:4], len(s))
}

// scrubURL removes secret query parameters from a URL that is itself a value
// somewhere — redirect_uri, resource, Referer, Location. A secret nested one
// level down is still a secret, and this is the path that leaked.
func scrubURL(s string) string {
	if !strings.Contains(s, "?") {
		return s
	}
	u, err := url.Parse(s)
	if err != nil || u.RawQuery == "" {
		return s
	}
	q := u.Query()
	changed := false
	for k, vs := range q {
		if !secretParams[strings.ToLower(k)] {
			continue
		}
		for i := range vs {
			vs[i] = Fingerprint(vs[i])
		}
		q[k] = vs
		changed = true
	}
	if !changed {
		return s
	}
	u.RawQuery = q.Encode()
	return u.String()
}

// scrub is applied to every value that reaches the log, from any code path.
// Checking the individual redactors was not enough: events written directly
// bypassed them, which is how a URL-borne secret got through.
func scrub(key string, v any) any {
	if secretParams[strings.ToLower(key)] {
		if str, ok := v.(string); ok {
			return Fingerprint(str)
		}
		return "[redacted]"
	}
	switch t := v.(type) {
	case string:
		return scrubURL(t)
	case []string:
		out := make([]string, len(t))
		for i, x := range t {
			out[i] = scrubURL(x)
		}
		return out
	case map[string]any:
		out := make(map[string]any, len(t))
		for k, val := range t {
			out[k] = scrub(k, val)
		}
		return out
	case []any:
		out := make([]any, len(t))
		for i, val := range t {
			out[i] = scrub("", val)
		}
		return out
	default:
		return v
	}
}

func redactValues(v url.Values) map[string]any {
	out := map[string]any{}
	for k, vs := range v {
		if len(vs) == 0 {
			continue
		}
		if secretParams[strings.ToLower(k)] {
			out[k] = Fingerprint(vs[0])
			continue
		}
		if len(vs) == 1 {
			out[k] = scrubURL(vs[0])
		} else {
			out[k] = scrub("", toAny(vs))
		}
	}
	return out
}

func toAny(vs []string) []any {
	out := make([]any, len(vs))
	for i, v := range vs {
		out[i] = v
	}
	return out
}

func redactHeaders(h http.Header) map[string]any {
	out := map[string]any{}
	for k, vs := range h {
		if len(vs) == 0 {
			continue
		}
		lk := strings.ToLower(k)
		if lk == "cookie" || lk == "set-cookie" {
			// A cookie header is a list of name=value pairs, not a scheme and
			// a credential. Splitting it on a space kept the first pair in
			// the clear. Nothing from it is recorded but its shape.
			out[k] = fmt.Sprintf("[%d cookie(s), not recorded]", len(strings.Split(vs[0], ";")))
			continue
		}
		if secretHeaders[lk] {
			// Record the scheme but never the credential: "Bearer" plus a
			// fingerprint tells us which token was used without storing it.
			f := vs[0]
			if scheme, cred, ok := strings.Cut(f, " "); ok {
				out[k] = scheme + " " + Fingerprint(cred)
			} else {
				out[k] = Fingerprint(f)
			}
			continue
		}
		// Referer and Location are URLs, and a URL is a place a secret hides.
		if len(vs) == 1 {
			out[k] = scrubURL(vs[0])
		} else {
			out[k] = scrub("", toAny(vs))
		}
	}
	return out
}

// redactJSON walks a decoded JSON document and replaces the value of any key
// named like a secret. It recurses, because tokens turn up nested.
func redactJSON(v any) any {
	switch t := v.(type) {
	case map[string]any:
		out := make(map[string]any, len(t))
		for k, val := range t {
			if secretParams[strings.ToLower(k)] {
				if s, ok := val.(string); ok {
					out[k] = Fingerprint(s)
					continue
				}
				out[k] = "[redacted]"
				continue
			}
			out[k] = redactJSON(val)
		}
		return out
	case []any:
		out := make([]any, len(t))
		for i, val := range t {
			out[i] = redactJSON(val)
		}
		return out
	default:
		return v
	}
}

// redactBody decodes a body for structured redaction where it can, and falls
// back to a description rather than the bytes where it cannot. It never
// returns raw bytes it did not understand.
func redactBody(contentType string, b []byte) any {
	if len(b) == 0 {
		return nil
	}
	ct := strings.ToLower(contentType)
	switch {
	case strings.Contains(ct, "application/json"):
		var v any
		if err := json.Unmarshal(b, &v); err != nil {
			return map[string]any{"unparsed": true, "bytes": len(b)}
		}
		return redactJSON(v)
	case strings.Contains(ct, "application/x-www-form-urlencoded"):
		v, err := url.ParseQuery(string(b))
		if err != nil {
			return map[string]any{"unparsed": true, "bytes": len(b)}
		}
		return redactValues(v)
	case strings.Contains(ct, "text/event-stream"):
		return map[string]any{"event_stream": true, "bytes": len(b)}
	default:
		return map[string]any{"content_type": contentType, "bytes": len(b)}
	}
}

type ctxKey int

const exchangeKey ctxKey = 0

func WithExchange(ctx context.Context, id string) context.Context {
	return context.WithValue(ctx, exchangeKey, id)
}

// Exchange returns the correlation id for the HTTP exchange a handler is
// serving, so that events written from inside a handler join up with the
// request and response lines around them.
func Exchange(ctx context.Context) string {
	if v, ok := ctx.Value(exchangeKey).(string); ok {
		return v
	}
	return ""
}

func randHex(n int) string {
	b := make([]byte, n)
	crand.Read(b)
	return hex.EncodeToString(b)
}

// Obs is the observation log.
type Obs struct {
	mu sync.Mutex
	f  *os.File
}

func NewObs(path string) (*Obs, error) {
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return nil, err
	}
	return &Obs{f: f}, nil
}

func (o *Obs) Close() error { return o.f.Close() }

func (o *Obs) Write(kind string, fields map[string]any) {
	rec := map[string]any{
		"ts":   time.Now().UTC().Format(time.RFC3339Nano),
		"kind": kind,
	}
	for k, v := range fields {
		rec[k] = scrub(k, v)
	}
	b, err := json.Marshal(rec)
	if err != nil {
		b, _ = json.Marshal(map[string]any{"ts": rec["ts"], "kind": "observation_error", "error": err.Error()})
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	if _, err := o.f.Write(append(b, '\n')); err != nil {
		// The log is the deliverable. Losing a line silently would mean
		// reporting an observation that was never recorded.
		fmt.Fprintf(os.Stderr, "FATAL: cannot write observation log: %v\n", err)
		os.Exit(1)
	}
	o.f.Sync()
	fmt.Fprintf(os.Stderr, "%s %s\n", kind, string(b))
}

// capture is a ResponseWriter that records status and body size, and keeps the
// body only when it is small and structured enough to be worth keeping.
type capture struct {
	http.ResponseWriter
	status int
	n      int
	buf    bytes.Buffer
	keep   bool
}

func (c *capture) WriteHeader(code int) {
	c.status = code
	c.ResponseWriter.WriteHeader(code)
}

func (c *capture) Write(b []byte) (int, error) {
	if c.status == 0 {
		c.status = http.StatusOK
	}
	c.n += len(b)
	if c.keep && c.buf.Len() < 16<<10 {
		c.buf.Write(b)
	}
	return c.ResponseWriter.Write(b)
}

// Flush lets SSE responses stream through the observation middleware. Without
// it a streaming response would be buffered here, which is exactly the failure
// the transport specification warns proxies about.
func (c *capture) Flush() {
	if f, ok := c.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

// Middleware records one line per request and one per response.
func (o *Obs) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		// Without this, two concurrent exchanges cannot be told apart in the
		// log, and the rotation observations are exactly the ones that
		// interleave.
		xid := "x" + randHex(6)
		r = r.WithContext(WithExchange(r.Context(), xid))

		var body []byte
		if r.Body != nil {
			body, _ = io.ReadAll(io.LimitReader(r.Body, 1<<20))
			r.Body.Close()
			r.Body = io.NopCloser(bytes.NewReader(body))
		}

		o.Write("request", map[string]any{
			"exchange": xid,
			"method":   r.Method,
			"path":     r.URL.Path,
			"query":    redactValues(r.URL.Query()),
			"headers":  redactHeaders(r.Header),
			"body":     redactBody(r.Header.Get("Content-Type"), body),
			"remote":   r.RemoteAddr,
		})

		c := &capture{ResponseWriter: w, keep: true}
		next.ServeHTTP(c, r)

		sent := map[string]any{}
		for _, h := range responseHeadersRecorded {
			if v := c.Header().Get(h); v != "" {
				sent[h] = scrubURL(v)
			}
		}
		o.Write("response", map[string]any{
			"exchange":    xid,
			"method":      r.Method,
			"path":        r.URL.Path,
			"status":      c.status,
			"headers":     sent,
			"bytes":       c.n,
			"duration_ms": time.Since(start).Milliseconds(),
			"body":        redactBody(c.Header().Get("Content-Type"), c.buf.Bytes()),
		})
	})
}
