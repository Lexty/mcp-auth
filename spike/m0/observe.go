package main

import (
	"bytes"
	"crypto/sha256"
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
	"registration_access_token": true,
	"assertion":                 true,
	"password":                  true,
}

// secretHeaders are headers whose value is never recorded.
var secretHeaders = map[string]bool{
	"authorization":       true,
	"proxy-authorization": true,
	"cookie":              true,
	"set-cookie":          true,
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
			out[k] = vs[0]
		} else {
			out[k] = vs
		}
	}
	return out
}

func redactHeaders(h http.Header) map[string]any {
	out := map[string]any{}
	for k, vs := range h {
		if len(vs) == 0 {
			continue
		}
		if secretHeaders[strings.ToLower(k)] {
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
		if len(vs) == 1 {
			out[k] = vs[0]
		} else {
			out[k] = vs
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
		rec[k] = v
	}
	b, err := json.Marshal(rec)
	if err != nil {
		b, _ = json.Marshal(map[string]any{"ts": rec["ts"], "kind": "observation_error", "error": err.Error()})
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	o.f.Write(append(b, '\n'))
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

		var body []byte
		if r.Body != nil {
			body, _ = io.ReadAll(io.LimitReader(r.Body, 1<<20))
			r.Body.Close()
			r.Body = io.NopCloser(bytes.NewReader(body))
		}

		o.Write("request", map[string]any{
			"method":  r.Method,
			"path":    r.URL.Path,
			"query":   redactValues(r.URL.Query()),
			"headers": redactHeaders(r.Header),
			"body":    redactBody(r.Header.Get("Content-Type"), body),
			"remote":  r.RemoteAddr,
		})

		c := &capture{ResponseWriter: w, keep: true}
		next.ServeHTTP(c, r)

		o.Write("response", map[string]any{
			"method":      r.Method,
			"path":        r.URL.Path,
			"status":      c.status,
			"bytes":       c.n,
			"duration_ms": time.Since(start).Milliseconds(),
			"body":        redactBody(c.Header().Get("Content-Type"), c.buf.Bytes()),
		})
	})
}
