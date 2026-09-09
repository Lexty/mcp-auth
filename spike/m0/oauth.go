package main

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"html/template"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// A deliberately minimal OAuth 2.1 authorization server. Identity is hard
// coded; there is no upstream provider and no policy. The point is to find out
// what a real MCP client sends, in what order, and what it does when things
// expire or fail — not to be a usable authorization server.
//
// One thing here is not minimal on purpose: both Dynamic Client Registration
// and Client ID Metadata Documents are supported, and the metadata advertises
// both. Which one the client actually picks is the most valuable single
// observation this spike can produce, and we cannot learn it by offering only
// one.

type Client struct {
	ID           string
	Secret       string
	Name         string
	RedirectURIs []string
	AuthMethod   string // token endpoint auth method this client registered with
	Via          string // "dcr" | "cimd" | "preregistered"
	Registered   time.Time
	Raw          map[string]any
}

type AuthCode struct {
	Code                string
	ClientID            string
	RedirectURI         string
	CodeChallenge       string
	CodeChallengeMethod string
	Resource            string
	Scope               string
	Expires             time.Time
}

type Session struct {
	ID           string
	ClientID     string
	AccessToken  string
	RefreshToken string
	Resource     string
	Scope        string
	AccessExp    time.Time
	RefreshExp   time.Time
	Generation   int // how many times refresh has rotated
	Revoked      bool
}

type Store struct {
	mu        sync.Mutex
	clients   map[string]*Client
	codes     map[string]*AuthCode
	sessions  map[string]*Session // keyed by session id
	byAccess  map[string]string
	byRefresh map[string]string
	// retired refresh tokens, kept so we can observe a client presenting one
	// after rotation instead of silently treating it as unknown.
	retiredRefresh map[string]string
}

func NewStore() *Store {
	return &Store{
		clients:        map[string]*Client{},
		codes:          map[string]*AuthCode{},
		sessions:       map[string]*Session{},
		byAccess:       map[string]string{},
		byRefresh:      map[string]string{},
		retiredRefresh: map[string]string{},
	}
}

func token(n int) string {
	b := make([]byte, n)
	rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

type Server struct {
	cfg   Config
	obs   *Obs
	store *Store

	// control knobs, driven from the admin listener, so that the mandatory M0
	// observations are produced deliberately rather than waited for.
	mu                sync.Mutex
	force401          bool
	forceInvalidGrant bool
}

func (s *Server) issuer() string { return strings.TrimRight(s.cfg.PublicURL, "/") }

func (s *Server) resourceURL() string { return s.issuer() + s.cfg.MCPPath }

// ---------- metadata ----------

func (s *Server) protectedResourceMetadata(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, 200, map[string]any{
		"resource":                 s.resourceURL(),
		"authorization_servers":    []string{s.issuer()},
		"scopes_supported":         []string{"mcp", "offline_access"},
		"bearer_methods_supported": []string{"header"},
	})
}

func (s *Server) authorizationServerMetadata(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, 200, map[string]any{
		"issuer":                                s.issuer(),
		"authorization_endpoint":                s.issuer() + "/authorize",
		"token_endpoint":                        s.issuer() + "/token",
		"registration_endpoint":                 s.issuer() + "/register",
		"revocation_endpoint":                   s.issuer() + "/revoke",
		"response_types_supported":              []string{"code"},
		"grant_types_supported":                 []string{"authorization_code", "refresh_token"},
		"code_challenge_methods_supported":      []string{"S256"},
		"scopes_supported":                      []string{"mcp", "offline_access"},
		"token_endpoint_auth_methods_supported": []string{"none", "client_secret_post", "client_secret_basic"},
		// Advertised so that a client which prefers Client ID Metadata
		// Documents will choose them here. Both this and "none" above are
		// required before some clients will use CIMD at all.
		"client_id_metadata_document_supported": true,
	})
}

// ---------- dynamic client registration ----------

func (s *Server) register(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeErr(w, 405, "invalid_request", "POST required")
		return
	}
	var req map[string]any
	body, _ := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if err := json.Unmarshal(body, &req); err != nil {
		writeErr(w, 400, "invalid_client_metadata", "body is not JSON")
		return
	}
	var redirects []string
	if raw, ok := req["redirect_uris"].([]any); ok {
		for _, v := range raw {
			if s, ok := v.(string); ok {
				redirects = append(redirects, s)
			}
		}
	}
	if len(redirects) == 0 {
		writeErr(w, 400, "invalid_redirect_uri", "redirect_uris is required")
		return
	}
	name, _ := req["client_name"].(string)
	// A public client that asked for "none" and is handed a secret will not
	// use it, and the exchange then proves nothing about either method.
	authMethod, _ := req["token_endpoint_auth_method"].(string)
	if authMethod == "" {
		authMethod = "client_secret_post"
	}
	secret := token(24)
	if authMethod == "none" {
		secret = ""
	}

	c := &Client{
		ID:           "dcr_" + token(12),
		Secret:       secret,
		AuthMethod:   authMethod,
		Name:         name,
		RedirectURIs: redirects,
		Via:          "dcr",
		Registered:   time.Now(),
		Raw:          req,
	}
	s.store.mu.Lock()
	s.store.clients[c.ID] = c
	s.store.mu.Unlock()

	s.obs.Write("client_registered", map[string]any{
		"via":           "dcr",
		"client_id":     c.ID,
		"client_name":   name,
		"redirect_uris": redirects,
		"request":       redactJSON(req),
	})

	out := map[string]any{
		"client_id":                  c.ID,
		"client_id_issued_at":        c.Registered.Unix(),
		"redirect_uris":              redirects,
		"token_endpoint_auth_method": c.AuthMethod,
		"grant_types":                []string{"authorization_code", "refresh_token"},
		"response_types":             []string{"code"},
	}
	if c.Secret != "" {
		out["client_secret"] = c.Secret
		out["client_secret_expires_at"] = 0
	}
	writeJSON(w, 201, out)
}

// ---------- client id metadata documents ----------

// resolveCIMD fetches a URL-shaped client_id.
//
// A public endpoint that takes a URL from an unauthenticated caller and
// fetches it is a server-side request forgery primitive. A first attempt here
// resolved the host, checked the addresses, and then handed the name to an
// ordinary HTTP client that resolved it again — so the addresses that were
// checked were not the addresses that were connected to.
//
// Doing that properly needs address checking at dial time and a considered
// position on proxies. For a throwaway experiment the honest answer is not to
// do it properly but to not do it at all: only URLs the operator has named on
// the command line are fetched. Anything else is refused and recorded, which
// is itself an observation about which clients would have needed it.
func (s *Server) resolveCIMD(clientID string) (*Client, error) {
	u, err := url.Parse(clientID)
	if err != nil {
		return nil, fmt.Errorf("client_id is not a URL: %w", err)
	}
	if u.Scheme != "https" {
		return nil, fmt.Errorf("client_id must be https")
	}
	if u.Path == "" || u.Path == "/" {
		return nil, fmt.Errorf("client_id must have a path component")
	}
	if !s.cimdAllowed(clientID) {
		return nil, fmt.Errorf("client metadata document %q is not in -cimd-allow; "+
			"the spike will not fetch arbitrary URLs", clientID)
	}
	if err := guardHost(u.Hostname()); err != nil {
		return nil, err
	}

	cl := &http.Client{
		Timeout: 5 * time.Second,
		Transport: &http.Transport{
			// Defence in depth behind the allow list: check the address that
			// is actually dialled, not one resolved earlier and separately.
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				host, _, err := net.SplitHostPort(addr)
				if err != nil {
					return nil, err
				}
				if ip := net.ParseIP(host); ip != nil && !publicIP(ip) {
					return nil, fmt.Errorf("refusing to connect to non-public address %s", host)
				}
				return (&net.Dialer{Timeout: 3 * time.Second}).DialContext(ctx, network, addr)
			},
		},
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return fmt.Errorf("redirects are not followed when resolving client metadata")
		},
	}
	resp, err := cl.Get(clientID)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("metadata document returned %d", resp.StatusCode)
	}
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 256<<10))
	if err != nil {
		return nil, err
	}
	var doc map[string]any
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil, fmt.Errorf("metadata document is not JSON: %w", err)
	}
	if got, _ := doc["client_id"].(string); got != clientID {
		return nil, fmt.Errorf("metadata client_id %q does not match the document URL", got)
	}
	var redirects []string
	if arr, ok := doc["redirect_uris"].([]any); ok {
		for _, v := range arr {
			if s, ok := v.(string); ok {
				redirects = append(redirects, s)
			}
		}
	}
	if len(redirects) == 0 {
		return nil, fmt.Errorf("metadata document has no redirect_uris")
	}
	name, _ := doc["client_name"].(string)
	return &Client{
		ID:           clientID,
		Name:         name,
		RedirectURIs: redirects,
		AuthMethod:   "none", // CIMD clients authenticate as public clients
		Via:          "cimd",
		Registered:   time.Now(),
		Raw:          doc,
	}, nil
}

// cgnat is carrier-grade NAT space. None of net.IP's own predicates exclude
// it, so a check built from IsPrivate and friends lets it through.
var cgnat = net.IPNet{IP: net.IPv4(100, 64, 0, 0), Mask: net.CIDRMask(10, 32)}

func publicIP(ip net.IP) bool {
	if !ip.IsGlobalUnicast() || ip.IsPrivate() || ip.IsLoopback() ||
		ip.IsLinkLocalUnicast() || ip.IsInterfaceLocalMulticast() {
		return false
	}
	return !cgnat.Contains(ip)
}

func guardHost(host string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	ips, err := net.DefaultResolver.LookupIP(ctx, "ip", host)
	if err != nil {
		return fmt.Errorf("cannot resolve %s: %w", host, err)
	}
	for _, ip := range ips {
		if !publicIP(ip) {
			return fmt.Errorf("%s resolves to a non-public address", host)
		}
	}
	return nil
}

func (s *Server) cimdAllowed(clientID string) bool {
	for _, a := range s.cfg.CIMDAllow {
		if a == clientID {
			return true
		}
	}
	return false
}

// lookupClient resolves a client_id from either registration mechanism.
func (s *Server) lookupClient(clientID string) (*Client, error) {
	s.store.mu.Lock()
	c, ok := s.store.clients[clientID]
	s.store.mu.Unlock()
	if ok {
		return c, nil
	}
	if strings.HasPrefix(clientID, "https://") {
		c, err := s.resolveCIMD(clientID)
		if err != nil {
			s.obs.Write("cimd_rejected", map[string]any{"client_id": clientID, "error": err.Error()})
			return nil, err
		}
		s.store.mu.Lock()
		s.store.clients[c.ID] = c
		s.store.mu.Unlock()
		s.obs.Write("client_registered", map[string]any{
			"via":           "cimd",
			"client_id":     c.ID,
			"client_name":   c.Name,
			"redirect_uris": c.RedirectURIs,
			"document":      redactJSON(c.Raw),
		})
		return c, nil
	}
	return nil, fmt.Errorf("unknown client_id")
}

// redirectAllowed compares exactly, with the one documented exception for
// loopback redirects on an ephemeral port that native clients require.
func redirectAllowed(registered []string, presented string) (bool, string) {
	for _, r := range registered {
		if r == presented {
			return true, "exact"
		}
	}
	pu, err := url.Parse(presented)
	if err != nil {
		return false, ""
	}
	if pu.Hostname() != "localhost" && pu.Hostname() != "127.0.0.1" && pu.Hostname() != "::1" {
		return false, ""
	}
	// Only the port may differ. Query, fragment and userinfo are part of the
	// registered value and ignoring them would widen the exception well past
	// what RFC 8252 asks for.
	if pu.User != nil || pu.RawQuery != "" || pu.Fragment != "" {
		return false, ""
	}
	for _, r := range registered {
		ru, err := url.Parse(r)
		if err != nil || ru.User != nil || ru.RawQuery != "" || ru.Fragment != "" {
			continue
		}
		if ru.Scheme == pu.Scheme && ru.Hostname() == pu.Hostname() && ru.Path == pu.Path {
			return true, "loopback-port-ignored"
		}
	}
	return false, ""
}

// ---------- authorize ----------

var consentPage = template.Must(template.New("consent").Parse(`<!doctype html>
<meta charset="utf-8"><title>Authorize</title>
<style>body{font:15px system-ui;margin:0;display:grid;place-items:center;height:100vh;background:#faf9f7}
.card{max-width:30rem;padding:2rem;border:1px solid #ddd;border-radius:.75rem;background:#fff}
dt{font-weight:600;margin-top:.75rem}dd{margin:0;font-family:ui-monospace,monospace;word-break:break-all;color:#444}
button{margin-top:1.5rem;padding:.6rem 1.2rem;font-size:1rem;border:0;border-radius:.4rem;background:#1a1a1a;color:#fff}</style>
<div class="card">
<h1>Authorize this client?</h1>
<p>M0 spike. Identity is hard coded; nothing here is a real access decision.</p>
<dl>
<dt>Client</dt><dd>{{.ClientName}}</dd>
<dt>Client ID</dt><dd>{{.ClientID}}</dd>
<dt>Redirect URI</dt><dd>{{.RedirectURI}}</dd>
<dt>Resource</dt><dd>{{.Resource}}</dd>
<dt>Scope</dt><dd>{{.Scope}}</dd>
</dl>
<form method="POST" action="/consent">
<input type="hidden" name="rid" value="{{.RID}}">
<button type="submit">Approve</button>
</form>
</div>`))

type pendingAuth struct {
	q       url.Values
	client  *Client
	created time.Time
}

var pending = struct {
	mu sync.Mutex
	m  map[string]*pendingAuth
}{m: map[string]*pendingAuth{}}

func (s *Server) authorize(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()

	// Recorded before anything is validated: this is the observation the whole
	// experiment exists for.
	s.obs.Write("authorize_request", map[string]any{
		"client_id":             q.Get("client_id"),
		"redirect_uri":          q.Get("redirect_uri"),
		"response_type":         q.Get("response_type"),
		"scope":                 q.Get("scope"),
		"resource":              q.Get("resource"),
		"resource_present":      q.Has("resource"),
		"code_challenge_method": q.Get("code_challenge_method"),
		"has_code_challenge":    q.Has("code_challenge"),
		"has_state":             q.Has("state"),
		"all_params":            redactValues(q),
	})

	c, err := s.lookupClient(q.Get("client_id"))
	if err != nil {
		writeErr(w, 400, "invalid_client", err.Error())
		return
	}
	ok, how := redirectAllowed(c.RedirectURIs, q.Get("redirect_uri"))
	if !ok {
		s.obs.Write("redirect_uri_rejected", map[string]any{
			"presented": q.Get("redirect_uri"), "registered": c.RedirectURIs,
		})
		writeErr(w, 400, "invalid_request", "redirect_uri does not match a registered value")
		return
	}
	s.obs.Write("redirect_uri_accepted", map[string]any{"match": how, "uri": q.Get("redirect_uri")})

	if q.Get("code_challenge_method") != "S256" {
		s.redirectErr(w, r, q, "invalid_request", "PKCE S256 is required")
		return
	}

	rid := token(12)
	pending.mu.Lock()
	pending.m[rid] = &pendingAuth{q: q, client: c, created: time.Now()}
	pending.mu.Unlock()

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("X-Frame-Options", "DENY")
	consentPage.Execute(w, map[string]any{
		"ClientName":  firstNonEmpty(c.Name, "(unnamed)"),
		"ClientID":    c.ID,
		"RedirectURI": q.Get("redirect_uri"),
		"Resource":    firstNonEmpty(q.Get("resource"), "(not sent)"),
		"Scope":       firstNonEmpty(q.Get("scope"), "(none)"),
		"RID":         rid,
	})
}

func (s *Server) consent(w http.ResponseWriter, r *http.Request) {
	r.ParseForm()
	pending.mu.Lock()
	p := pending.m[r.FormValue("rid")]
	delete(pending.m, r.FormValue("rid"))
	pending.mu.Unlock()
	if p == nil {
		writeErr(w, 400, "invalid_request", "unknown or expired authorization request")
		return
	}
	q := p.q

	code := token(24)
	s.store.mu.Lock()
	s.store.codes[code] = &AuthCode{
		Code:                code,
		ClientID:            p.client.ID,
		RedirectURI:         q.Get("redirect_uri"),
		CodeChallenge:       q.Get("code_challenge"),
		CodeChallengeMethod: q.Get("code_challenge_method"),
		Resource:            q.Get("resource"),
		Scope:               q.Get("scope"),
		Expires:             time.Now().Add(5 * time.Minute),
	}
	s.store.mu.Unlock()

	s.obs.Write("consent_approved", map[string]any{
		"client_id": p.client.ID,
		"resource":  q.Get("resource"),
		"elapsed_s": time.Since(p.created).Seconds(),
	})

	u, _ := url.Parse(q.Get("redirect_uri"))
	rq := u.Query()
	rq.Set("code", code)
	if st := q.Get("state"); st != "" {
		rq.Set("state", st)
	}
	rq.Set("iss", s.issuer())
	u.RawQuery = rq.Encode()
	http.Redirect(w, r, u.String(), http.StatusFound)
}

func (s *Server) redirectErr(w http.ResponseWriter, r *http.Request, q url.Values, code, desc string) {
	u, err := url.Parse(q.Get("redirect_uri"))
	if err != nil {
		writeErr(w, 400, code, desc)
		return
	}
	rq := u.Query()
	rq.Set("error", code)
	rq.Set("error_description", desc)
	if st := q.Get("state"); st != "" {
		rq.Set("state", st)
	}
	u.RawQuery = rq.Encode()
	http.Redirect(w, r, u.String(), http.StatusFound)
}

// ---------- token ----------

func (s *Server) tokenEndpoint(w http.ResponseWriter, r *http.Request) {
	ct := r.Header.Get("Content-Type")
	if err := r.ParseForm(); err != nil {
		writeErr(w, 400, "invalid_request", "cannot parse body")
		return
	}
	s.obs.Write("token_request", map[string]any{
		"grant_type":       r.PostFormValue("grant_type"),
		"content_type":     ct,
		"resource":         r.PostFormValue("resource"),
		"resource_present": r.PostForm.Has("resource"),
		"scope":            r.PostFormValue("scope"),
		"client_auth":      clientAuthMethod(r),
		"form":             redactValues(r.PostForm),
	})

	switch r.PostFormValue("grant_type") {
	case "authorization_code":
		s.grantAuthorizationCode(w, r)
	case "refresh_token":
		s.grantRefresh(w, r)
	default:
		writeErr(w, 400, "unsupported_grant_type", "only authorization_code and refresh_token")
	}
}

// authenticateClient checks that the caller is the client the code was issued
// to, using the method that client registered with.
func (s *Server) authenticateClient(r *http.Request, wantID string) error {
	id, secret := r.PostFormValue("client_id"), r.PostFormValue("client_secret")
	if bid, bsecret, ok := r.BasicAuth(); ok {
		id, secret = bid, bsecret
	}
	if id == "" {
		return fmt.Errorf("client_id is required")
	}
	if id != wantID {
		return fmt.Errorf("client_id does not match the authorization request")
	}
	s.store.mu.Lock()
	c := s.store.clients[wantID]
	s.store.mu.Unlock()
	if c == nil {
		return fmt.Errorf("unknown client")
	}
	if c.AuthMethod == "none" {
		return nil
	}
	if secret == "" {
		return fmt.Errorf("client authentication is required for this client")
	}
	if subtle.ConstantTimeCompare([]byte(secret), []byte(c.Secret)) != 1 {
		return fmt.Errorf("client authentication failed")
	}
	return nil
}

func clientAuthMethod(r *http.Request) string {
	if _, _, ok := r.BasicAuth(); ok {
		return "client_secret_basic"
	}
	if r.PostFormValue("client_secret") != "" {
		return "client_secret_post"
	}
	return "none"
}

func (s *Server) grantAuthorizationCode(w http.ResponseWriter, r *http.Request) {
	code := r.PostFormValue("code")
	s.store.mu.Lock()
	ac := s.store.codes[code]
	delete(s.store.codes, code)
	s.store.mu.Unlock()

	if ac == nil || time.Now().After(ac.Expires) {
		writeErr(w, 400, "invalid_grant", "unknown or expired code")
		return
	}
	// A minimal server that skips these accepts a request a real one would
	// refuse, so a success here would say nothing about the real thing.
	if err := s.authenticateClient(r, ac.ClientID); err != nil {
		s.obs.Write("client_auth_failed", map[string]any{"client_id": ac.ClientID, "error": err.Error()})
		writeErr(w, 401, "invalid_client", err.Error())
		return
	}
	if res := r.PostFormValue("resource"); res != "" && ac.Resource != "" && res != ac.Resource {
		s.obs.Write("resource_mismatch", map[string]any{"authorize": ac.Resource, "token": res})
		writeErr(w, 400, "invalid_target", "resource does not match the authorization request")
		return
	}
	if ac.RedirectURI != r.PostFormValue("redirect_uri") {
		writeErr(w, 400, "invalid_grant", "redirect_uri does not match the authorization request")
		return
	}
	verifier := r.PostFormValue("code_verifier")
	sum := sha256.Sum256([]byte(verifier))
	if base64.RawURLEncoding.EncodeToString(sum[:]) != ac.CodeChallenge {
		s.obs.Write("pkce_failed", map[string]any{"client_id": ac.ClientID})
		writeErr(w, 400, "invalid_grant", "PKCE verification failed")
		return
	}

	sess := &Session{
		ID:           "sess_" + token(9),
		ClientID:     ac.ClientID,
		AccessToken:  token(32),
		RefreshToken: token(32),
		Resource:     ac.Resource,
		Scope:        ac.Scope,
		AccessExp:    time.Now().Add(s.cfg.AccessTTL),
		RefreshExp:   time.Now().Add(s.cfg.RefreshTTL),
	}
	s.store.mu.Lock()
	s.store.sessions[sess.ID] = sess
	s.store.byAccess[sess.AccessToken] = sess.ID
	s.store.byRefresh[sess.RefreshToken] = sess.ID
	s.store.mu.Unlock()

	s.obs.Write("session_issued", map[string]any{
		"session":      sess.ID,
		"client_id":    sess.ClientID,
		"resource":     sess.Resource,
		"access_ttl_s": s.cfg.AccessTTL.Seconds(),
		"access_fp":    Fingerprint(sess.AccessToken),
		"refresh_fp":   Fingerprint(sess.RefreshToken),
	})
	s.writeTokens(w, sess)
}

func (s *Server) grantRefresh(w http.ResponseWriter, r *http.Request) {
	rt := r.PostFormValue("refresh_token")

	s.mu.Lock()
	forced := s.forceInvalidGrant
	s.forceInvalidGrant = false
	s.mu.Unlock()
	if forced {
		s.obs.Write("refresh_forced_invalid_grant", map[string]any{"presented_fp": Fingerprint(rt)})
		writeErr(w, 400, "invalid_grant", "refresh token rejected on purpose (control)")
		return
	}

	// One critical section. Splitting the check from the consumption let two
	// concurrent refreshes both see a live token, and rotation is precisely
	// what this spike is meant to measure.
	s.store.mu.Lock()
	id, ok := s.store.byRefresh[rt]
	retiredFrom, wasRetired := s.store.retiredRefresh[rt]

	if wasRetired {
		s.store.mu.Unlock()
		// The observation that matters most about rotation: the client came
		// back with a token we already replaced.
		s.obs.Write("refresh_reuse_of_retired_token", map[string]any{
			"presented_fp": Fingerprint(rt), "session": retiredFrom,
		})
		writeErr(w, 400, "invalid_grant", "refresh token already used")
		return
	}
	if !ok {
		s.store.mu.Unlock()
		writeErr(w, 400, "invalid_grant", "unknown refresh token")
		return
	}

	sess := s.store.sessions[id]
	if sess == nil || sess.Revoked || time.Now().After(sess.RefreshExp) {
		s.store.mu.Unlock()
		writeErr(w, 400, "invalid_grant", "session is over")
		return
	}
	if sess.RefreshToken != rt {
		// Lost a race with another refresh for the same session.
		s.store.mu.Unlock()
		s.obs.Write("refresh_lost_race", map[string]any{"session": id})
		writeErr(w, 400, "invalid_grant", "refresh token is no longer current")
		return
	}
	sinceExpiry := time.Since(sess.AccessExp)
	delete(s.store.byAccess, sess.AccessToken)
	delete(s.store.byRefresh, sess.RefreshToken)
	s.store.retiredRefresh[sess.RefreshToken] = sess.ID
	sess.AccessToken = token(32)
	sess.RefreshToken = token(32)
	sess.AccessExp = time.Now().Add(s.cfg.AccessTTL)
	sess.Generation++
	s.store.byAccess[sess.AccessToken] = sess.ID
	s.store.byRefresh[sess.RefreshToken] = sess.ID
	// An immutable snapshot for the response and the log, taken while the lock
	// is still held: reading sess afterwards races a concurrent refresh and
	// would corrupt the generation and fingerprint comparison.
	snap := *sess
	s.store.mu.Unlock()
	sess = &snap

	// A negative value means the client refreshed before the token expired.
	// That number answers "does it refresh proactively, and how early?".
	s.obs.Write("refresh_rotated", map[string]any{
		"session":                    sess.ID,
		"generation":                 sess.Generation,
		"seconds_past_access_expiry": sinceExpiry.Seconds(),
		"new_access_fp":              Fingerprint(sess.AccessToken),
		"new_refresh_fp":             Fingerprint(sess.RefreshToken),
	})
	s.writeTokens(w, sess)
}

func (s *Server) writeTokens(w http.ResponseWriter, sess *Session) {
	writeJSON(w, 200, map[string]any{
		"access_token":  sess.AccessToken,
		"token_type":    "Bearer",
		"expires_in":    int(time.Until(sess.AccessExp).Seconds()),
		"refresh_token": sess.RefreshToken,
		"scope":         sess.Scope,
	})
}

func (s *Server) revoke(w http.ResponseWriter, r *http.Request) {
	r.ParseForm()
	t := r.PostFormValue("token")
	s.store.mu.Lock()
	id, ok := s.store.byAccess[t]
	if !ok {
		id, ok = s.store.byRefresh[t]
	}
	if ok {
		if sess := s.store.sessions[id]; sess != nil {
			sess.Revoked = true
		}
	}
	s.store.mu.Unlock()
	s.obs.Write("revoke", map[string]any{"known": ok, "session": id, "token_fp": Fingerprint(t)})
	w.WriteHeader(200)
}

// ---------- helpers ----------

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}

func writeErr(w http.ResponseWriter, status int, code, desc string) {
	writeJSON(w, status, map[string]any{"error": code, "error_description": desc})
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}
