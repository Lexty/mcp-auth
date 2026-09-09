// Command m0-spike is the throwaway experiment for milestone M0.
//
// It is a minimal OAuth 2.1 authorization server plus a one-tool MCP endpoint,
// with identity hard coded and no upstream identity provider. Its output is
// not this program but the JSONL observation log it writes: what a real MCP
// client sends, in what order, and how it behaves at expiry, on 401, and on a
// refused refresh.
//
// Nothing here is a design for the real gateway. See docs/m0-gate.md.
package main

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"
)

type Config struct {
	PublicURL  string
	Listen     string
	Admin      string
	MCPPath    string
	ObsPath    string
	AccessTTL  time.Duration
	RefreshTTL time.Duration
	Identity   string
	StatePath  string
	CIMDAllow  []string
	ControlKey string
}

func isLoopbackURL(raw string) bool {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "http" {
		return false
	}
	h := u.Hostname()
	return h == "localhost" || h == "127.0.0.1" || h == "::1"
}

func main() {
	var cfg Config
	flag.StringVar(&cfg.PublicURL, "public-url", "", "public HTTPS base URL the client will reach, e.g. https://name.example.com (required)")
	flag.StringVar(&cfg.Listen, "listen", "127.0.0.1:8420", "local address for the public-facing handler, to be fronted by a tunnel")
	flag.StringVar(&cfg.Admin, "admin", "127.0.0.1:8421", "loopback address for control endpoints; never expose this")
	flag.StringVar(&cfg.MCPPath, "mcp-path", "/mcp", "path of the MCP endpoint")
	flag.StringVar(&cfg.ObsPath, "obs", "m0-observations.jsonl", "observation log")
	// A client may refresh proactively up to five minutes before expiry, so a
	// lifetime at or below that leaves no window in which the token is both
	// live and near expiry — natural expiry behaviour would never be seen.
	flag.DurationVar(&cfg.AccessTTL, "access-ttl", 10*time.Minute, "access token lifetime; must exceed the client's proactive refresh window to observe natural expiry")
	flag.DurationVar(&cfg.RefreshTTL, "refresh-ttl", 24*time.Hour, "refresh token lifetime")
	flag.StringVar(&cfg.StatePath, "state", ".m0/state.json", "where to keep clients and sessions across restarts; holds live tokens in the clear, mode 0600. Empty disables it")
	flag.StringVar(&cfg.Identity, "identity", "m0-hardcoded-subject", "the hard coded identity this spike claims")
	flag.Func("cimd-allow", "exact client metadata document URL the spike may fetch (repeatable); anything else is refused", func(v string) error {
		cfg.CIMDAllow = append(cfg.CIMDAllow, v)
		return nil
	})
	flag.Parse()

	if cfg.PublicURL == "" {
		fmt.Fprintln(os.Stderr, "-public-url is required: the client reaches this server from the internet,\nand the URL is baked into the OAuth metadata it discovers.")
		os.Exit(2)
	}
	// HTTPS is required, with the loopback exception OAuth 2.1 already makes.
	// That exception is what lets a native client on this machine drive the
	// spike with no tunnel at all, which is the cheapest first observation
	// available and needs no accounts.
	if !strings.HasPrefix(cfg.PublicURL, "https://") && !isLoopbackURL(cfg.PublicURL) {
		fmt.Fprintln(os.Stderr, "-public-url must be https, or http on a loopback host for a local client")
		os.Exit(2)
	}

	obs, err := NewObs(cfg.ObsPath)
	if err != nil {
		log.Fatalf("cannot open observation log: %v", err)
	}
	defer obs.Close()

	// The control endpoints change the experiment. Loopback alone does not
	// keep a web page from reaching them, so they need a key and a method.
	cfg.ControlKey = token(16)
	s := &Server{cfg: cfg, obs: obs, store: NewStore()}
	if err := s.store.Load(cfg.StatePath); err != nil {
		log.Fatalf("cannot read %s: %v", cfg.StatePath, err)
	}
	log.Printf("control key: %s", cfg.ControlKey)
	obs.Write("spike_started", map[string]any{
		"public_url": cfg.PublicURL, "mcp_path": cfg.MCPPath,
		"access_ttl_s": cfg.AccessTTL.Seconds(), "resource": s.resourceURL(),
	})

	pub := http.NewServeMux()
	pub.HandleFunc("/.well-known/oauth-protected-resource", s.protectedResourceMetadata)
	// Some clients probe the path-suffixed form first when the MCP endpoint has
	// a path component. Serving both, and observing which was used, is cheaper
	// than guessing.
	pub.HandleFunc("/.well-known/oauth-protected-resource/", s.protectedResourceMetadata)
	pub.HandleFunc("/.well-known/oauth-authorization-server", s.authorizationServerMetadata)
	pub.HandleFunc("/.well-known/oauth-authorization-server/", s.authorizationServerMetadata)
	pub.HandleFunc("/.well-known/openid-configuration", s.authorizationServerMetadata)
	pub.HandleFunc("/register", s.register)
	pub.HandleFunc("/authorize", s.authorize)
	pub.HandleFunc("/consent", s.consent)
	pub.HandleFunc("/token", s.tokenEndpoint)
	pub.HandleFunc("/revoke", s.revoke)
	pub.HandleFunc(cfg.MCPPath, s.mcp)
	// Anything else is recorded too: an unexpected probe is a finding.
	pub.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		obs.Write("unrouted_request", map[string]any{"method": r.Method, "path": r.URL.Path})
		http.NotFound(w, r)
	})

	// control guards every control endpoint: POST only, a key, and no browser
	// origin. A GET from a page the operator happens to have open would
	// otherwise silently alter a run.
	control := func(name string, fn func(w http.ResponseWriter, r *http.Request)) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			if r.Method != http.MethodPost {
				http.Error(w, "POST required", http.StatusMethodNotAllowed)
				return
			}
			if r.Header.Get("Origin") != "" || r.Header.Get("Sec-Fetch-Site") != "" {
				obs.Write("control_rejected", map[string]any{"endpoint": name, "reason": "browser origin"})
				http.Error(w, "not callable from a browser", http.StatusForbidden)
				return
			}
			if subtle.ConstantTimeCompare([]byte(r.Header.Get("X-Control-Key")), []byte(cfg.ControlKey)) != 1 {
				obs.Write("control_rejected", map[string]any{"endpoint": name, "reason": "bad key"})
				http.Error(w, "X-Control-Key required", http.StatusForbidden)
				return
			}
			fn(w, r)
		}
	}

	adm := http.NewServeMux()
	adm.HandleFunc("/control/force-401", control("force-401", func(w http.ResponseWriter, r *http.Request) {
		s.mu.Lock()
		s.force401 = true
		s.mu.Unlock()
		fmt.Fprintln(w, "next MCP request will be answered 401")
	}))
	adm.HandleFunc("/control/invalidate-refresh", control("invalidate-refresh", func(w http.ResponseWriter, r *http.Request) {
		s.mu.Lock()
		s.forceInvalidGrant = true
		s.mu.Unlock()
		fmt.Fprintln(w, "next refresh will be refused with invalid_grant")
	}))
	adm.HandleFunc("/control/expire-access", control("expire-access", func(w http.ResponseWriter, r *http.Request) {
		n := 0
		s.store.mu.Lock()
		for _, sess := range s.store.sessions {
			sess.AccessExp = time.Now().Add(-time.Second)
			n++
		}
		s.store.mu.Unlock()
		obs.Write("access_tokens_expired_by_control", map[string]any{"sessions": n})
		fmt.Fprintf(w, "expired %d session(s)\n", n)
	}))
	adm.HandleFunc("/control/revoke-all", control("revoke-all", func(w http.ResponseWriter, r *http.Request) {
		n := 0
		s.store.mu.Lock()
		for _, sess := range s.store.sessions {
			sess.Revoked = true
			n++
		}
		s.store.mu.Unlock()
		obs.Write("sessions_revoked_by_control", map[string]any{"sessions": n})
		fmt.Fprintf(w, "revoked %d session(s)\n", n)
	}))
	adm.HandleFunc("/state", control("state", func(w http.ResponseWriter, r *http.Request) {
		s.store.mu.Lock()
		defer s.store.mu.Unlock()
		clients := []any{}
		for _, c := range s.store.clients {
			clients = append(clients, map[string]any{
				"client_id": c.ID, "name": c.Name, "via": c.Via, "redirect_uris": c.RedirectURIs,
			})
		}
		sessions := []any{}
		for _, x := range s.store.sessions {
			sessions = append(sessions, map[string]any{
				"session": x.ID, "client_id": x.ClientID, "generation": x.Generation,
				"revoked": x.Revoked, "access_expires": x.AccessExp.UTC(),
				"access_fp": Fingerprint(x.AccessToken), "refresh_fp": Fingerprint(x.RefreshToken),
			})
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{"clients": clients, "sessions": sessions})
	}))

	pubSrv := &http.Server{Addr: cfg.Listen, Handler: obs.Middleware(pub)}
	admSrv := &http.Server{Addr: cfg.Admin, Handler: adm}

	go func() {
		log.Printf("public handler on %s, advertising %s", cfg.Listen, cfg.PublicURL)
		if err := pubSrv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatal(err)
		}
	}()
	go func() {
		log.Printf("control endpoints on %s (loopback only)", cfg.Admin)
		if err := admSrv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatal(err)
		}
	}()

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)
	<-stop
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	pubSrv.Shutdown(ctx)
	admSrv.Shutdown(ctx)
	if err := s.store.Save(cfg.StatePath); err != nil {
		log.Printf("could not save state: %v", err)
	}
	obs.Write("spike_stopped", nil)
	log.Printf("observations written to %s", cfg.ObsPath)
}
