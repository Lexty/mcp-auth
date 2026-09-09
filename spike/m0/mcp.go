package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

// A minimal MCP endpoint with one tool. It answers both shapes of the
// transport — the older initialize handshake and the newer per-request
// metadata form — because which one the client speaks is one of the things M0
// has to find out rather than assume.

type rpcReq struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
}

func (s *Server) mcp(w http.ResponseWriter, r *http.Request) {
	// Record the transport-level facts before anything else: these decide
	// whether per-tool policy can ever be enforced from headers.
	s.obs.Write("mcp_transport", map[string]any{
		"protocol_version": r.Header.Get("MCP-Protocol-Version"),
		"mcp_method":       r.Header.Get("Mcp-Method"),
		"mcp_name":         r.Header.Get("Mcp-Name"),
		"session_id":       r.Header.Get("Mcp-Session-Id"),
		"accept":           r.Header.Get("Accept"),
		"http_method":      r.Method,
	})

	if r.Method == http.MethodGet || r.Method == http.MethodDelete {
		// Older revisions use these; newer ones do not. Answering 405 and
		// recording it tells us which era the client believes it is in.
		s.obs.Write("mcp_legacy_method", map[string]any{"method": r.Method})
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	sess, ok := s.authorizeRequest(w, r)
	if !ok {
		return
	}

	body, _ := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	var req rpcReq
	if err := json.Unmarshal(body, &req); err != nil {
		http.Error(w, "bad JSON-RPC", http.StatusBadRequest)
		return
	}

	// Whether the mirrored header agrees with the body is the question that
	// decides if header-based policy is safe anywhere. The specification puts
	// that check on the server that processes the body, and requires it to
	// reject — recording the disagreement and then serving the request would
	// have made the spike itself the vulnerable backend it warns about.
	if h := r.Header.Get("Mcp-Method"); h != "" && h != req.Method {
		s.obs.Write("header_body_mismatch", map[string]any{
			"exchange": Exchange(r.Context()), "header_method": h, "body_method": req.Method,
		})
		writeRPCErrStatus(w, req.ID, http.StatusBadRequest, -32020,
			fmt.Sprintf("Header mismatch: Mcp-Method %q does not match body method %q", h, req.Method), nil)
		return
	}
	// The version is declared in two places and they must agree, for the same
	// reason.
	if hv, bv := r.Header.Get("MCP-Protocol-Version"), metaVersion(req.Params); hv != "" && bv != "" && hv != bv {
		s.obs.Write("version_header_body_mismatch", map[string]any{"header": hv, "meta": bv})
		writeRPCErrStatus(w, req.ID, http.StatusBadRequest, -32020,
			"Header mismatch: MCP-Protocol-Version does not match _meta", nil)
		return
	}

	// Reject an unsupported version the way the specification requires, so that
	// a client's retry behaviour is observable rather than guessed at.
	if v := r.Header.Get("MCP-Protocol-Version"); v != "" && !supported(v) {
		s.obs.Write("unsupported_protocol_version", map[string]any{"requested": v})
		writeRPCErrStatus(w, req.ID, http.StatusBadRequest, -32022, "Unsupported protocol version",
			map[string]any{"supported": supportedVersions, "requested": v})
		return
	}

	switch req.Method {
	case "server/discover":
		// Mandatory in the modern era, and the first thing a modern client
		// sends. The spike answers as dual-era so that whichever way the
		// client goes is observable.
		s.obs.Write("mcp_discover", map[string]any{
			"session": sess.ID, "client_declared_version": r.Header.Get("MCP-Protocol-Version"),
			"params": redactJSON(rawAny(req.Params)),
		})
		writeRPC(w, req.ID, map[string]any{
			"resultType":        "complete",
			"supportedVersions": supportedVersions,
			"capabilities":      map[string]any{"tools": map[string]any{}},
			"instructions":      "M0 spike. One tool, hard coded identity, no policy.",
			"_meta": map[string]any{
				"io.modelcontextprotocol/serverInfo": map[string]any{"name": "m0-spike", "version": "0"},
			},
		})
	case "initialize":
		s.obs.Write("mcp_initialize", map[string]any{"session": sess.ID, "params": redactJSON(rawAny(req.Params))})

		// Answer without minting a session id: whether the client then insists
		// on one is itself an observation.
		writeRPC(w, req.ID, map[string]any{
			"protocolVersion": "2025-06-18",
			"capabilities":    map[string]any{"tools": map[string]any{}},
			"serverInfo":      map[string]any{"name": "m0-spike", "version": "0"},
		})
		s.obs.Write("mcp_era", map[string]any{"era": "legacy", "session": sess.ID})
	case "notifications/initialized":
		w.WriteHeader(http.StatusAccepted)
	case "tools/list":
		writeRPC(w, req.ID, map[string]any{"tools": []any{map[string]any{
			"name":        "whoami",
			"description": "Returns the identity the gateway spike believes is calling.",
			"inputSchema": map[string]any{"type": "object", "properties": map[string]any{}},
		}}})
	case "tools/call":
		var p struct {
			Name string `json:"name"`
		}
		json.Unmarshal(req.Params, &p)
		s.obs.Write("tool_called", map[string]any{
			"exchange": Exchange(r.Context()),
			"session":  sess.ID, "tool": p.Name, "header_name": r.Header.Get("Mcp-Name"),
		})
		if h := r.Header.Get("Mcp-Name"); h != "" && h != p.Name {
			s.obs.Write("header_body_mismatch", map[string]any{
				"header_name": h, "body_name": p.Name,
			})
			writeRPCErrStatus(w, req.ID, http.StatusBadRequest, -32020,
				fmt.Sprintf("Header mismatch: Mcp-Name %q does not match body name %q", h, p.Name), nil)
			return
		}
		if p.Name != "whoami" {
			// Returning whoami for any name would mean the spike could not
			// tell a policy question from a typo.
			writeRPCErr(w, req.ID, -32602, "unknown tool: "+p.Name)
			return
		}
		writeRPC(w, req.ID, map[string]any{"content": []any{map[string]any{
			"type": "text",
			"text": fmt.Sprintf("subject=%s session=%s generation=%d resource=%s",
				s.cfg.Identity, sess.ID, sess.Generation, sess.Resource),
		}}})
	default:
		writeRPCErr(w, req.ID, -32601, "method not found: "+req.Method)
	}
}

// authorizeRequest is the whole access decision in the spike: a valid,
// unexpired, unrevoked token. No policy, no roles, no upstream.
func (s *Server) authorizeRequest(w http.ResponseWriter, r *http.Request) (*Session, bool) {
	s.mu.Lock()
	forced := s.force401
	s.force401 = false
	s.mu.Unlock()
	if forced {
		s.obs.Write("forced_401", nil)
		s.challenge(w, "forced by control endpoint")
		return nil, false
	}

	auth := r.Header.Get("Authorization")
	if len(auth) < 8 || auth[:7] != "Bearer " {
		s.obs.Write("unauthenticated_request", map[string]any{"had_authorization": auth != ""})
		s.challenge(w, "no bearer token")
		return nil, false
	}
	tok := auth[7:]

	s.store.mu.Lock()
	id, ok := s.store.byAccess[tok]
	var sess *Session
	if ok {
		sess = s.store.sessions[id]
	}
	s.store.mu.Unlock()

	switch {
	case sess == nil:
		s.obs.Write("token_unknown", map[string]any{"token_fp": Fingerprint(tok)})
		s.challenge(w, "unknown token")
		return nil, false
	case sess.Revoked:
		s.obs.Write("token_revoked", map[string]any{"session": sess.ID})
		s.challenge(w, "session revoked")
		return nil, false
	case time.Now().After(sess.AccessExp):
		s.obs.Write("token_expired", map[string]any{
			"session": sess.ID, "expired_s_ago": time.Since(sess.AccessExp).Seconds(),
		})
		s.challenge(w, "token expired")
		return nil, false
	}
	return sess, true
}

// challenge returns the 401 that starts discovery. The header must point at
// the protected resource metadata, and the status must be 401 — a client will
// not read this header off a 200.
func (s *Server) challenge(w http.ResponseWriter, why string) {
	w.Header().Set("WWW-Authenticate",
		fmt.Sprintf(`Bearer resource_metadata=%q`, s.issuer()+"/.well-known/oauth-protected-resource"))
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusUnauthorized)
	json.NewEncoder(w).Encode(map[string]any{"error": "unauthorized", "detail": why})
}

func writeRPC(w http.ResponseWriter, id json.RawMessage, result any) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{"jsonrpc": "2.0", "id": rawOrNull(id), "result": result})
}

// supportedVersions is deliberately dual-era: the spike should be able to talk
// to whatever turns up, because which era a client uses is an observation.
var supportedVersions = []string{"2026-07-28", "2025-11-25", "2025-06-18"}

func supported(v string) bool {
	for _, s := range supportedVersions {
		if s == v {
			return true
		}
	}
	return false
}

// An unknown method is a 404 with -32601 in the modern revision, which is what
// distinguishes it from a legacy server that does not host this endpoint.
func writeRPCErr(w http.ResponseWriter, id json.RawMessage, code int, msg string) {
	writeRPCErrStatus(w, id, http.StatusNotFound, code, msg, nil)
}

func writeRPCErrStatus(w http.ResponseWriter, id json.RawMessage, status, code int, msg string, data any) {
	e := map[string]any{"code": code, "message": msg}
	if data != nil {
		e["data"] = data
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(map[string]any{"jsonrpc": "2.0", "id": rawOrNull(id), "error": e})
}

func rawOrNull(id json.RawMessage) any {
	if len(id) == 0 {
		return nil
	}
	return id
}

// metaVersion reads the protocol version a modern client puts in _meta, so it
// can be compared with the header that mirrors it.
func metaVersion(params json.RawMessage) string {
	var p struct {
		Meta map[string]any `json:"_meta"`
	}
	if json.Unmarshal(params, &p) != nil {
		return ""
	}
	v, _ := p.Meta["io.modelcontextprotocol/protocolVersion"].(string)
	return v
}

func rawAny(b json.RawMessage) any {
	var v any
	json.Unmarshal(b, &v)
	return v
}
