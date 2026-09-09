# M0 — observations

What a real MCP client actually did, recorded against the spike in `spike/m0`. This is the
deliverable of the gate; the spike is not.

**Run:** 2026-09-09, `spike/m0` at commit `4296eff` and later.
**Client:** Claude Code 2.1.266–2.1.267, a **native** client running on the operator's own machine.
**Server:** the M0 spike — an authorization server of our own, no upstream identity provider,
identity hard coded, no policy.

Everything below is what was observed. Where something was not observed, it says so, and where
the rig cannot produce it at all, it says that instead — those are different findings.

## Status of the gate

**M0 is not passed.** Experiment B (client → our own authorization server → tool call) is
complete. Experiment A (client → identity provider directly → resource server) has not been
attempted, because it needs a tenant that does not exist yet. A hosted connector has also not been
observed; only the native profile has. See `m0-gate.md` for what those omissions do and do not
license.

## What was observed

### Client registration — CIMD, not DCR

The client registered by **Client ID Metadata Document**, presenting
`https://claude.ai/oauth/claude-code-client-metadata` as its `client_id`. The fetched document
named the client "Claude Code", declared `token_endpoint_auth_method: none`, and listed exactly two
redirect URIs, both port-less: `http://localhost/callback` and `http://127.0.0.1/callback`.

This matters beyond configuration. The original brief argued that MCP clients "go looking for
Dynamic Client Registration first", and used that as one of three reasons an identity provider
without DCR could not be used. The live client chose CIMD. Implementing both mechanisms, rather
than only the one the brief predicted, is what made this observable — had the spike offered DCR
alone, the client would have used DCR and the observation would have been a self-fulfilling
falsehood.

### The authorization request

One request answered four questions at once:

| | |
| --- | --- |
| `resource` | **Sent**, on both `/authorize` and `/token`, as the canonical MCP endpoint URL |
| `scope` | `mcp offline_access` — the client **appended `offline_access` itself** |
| PKCE | `code_challenge_method=S256`, `state` present |
| `redirect_uri` | `http://localhost:57104/callback` — an ephemeral port |

The redirect URI exercised the loopback exception: the registered value has no port, the presented
one does. The spike accepted it as `loopback-port-ignored` and recorded that it did so by the
exception rather than by exact match.

At the token endpoint the client authenticated as a **public client** (`client_auth: none`),
consistent with its metadata document, and sent the body as
`application/x-www-form-urlencoded`.

### Transport

- Protocol version **`2026-07-28`** — the revision that removed protocol-level sessions and the
  GET stream.
- The first method is **`server/discover`**, not `initialize`. There is no handshake.
- `Mcp-Method` was present on every request and **agreed with the body method** every time.
  `Mcp-Name: whoami` was present on the tool call and agreed with the body's tool name.
- No `Mcp-Session-Id` was ever sent, consistent with that revision having no protocol sessions.
- `Accept: application/json, text/event-stream` on every request.

One discrepancy, recorded without an explanation: the MCP request declared `2026-07-28`, while the
OAuth discovery requests that followed it carried `Mcp-Protocol-Version: 2025-11-25`.

Discovery used the **path-suffixed** protected-resource metadata path
(`/.well-known/oauth-protected-resource/mcp`) as well as the bare one.

### Result schemas — three refusals, each one instructive

The client rejected three successive results and named the rule each time. This is the clearest
demonstration in the run of why M0 is a gate: none of these came out of reading the
specification's examples.

1. `tools/list` without `resultType` — "servers implementing protocol revision 2026-07-28 MUST
   include it".
2. Then, with `resultType` but without `ttlMs` and `cacheScope` — both required, `cacheScope`
   constrained to `public` or `private`.
3. `server/discover` was accepted throughout.

The second is worth carrying into the design. The protocol **forces a server to declare the cache
scope of a tool list**. A list filtered by the caller's entitlement is not publicly cacheable, so
the requirement is a safeguard rather than a nuisance — see `architecture.md` and [R23].

### Token lifecycle

| Event | Observed |
| --- | --- |
| Access token expires (forced server-side) | Client receives `401`, refreshes, retries, succeeds. Transparent to the caller. |
| `401` on a still-valid token | Same: refresh, retry, success. The client does not surface an error. |
| Refresh token rotation | Adopted immediately. Across four rotations the client **never once replayed a retired refresh token**. |
| Refresh refused with `invalid_grant` | Client stops and reports "needs authentication" to the user. It does not loop, hang, or retry indefinitely. |
| Unknown token after a server restart | `401` → refresh attempt → `invalid_grant` → reports to the user. |
| **Proactive refresh, before a client-known expiry** | Observed, and measured: the client refreshed **288.7 seconds — 4 min 49 s — before expiry**, with no `401` anywhere in the exchange. |

One-time refresh rotation is therefore safe with this client, which is the property the design
depends on.

Measuring the proactive case needed a separate run, because a server-forced expiry does not
reach the client: the token it holds still looks valid to it, so what that measures is the
reaction to an unexpected `401`. To see the other behaviour the token lifetime was set to six
minutes and left alone — the documented proactive window is up to five minutes before expiry, so
the first call after the first minute falls inside it. It did, and the measured −288.7 s sits just
inside the documented five. These are two different behaviours and the log distinguishes them.

A consequence for the real gateway: an access token lifetime at or below five minutes would be
refreshed essentially on issue, so the shortest useful lifetime is bounded by the client's
refresh window, not by our preference.

## What was not observed, and why

- **Experiment A**, the direct path to an identity provider. Blocked on a tenant.
- **A hosted connector.** Only the native profile was exercised. The two differ in where the
  connection originates, in the redirect URI, and in the exposure required.

## What the rig cannot answer at all

Recording these as "the client did not do it" would be false:

- **Streaming.** The spike never opens an SSE response, so nothing here observes long-lived
  streams or what a client does when one is interrupted.
- **Cancellation across a proxy hop.** There is no separate backend; the spike answers requests
  itself. Whether closing a client stream propagates to a backend request, and whether the backend
  then stops work, is untestable without a controlled streaming fixture behind a real proxy.
- **Any other backend's header/body contract.** The spike validates headers against the body and
  refuses a mismatch, as a server processing the body must. That says nothing about whether some
  other backend does — and it is precisely that unknown which decides whether per-tool policy can
  ever be enforced from headers. See `security-model.md`.

## Consequences for the design

1. **CIMD is not optional.** The gateway must implement it, not merely DCR. A client that prefers
   it will use it, and an admission policy over trusted client URLs is what answers the "anyone can
   register" objection.
2. **The loopback exception is exercised in practice**, not hypothetically. Whether the gateway
   serves native clients at all is a live decision, not a formality — `open-questions.md` Q7.
3. **`resource` arrives and is usable.** The per-resource binding the design depends on can be
   recorded at issuance, because the client supplies it on both requests.
4. **Refresh rotation is safe.** One-time rotation caused no failure across four rotations.
5. **A filtered tool list carries cache obligations.** The gateway cannot rewrite `tools/list`
   without owning `cacheScope`.
6. **The transport revision in the field is `2026-07-28`.** Any assumption based on
   `Mcp-Session-Id` or a GET stream is about a different revision — `open-questions.md` Q3.
