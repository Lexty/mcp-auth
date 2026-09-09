# M0 spike

Throwaway. This is not a design for the gateway and no part of it should be promoted into one —
see `docs/m0-gate.md` for why M0 is a gate rather than a first sprint.

A minimal OAuth 2.1 authorization server plus a one-tool MCP endpoint. Identity is hard coded,
there is no upstream identity provider, there is no policy, and all state is in memory. Its output
is the JSONL observation log, not this program.

## What it is instrumented to answer

The mandatory observations in `docs/m0-gate.md`, each produced deliberately rather than waited for:

| Observation | How to produce it |
| --- | --- |
| Which registration mechanism the client picks | Both are offered; the log records `client_registered` with `via: dcr` or `via: cimd` |
| Whether `resource` is sent, and with what value | `authorize_request` and `token_request` record it and whether it was present at all |
| Which scopes are requested, and whether `offline_access` is appended | `authorize_request.scope` |
| PKCE method | `authorize_request.code_challenge_method` |
| Behaviour at access token expiry | `POST /control/expire-access`, then watch for `token_expired` and a refresh |
| Behaviour on `401` | `POST /control/force-401` |
| Whether a rotated refresh token is adopted | `refresh_rotated` gives the new fingerprint; `refresh_reuse_of_retired_token` fires if the client comes back with the old one |
| Behaviour on a refused refresh | `POST /control/invalidate-refresh`, then watch whether the client re-authorises cleanly or the connection stays stuck |
| Whether the transport headers agree with the body | `mcp_transport` on every request, `header_body_mismatch` when they disagree |
| Which transport revision is spoken | `mcp_transport.protocol_version`, and `mcp_legacy_method` if the client tries GET or DELETE |

`refresh_rotated.seconds_past_access_expiry` is the one number worth watching: negative means the
client refreshed *before* expiry, and its magnitude is how early.

## Secrets in the log

Tokens, codes, verifiers and client secrets are never written. They are replaced by a truncated
SHA-256 fingerprint plus a length, which is enough to tell "the same token again" from "a new one"
— the distinction the rotation observations depend on — without storing anything reusable. Bodies
of content types the redactor does not understand are recorded as a byte count, never echoed.

`go test ./spike/m0` is mostly tests of exactly that. It is the only part of a throwaway program
worth testing, because the log is meant to be pasted into a report.

## Running it

The client connects from its vendor's cloud over the public internet, so the spike needs a public
HTTPS URL with a globally routable address. It listens on loopback and expects a tunnel in front.

```sh
go run ./spike/m0 -public-url https://YOUR-STABLE-HOST -obs m0-observations.jsonl
# in another shell, point a tunnel at 127.0.0.1:8420
```

**Use a stable hostname.** A connector's authentication settings cannot be changed after it is
created, so a tunnel that hands out a fresh URL on every restart means recreating the connector
every time. Reserve a fixed domain before the first run.

Flags worth knowing:

- `-access-ttl` (default 5m) — short on purpose, so expiry behaviour is observed early.
- `-listen` (default `127.0.0.1:8420`) — the tunnel's target.
- `-admin` (default `127.0.0.1:8421`) — control endpoints. Loopback only; never expose it.
- `-mcp-path` (default `/mcp`) — the MCP endpoint. The registered connector URL must be
  `<public-url><mcp-path>` exactly, with no trailing slash.

Control endpoints, all on the admin listener:

```
POST /control/expire-access       expire every access token now
POST /control/force-401           answer the next MCP request 401
POST /control/invalidate-refresh  refuse the next refresh with invalid_grant
POST /control/revoke-all          revoke every session
GET  /state                       clients and sessions, fingerprints only
```

## After a run

The log is the deliverable. Record what was observed separately from what it is thought to mean,
and mark branches that did not occur as not observed — an absent branch is a finding, not a blank.
