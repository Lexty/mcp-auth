# Brief — a universal authorization gateway for MCP servers

> **About this document. It is historical, and it is not normative.** This is the original
> requirement brief, translated into English and de-branded: organisation-specific names,
> repositories and deployment details have been generalised. It is preserved as the statement of
> intent, exactly as written.
>
> Where it disagrees with any other document here, the other document wins. It contains
> requirements that validation refuted, arguments that no longer hold, and provider-specific
> assumptions that must not be read as applying to every upstream. Inline notes mark the largest
> divergences, but they are not exhaustive — treat the whole document as a record of what was asked
> for, not as a specification of what is being built.
>
> **Its section "Context that is not in the code" is partly superseded.** Two of the three claims
> there were refuted against primary sources during validation. Read `validation.md` before acting
> on anything in that section. The body of this document is deliberately left as written rather
> than silently corrected, so that the reasoning trail stays intact.

## What we are making

A small reverse proxy that sits in front of **any** MCP server (Streamable HTTP) and takes on
everything to do with "who is asking, and what are they allowed to do". The MCP server itself
knows nothing about authorization and is not exposed: the gateway is the only public process, and
the backend listens only on loopback or a private network address.

Universality here means exactly one thing: the gateway does not know what server is behind it.
Documentation, log access, query tools, anything at all — that is configuration, not code. The
first consumer is a documentation server that today understands only a single shared bearer token.

The main goal is not technical. **Security engineers must be able to trust this and to operate
it**: identity comes from the organisation's identity provider, access is granted through the
mechanisms they already run, revocation works, actions are visible in an audit trail, and the
gateway is small enough to be read end to end.

## Context that is not in the code

> Superseded in part — see `validation.md`.

This has already been established and does not need re-checking — but it cannot be ignored either;
the whole architecture grows out of it.

**The Claude connector cannot be pointed directly at Entra.** Three independent reasons:

- Entra has no Dynamic Client Registration, and MCP clients go looking for it first;
- Claude sends the RFC 8707 `resource` parameter set to the MCP server URL; Entra validates
  `resource` against the Application ID URI from the manifest, and the RFC 9728 canonical resource
  check on the client side rejects an Application ID URI — the requirements are mutually
  exclusive;
- on the hosted surface the callback succeeds, after which the backend **never POSTs to `/token`**.
  This also breaks Microsoft's own first-party servers, which means it is not fixable by
  configuration.

**The connection always originates from the client vendor's cloud**, on every client, including a
desktop application on a laptop inside a VPN. The gateway therefore has to be publicly reachable,
and a network allow-list restricted to the vendor's published egress range is not authorization —
it only excludes the rest of the internet.

**A connector's authentication settings are immutable after creation.** Changing the gateway URL
or the authorization scheme means recreating the connector and having everyone reconnect. So the
URL and the scheme have to be fixed before announcing it.

## Architecture

```
MCP client (vendor cloud)
   │  OAuth 2.1: discovery → registration → /authorize → /token
   │  MCP: POST /mcp  (Authorization: Bearer <our token>)
   ▼
mcp-gate  ── user redirected ──▶  identity provider (OIDC, upstream)
   │                              authorization code + PKCE
   │  X-Auth-*  (identity and roles)
   ▼
any MCP server — listens on 127.0.0.1, not exposed
```

The gateway **is itself the authorization server** for the client, with the identity provider
above it supplying identity. The client does not talk to the identity provider at all.

## Requirements

### 1. The OAuth side facing the client

- OAuth 2.1: PKCE `S256` mandatory, no implicit grant, `redirect_uri` compared by exact match.
- Metadata: `/.well-known/oauth-protected-resource` (RFC 9728) and
  `/.well-known/oauth-authorization-server` (RFC 8414).
- An unauthorized request returns `401` with
  `WWW-Authenticate: Bearer resource_metadata="https://<host>/.well-known/oauth-protected-resource"`.
- `POST /register` — Dynamic Client Registration (RFC 7591). Mandatory; manual entry of a client
  ID and secret remains as a fallback path.
- `/authorize`, `/token`, `/revoke` (RFC 7009).
- **Opaque tokens, state held by the gateway.** Not JWT: security engineers need real revocation
  "now", not "when it expires". Storage is a single file in the deployment directory and survives
  restart.
- Short access token (one hour by default), refresh rotated on every use, absolute session
  lifetime bounded (24 hours by default, configurable — the final word belongs to the security
  reviewers).

### 2. The identity provider as upstream

- Authorization code with PKCE, confidential client (secret or certificate).
- `id_token` validation: `iss`, `aud` equal to our client ID, tenant identifier strictly equal to
  the configured one, plus `nonce` and `exp`. Single tenant; any other tenant is a refusal.
- Read the roles claim, the object identifier, `sub`, `preferred_username`/`email`, `name`.
- **Do not hard-code `prompt=consent`.** In tenants with user consent disabled this breaks
  sign-in; it is a known bug in another implementation and there is no reason to repeat it.
- Renewing our session goes through a refresh to the identity provider. That is the mechanism for
  "the person left": the account is disabled, the refresh fails, and the session dies within its
  own lifetime with no manual action.

### 3. Access model

- **App roles, not groups.** A role value is a string from the application manifest and is the same
  in any tenant; a group object ID is a tenant-bound GUID that will not survive a move. Roles also
  avoid the overage claim, where a user in a few hundred groups receives a pointer to a directory
  API instead of a list.
- **Default deny.** An absent roles claim is a refusal, not "no restrictions": with user assignment
  not required, an unassigned user signs in successfully and arrives with no roles.
- Configuration describes routes: path prefix → backend → the set of roles granting access.
- v1 gates access at whole-server granularity. Per-tool access is the next stage, but **JSON-RPC
  parsing must be hidden behind an interface from the start**, so that adding it does not require
  rewriting the proxy. When it arrives, `tools/list` must be filtered by entitlement, or the model
  will call what it may not and collect refusals.

### 4. Forwarding identity downstream

- Inbound `X-Auth-*` headers are **stripped** at the edge; otherwise they can be forged from
  outside.
- Added: `X-Auth-Subject`, `X-Auth-Email`, `X-Auth-Name`, `X-Auth-Roles` (comma-separated),
  `X-Auth-Session`.
- The backend may ignore them. The first consumer does ignore them today, and that is fine.

### 5. Audit

- One JSONL line per request: timestamp, session identifier, subject, email, roles, HTTP status,
  JSON-RPC method and tool name (when parsed), policy decision, duration, response size, client IP.
- No tokens, no secrets, no request or response bodies. Tool arguments behind a separate flag, off
  by default.
- The file does not grow without bound and is readable without root.

### 6. Administrative surface

- A separate listener (loopback or private network), **never on the public port**.
- List active sessions, revoke one session, revoke all sessions of a subject, health, metrics in
  Prometheus format.
- The same operations as subcommands of the binary — it is a Go binary, there is no reason for a
  separate client.

### 7. Fallback mode: static token

- A mode where authorization is a shared token mapped to a synthetic identity with a fixed role
  set.
- Needed for CI, health checks, and for the pilot deployment that ships before the identity
  provider is in place.
- It passes through **the same** policy and **the same** audit path. There must be no separate
  bypass route.

## What is configurable

Everything that distinguishes a laboratory from production is configuration, not code:

| | |
|---|---|
| upstream OIDC | issuer, client ID, client secret, name of the roles claim |
| routes | prefix → backend address → required roles |
| sessions | access TTL, refresh TTL, absolute bound |
| mode | oidc / static-token |
| addresses | public listener, administrative listener, audit file, storage file |

Secrets come from files or environment variables and are not in the image. Moving between tenants
must be a configuration edit.

## What this is not

WAF, rate limiting beyond the primitive, DDoS protection, response rewriting, multi-tenancy, the
role of a full API gateway, browser SSO for humans. All of that is somebody else's work, and
attempting it here would destroy the main property: the gateway must be small enough for a
security engineer to read it end to end in an evening. That is a requirement, not a wish.

## Stages

**M0 — the spike, and it is a gate.** A minimal authorization server: no identity provider, no
policy, in-memory storage, hard-coded identity. The single goal is to drive a real custom connector
to the state where OAuth completes and a tool is called. The output of this stage is not code but a
**recorded observation**: what the client actually sends in registration, which redirect URIs it
registers, whether it sends `resource` and with what value, how and when it refreshes a token, what
it does on a `401`. Until this is passed, nothing further is built. Every later stage depends on
what is learned here.

> Superseded: M0 is now two experiments, in a defined order. See `m0-gate.md`.

**M1 — a real authorization server.** PKCE, dynamic registration, opaque tokens, persistent
storage, refresh with rotation, revocation. The identity provider is a local OIDC server in a
container, not Entra.

**M2 — Entra.** A throwaway tenant, app roles, single-tenant validation, default deny, renewal
through upstream refresh.

**M3 — policy, audit, administration.** Routes and roles from configuration, JSONL, session listing
and revocation, metrics.

**M4 — packaging and handover.** Image, compose, Kubernetes, documentation, the package for the
security reviewers.

## Acceptance criteria

1. A real custom connector completes OAuth and calls a tool behind the gateway.
2. A user without the required role signs in successfully at the identity provider and is refused
   — not with a `500`, but with a clear refusal and a line in the audit log.
3. Disabling an account at the identity provider ends access within the session lifetime, with no
   manual action on the server.
4. Revoking a session through the administrative surface takes effect immediately, on the very next
   request.
5. A forged inbound `X-Auth-Roles` has no effect on anything.
6. The backend is unreachable from outside — demonstrated, not asserted.
7. Changing tenant is a configuration edit, with no rebuild.
8. Static mode produces the same audit trail as OIDC mode.
9. The audit trail contains no tokens and no secrets.
10. Deployment is one directory; `docker compose down -v` leaves no container, no volume, no
    network and no trace outside it.

## Constraints and conventions

- Go, static binary, minimal base image, non-root user, read-only root filesystem.
- Install nothing globally: `npx`, `uvx`, containers.
- Compose **appends** `command` to `ENTRYPOINT`; Kubernetes **replaces** it — a rake already
  stepped on.
- Tests are table-driven; the end-to-end test against an OIDC stub must run in CI with no external
  network.
- No frameworks for the sake of frameworks. The standard library and a couple of small dependencies
  are enough.

## Risks

- **The client's OAuth behaviour is poorly documented.** That is precisely why M0 is a gate rather
  than the first step of development.
- Token lifetime versus how the connector refreshes it. If it does not refresh, users will
  re-authorise often and the TTL will have to be a compromise.

  > Superseded: refresh behaviour is documented — see `references.md` [R13].

- Consent policy in a corporate tenant: an administrator consent step is likely to be required
  once.
- Immutability of connector settings: an error in the URL costs everyone a reconnection.

## What to show the security reviewers

A separate short document, at the end of M4: a diagram of the flows and what is stored where; the
list of what is written to the audit trail and what is deliberately not; how access is granted and
revoked; how secrets are rotated; what the gateway sees and what it does not; what remains
available if it fails. That is the object of the review — they will look at the code second.

> Amended: this is no longer only an M4 deliverable. Audit readiness is a standing requirement —
> see `audit-readiness.md` and `decisions/0005-audit-readiness-and-operability-are-requirements.md`.
