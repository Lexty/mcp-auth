# Architecture

What we build and why this shape. The reasoning that selected it is in `validation.md`; the
obligations it carries are in `security-model.md`. External facts cite `references.md`.

## Shape

```
MCP client
   │  OAuth 2.1: discovery → client registration → /authorize → /token
   │  MCP: POST /mcp   (Authorization: Bearer <token issued by the gateway>)
   ▼
mcp-gate  ── user redirected for sign-in ──▶  identity provider (OIDC, upstream)
   │                                          authorization code + PKCE
   │  X-Auth-*  (identity and roles)
   ▼
any MCP server — listens on loopback, not exposed
```

The gateway is an **OAuth 2.1 authorization server** towards the client and an ordinary **OIDC
relying party** towards the identity provider. The client never talks to the identity provider. In
the specification's terms this makes the gateway an *MCP proxy server*, which carries obligations —
see `security-model.md`.

## Which clients

Two profiles exist and they differ in ways that reach the design. Hosted clients connect from the
vendor's cloud over the public internet and use a fixed HTTPS redirect URI [R17]. Native clients
connect from the user's own machine and use an RFC 8252 loopback redirect on an ephemeral port,
requiring the authorization server to match the port-less form [R16].

**Which of these the gateway supports is an open decision**, recorded in `security-model.md` under
"Loopback redirect URIs". Supporting only hosted clients keeps redirect matching absolutely exact.

## Why this shape

Stated in full in `validation.md` §2. In short:

- **Keycloak does not implement RFC 8707 at all** [R8]. Being precise about what that does and does
  not mean: its audience mappers on client scopes *do* bind a token to a resource at issuance. What
  is absent is honouring the `resource` the client actually requested. The binding therefore follows
  the scope the client happened to ask for rather than the resource it named, and a request whose
  `resource` and scope disagree is resolved by the scope.
- **Entra implements it, at a cost**: the resource value must be registered as an Application ID
  URI on the app registration [R4], and the resulting `aud` is the API's client ID rather than the
  resource URL [R6]. Separating routes by audience therefore means separate application
  registrations, or separating them by scope instead. That is administration, not impossibility —
  but it is administration in a second system, per route, forever.

Neither of those is by itself a proof that a broker is required. The requirement is ours: **one
uniform, specification-complete OAuth surface towards the client, and sessions the gateway itself
controls** — a session it can enumerate, bound absolutely, and revoke on the next request. Adding a
route becomes a change to this component's configuration rather than a change in whichever identity
system a given deployment happens to use. See `decisions/0003-single-oauth-mode-in-v1.md` for the
guarantees that motivate gateway-controlled sessions.

**Universality runs in both directions.** The gateway does not know what server is behind it, and
does not know what identity provider is above it. Both are configuration.

## Supported upstreams

Microsoft Entra ID and Keycloak, each through a **verified configuration** of the same generic OIDC
interface — not "any OIDC provider" sight unseen. Ordinary OIDC is enough for sign-in; it is not
enough for the rest. Each upstream owes a written contract covering:

- where identity comes from, and how it maps to `(issuer, sub)`;
- where roles come from, in what claim and what shape;
- how entitlements are re-read within a live session, and how often — a refresh response may omit
  `id_token` entirely [R7], so this cannot be assumed to come for free;
- when a disabled account starts being refused;
- what happens when the provider is unreachable — currently **TBD**, see `security-model.md`.

**Keycloak is supported as an upstream, not as the front towards the client.** See
`decisions/0002-keycloak-as-upstream-idp-only.md`.

## Identity

The subject key is the pair `(issuer, sub)`. Provider-specific identifiers are additional
attributes, never the primary key — Entra's `sub` is pairwise per application while `oid` is stable
across applications in a tenant [R6], and neither is portable across providers. See
`decisions/0004-identity-is-issuer-and-subject.md`.

## Access model

- **App roles, not groups.** A role value is a string from the application manifest, the same in any
  tenant; a group object ID is a tenant-bound GUID that does not survive a move. Roles also avoid
  the overage claim, where a user in enough groups receives a Graph pointer instead of a list [R6].
- **Default deny.** An absent roles claim is a refusal, not "no restrictions".
- Configuration describes routes: path prefix → backend → the roles granting access, and the
  resource identifier that route's tokens are bound to.
- v1 gates access at whole-server granularity.

### Per-tool policy, and why it is not simply body parsing

The brief assumes per-tool access requires parsing JSON-RPC, and asks for that parsing to sit behind
an interface so the proxy need not be rewritten later. The interface is still right, but the
assumption has changed.

The current transport mirrors the JSON-RPC method and the tool name into the `Mcp-Method` and
`Mcp-Name` HTTP headers, and says why: "so that intermediaries (load balancers, gateways,
observability tooling) can route and inspect requests without parsing the body" [R18]. For those
protocol versions, per-tool policy and per-tool audit are available from headers.

That does not make it free, and the version check alone does not make it safe. The protocol version
is declared by the caller, and the specification places header–body validation on the server that
processes the body [R18] — so the guarantee lives in the backend, not in the header. Enforcing
per-tool policy from headers requires a verified contract with the specific backend that it
validates and rejects mismatches; without it the gateway parses the body itself or refuses. The
full argument is in `security-model.md`.

So the decision surface is: enforce from headers only where a verified backend makes them
trustworthy; otherwise parse, or refuse. The interface exists to make that a choice rather than an
accident. When per-tool policy arrives, `tools/list` must be filtered by entitlement, or the model
will call what it may not and collect refusals.

## Tokens and state

Tokens issued to the client are **opaque, with state held by the gateway**. The brief's reason —
that revocation requires opacity — does not hold: what makes revocation immediate is checking
current state on every request, not the token format. The reason that does hold is that the gateway
needs a server-side record regardless, because that record is where the binding of an entitlement to
a specific resource lives, and it is where a session becomes something enumerable and revocable.

The store is a single file in the deployment directory and survives restart. Its format, backup
semantics and migration behaviour are in `operations.md`.

Access tokens are short-lived; refresh tokens rotate on every use [R13]; session lifetime has an
absolute bound. All three are configurable, and the defaults are a starting point for a security
conversation rather than a conclusion — see `open-questions.md` Q6.

## Identity forwarding

Inbound `X-Auth-*` headers are **stripped** at the edge; otherwise they can be forged from outside.
The gateway then sets subject, email, display name, roles, and session identifier. The backend is
free to ignore them, and no token or secret is ever forwarded to it [R11].

## Data flow and trust boundaries

| Boundary | What crosses it |
| --- | --- |
| Internet → gateway | MCP requests with a gateway-issued bearer token; OAuth endpoints; the consent page |
| Gateway → identity provider | Authorization code exchange, refresh, entitlement re-read, discovery. Client secret or certificate. |
| Gateway → backend | Proxied MCP request plus `X-Auth-*`. No token, no secret. |
| Gateway → disk | Token and session store; audit log |
| Administrative listener | Session listing and revocation, health, metrics. Never on the public port. |

The gateway sees identity, roles, and the shape of each request. It does not see the user's
credentials, and it does not interpret response content.

## Proxy behaviour

Streaming is passed through without buffering — servers signal this with `X-Accel-Buffering: no`
and a proxy that accumulates events breaks the transport [R18]. Unrecognised `Mcp-Param-*` headers
are forwarded unchanged [R18]. A client stream that closes must cause the gateway to close the
corresponding backend request, since the gateway sits between the two and the backend cannot
observe the client's disconnect. Which transport revisions are supported is open — see
`open-questions.md` Q3, and note that the revisions disagree about whether a disconnect
implies cancellation: the earlier one recommends against reading it that way [R21].

## Failure behaviour

Fail closed: if policy cannot be evaluated, access is refused. If the gateway is down the backend is
unreachable, which is the intended topology rather than a defect.

Behaviour when the identity provider is unreachable is **not yet decided** — the cases and what
would settle them are in `security-model.md`. Nothing in this repository should be read as
promising it.

## Static-token mode

Authorization by a shared token mapped to a synthetic identity with a fixed role set, for CI, health
checking, and a pilot that ships before the identity provider is in place. It passes through **the
same** policy and **the same** audit path. There is no bypass route.

A hosted client may offer a comparable capability of its own — a fixed credential sent as a request
header, entered once by an administrator [R3]. That covers delivery of the shared secret; verifying
it, mapping it to a synthetic identity, applying policy and writing the audit record remain the
gateway's work.

## Out of scope

WAF behaviour, rate limiting beyond the primitive, DDoS protection, response rewriting,
multi-tenancy, general API gateway duties, browser SSO for humans. Attempting any of these destroys
the property everything else depends on: that the whole thing can be read in an evening.
