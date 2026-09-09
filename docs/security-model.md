# Security model

Obligations this design carries, and semantics the brief left ambiguous. Everything here is
binding. External claims cite `references.md`; a claim marked **TBD** is open and names what would
close it.

## The gateway is an MCP proxy server

Once the gateway issues client credentials to arbitrary clients and holds a single confidential
client registration towards the identity provider, it matches the configuration the MCP
specification calls the **confused deputy problem**, in every particular: a static client ID used
with a third-party authorization server; clients registering dynamically, each with its own
`client_id`; a consent cookie set by the third party after first authorization; and no per-client
consent at the proxy before forwarding [R9].

The attack requires compromising nothing. An attacker registers a client with their own
`redirect_uri`, sends the user a crafted authorization link, and the user's existing consent cookie
causes the upstream to skip its consent screen. The authorization code is delivered to the
attacker's redirect URI and exchanged for a token that impersonates the user.

PKCE does not help: the attacker chooses the verifier for their own client.

### Mandatory mitigations

The specification's mitigation is a `MUST` [R9]. These are requirements:

- **A consent registry, scoped by what was actually approved.** Not merely a set of approved
  `client_id` values per user. An approval is a triple — user, client, and the extent of the grant
  (the resources and scopes shown on the consent page). Widening any part of the extent requires a
  fresh approval. The specification's consent page requirements make this explicit by demanding
  that the page "display the specific third-party API scopes being requested": an approval that did
  not display a scope cannot cover it.

  The failure this prevents: a client approved for one route later requests another, and a registry
  keyed on `client_id` alone silently treats it as already consented.

- **A consent page owned by the gateway**, shown *before* the upstream flow is initiated. It names
  the requesting client, displays the scopes and resources being requested, shows the registered
  `redirect_uri` where tokens will be sent, carries CSRF protection, and cannot be framed.

- **Exact-match redirect URI validation.** String equality, not pattern matching, not wildcards.
  A changed redirect URI requires re-registration. One exception, and it is narrow — see
  "Loopback redirect URIs" below.

- **State handling ordered correctly.** The state that authorises completing a specific upstream
  authorization is stored server-side **only after** consent is approved, and set immediately
  before the redirect. Setting it earlier makes the consent screen decorative [R9]. State values
  are single-use and short-lived; a callback with missing or mismatched state is rejected.

An ordering problem this creates, which must be solved rather than papered over: before the
upstream sign-in the gateway may not yet know which user the consent registry should be checked
against. The approval of a specific client, the browser transaction, and the identity established
at callback all have to be bound together.

### Loopback redirect URIs

Exact matching has one documented exception. Native clients use an RFC 8252 loopback redirect on an
ephemeral port; the Claude Code client declares `http://localhost/callback` and
`http://127.0.0.1/callback` and requires the authorization server to "accept both with the port
component ignored" [R16]. Exact matching on every other component still applies.

This exception carries a real weakness, stated in the same source: a metadata document "can't
prevent loopback impersonation on its own — any local process can bind a port and claim to be the
legitimate client" [R16].

**Decision required (TBD):** whether this gateway supports native clients at all. Supporting only
hosted clients keeps redirect matching absolutely exact; supporting native clients requires the
port exception and a consent page that displays the redirect URI hostname prominently. *Closed by:*
a decision record, informed by which clients M0 exercises.

## Client registration

Support **Client ID Metadata Documents alongside Dynamic Client Registration**, with manual entry
of a client ID and secret as a fallback. DCR alone is insufficient: the specification deprecates it
in favour of CIMD, and the client preference order is pre-registration, then CIMD, then DCR, then
manual entry [R1]. A client may select CIMD only when the authorization server metadata advertises
both CIMD support and `none` among supported token endpoint authentication methods [R3]; both must
be advertised deliberately.

CIMD does not establish that a client is trustworthy. It binds metadata to a URL, and an attacker
can host a valid document on their own domain. What answers the "anyone can register" objection is
an admission policy over trusted client URLs and domains, layered on top of CIMD.

CIMD also introduces an outbound HTTP fetch driven by an input value, which is an SSRF surface and
must be treated as one [R10]: HTTPS only; no private, loopback, link-local or carrier-grade-NAT
destinations; redirects not followed blindly; bounded document size and timeout; caching that
respects HTTP cache headers [R2]. The specification's own warning applies —
"avoid implementing IP validation manually" [R10].

## Resource binding

An entitlement is bound to a specific resource at issuance, and that binding lives in the
server-side token record. Checking the user's roles is not a substitute.

The failure this prevents: a user holds roles for two routes, but the client obtained consent for
only one. If the token record carries only identity and roles, a request to the second route passes
a role check it should never have reached.

The gateway therefore rejects a token presented at a resource other than the one it was issued for,
and rejects an authorization request naming a resource it does not serve. Accepting a token not
issued for this server is forbidden outright [R11].

### Comparing resource values — precisely

Three different things must not be conflated:

1. **The configured resource identifier** for a route. This is set by the operator, in one exact
   form, and it is what tokens are bound to.
2. **The value presented in a request** — the `resource` parameter on an authorization or token
   request, or the target of an incoming MCP request.
3. **Any normalisation applied before comparison.**

The client sends `resource` in a canonical form: "lowercase scheme and host, no trailing slash, no
fragment, no default port — including any path component" [R5]. That describes what *the client
produces*. It is not a licence for the gateway to rewrite arbitrary input into that form: silently
normalising away a distinguishing character can collapse two different resources into one.

Binding rules:

- Comparison is against the configured identifier, not against whatever a user typed.
- Scheme and host are compared case-insensitively; a default port is equivalent to its absence.
- A **fragment is rejected**, not stripped. A resource identifier has no fragment, and a request
  carrying one is malformed.
- A **trailing slash is not discarded unconditionally.** It may distinguish two configured
  resources. If the deployment treats it as insignificant, that is a configuration property of the
  route, applied to both sides of the comparison, and stated in the route's configuration.
- An unrecognised resource is refused. It is never defaulted to "the only route" or to the first
  match.

## Three revocation events

The brief says "revocation works". That covers three events with three mechanisms and three
timings. Each is stated separately, with its bound and the source of current state.

| Event | Mechanism | Bound |
| --- | --- | --- |
| An administrator revokes a session at the gateway | Server-side session record marked revoked, checked on every request | The next request. Firm. |
| An account is disabled at the identity provider | Whatever the upstream's verified contract says actually surfaces it — a failed refresh, a failed re-read, or a distinct signal | **TBD** — no formula yet, see below |
| A role is removed from a still-active user | Requires re-reading current entitlements; nothing else surfaces it | **TBD** — no formula yet, see below |

The third is the one that gets missed. **A successful refresh does not prove the entitlement
survived.** The user is still valid, so the refresh succeeds; the role is gone, so the decision
should change. Nothing about a refresh forces roles to be re-read — a refresh response may omit
`id_token` entirely [R7]. Re-reading entitlements and recomputing the decision is a mechanism the
gateway must implement deliberately.

The two **TBD** bounds are not editorial gaps, and it is tempting to close them with a formula such
as "equal to the re-read interval". That formula would be wrong. A polling interval bounds only how
long it takes us to *notice* state that is already available to us. It says nothing about:

- how long the provider itself takes to propagate the change to whatever we read;
- caching anywhere between the two, ours or theirs;
- any grace period we adopt for an unreachable provider (`open-questions.md` Q8), which extends the
  bound by its own length;
- the fact that re-reading roles is not guaranteed to reveal a *disabled account* at all. That is a
  different event, and which upstream signal surfaces it — a refused refresh, an error on the
  entitlement read, or something else — is part of each upstream's verified contract and is not yet
  established for either.

So the honest statement is that the bound is the sum of terms we have not measured, and no document
may publish a figure until they are. *Closed by:* `open-questions.md` Q5 and Q8, measured against
each upstream, and the security review's view on acceptable latency.

Two upstream properties are reported and not yet verified here [C2]: that a provider may issue a
new refresh token without invalidating the previous one, and that revoking an access token does not
prevent obtaining a new one by refresh. If they hold, rotating the gateway's own tokens one-time
protects the gateway's chain and says nothing about the upstream's.

Do not assume a provider session identifier corresponds to one client connection. Entra's `sid` is
documented only as "an unique identifier for a session … generated when a new session is
established" [R6]; whether it appears in access tokens, survives refresh, or distinguishes parallel
connections is unestablished, and the same page warns against depending on any claim being present.

## When the identity provider is unreachable

**TBD.** Required behaviour is not yet decided, and other documents must not refer to it as though
it were. What must be decided, separately for each case:

- **A live session, within its lifetime, when no upstream call is due.** Continuing to serve is
  defensible; so is refusing. The choice determines what "revocation within the session lifetime"
  actually guarantees during an outage.
- **A live session when a refresh or entitlement re-read is due and fails.** Distinguishing "the
  provider says no" from "the provider did not answer" matters: the first is a decision, the second
  is an absence of one. Treating an absence as a denial is fail-closed and may cause a mass
  logout during an outage; treating it as an approval is fail-open and unacceptable.
- **A new sign-in.** Necessarily fails; the question is only what the user is told.
- **Readiness.** Whether reaching the discovery document counts towards readiness is part of this
  same decision and is left open in `operations.md` for that reason. Deciding it there in isolation
  would pre-empt the cases above.

*Closed by:* a decision record, informed by M2 measurements against both upstreams.

## Token handling

- Never accept a token not issued for this gateway [R11]. Token passthrough — forwarding a
  client-supplied token to a downstream service — is forbidden and is one route into the confused
  deputy problem.
- The gateway issues its own tokens to the client and sends none of them to the backend. The
  backend receives identity headers only.
- Refresh tokens rotate on every use, and the response issuing the new one invalidates the old
  [R13].
- A refresh token that is no longer valid is refused with `invalid_grant`, not a custom code,
  because clients branch on it [R13].
- Access token lifetime, refresh lifetime and absolute session bound are configurable. Upstream
  token lifetimes are the provider's policy and are not something this component declares.

## Proxying MCP traffic

Obligations that fall on an intermediary, all from [R18]:

- **Do not buffer SSE responses.** Servers signal this with `X-Accel-Buffering: no`; a proxy that
  accumulates events breaks the transport.
- **Pass through unrecognised `Mcp-Param-*` headers** unchanged.
- **Do not enforce policy on the mirrored headers without a verified backend contract.**
  `Mcp-Method` and `Mcp-Name` mirror the JSON-RPC `method` and tool name into HTTP headers
  precisely so that intermediaries can route and inspect without parsing the body, and the
  specification warns that an intermediary enforcing policy on them "SHOULD verify that the
  `MCP-Protocol-Version` header indicates a version that requires header–body validation. If the
  version is older or the header is absent, the intermediary SHOULD reject the request rather than
  trusting unvalidated header values" [R18].

  **Checking that header is necessary and not sufficient, and this is the trap.** The version is
  declared by the caller. An attacker can send a modern version header, an `Mcp-Name` naming a tool
  they are allowed to call, and a body naming one they are not. The gateway approves on the header;
  a backend that does not validate header against body executes the body. The specification places
  that validation on the server that processes the body — "Servers that process the request body
  **MUST** reject requests where the values specified in the headers do not match the corresponding
  values in the request body" [R18] — which means the guarantee lives in the backend, not in the
  header.

  So enforcing per-tool policy from headers requires a **verified contract with the specific
  backend**: that it validates header against body before executing, and rejects an unsupported or
  absent protocol version rather than proceeding. Without that contract the gateway parses the body
  itself or refuses the request. There is no third option, and a well-formed request from a
  well-behaved client is not evidence that there is.
- Which transport revision the gateway supports is itself open — see `open-questions.md` Q3. The
  revisions differ in whether sessions and a GET stream exist at all [R18].

## Revocation boundary on open streams

"Refused on the next request" does not describe a stream already in flight. Long-lived streams
remain in the current transport: a `subscriptions/listen` response "is itself an SSE stream that
stays open" [R18], and a tool call may be executing when a revocation lands.

The transport supplies a mechanism, but it delivers less than it first appears. In the current
revision "closing the SSE response stream **MUST** be treated by the server as cancellation of that
request", and the server **MUST NOT** send any further messages for it — but stopping the work is
only a **SHOULD** [R18]. Closing a stream therefore reliably silences the response and does not
reliably stop what is running behind it. In the earlier revision it goes the other way, and the verb matters: disconnection "**SHOULD NOT**
be interpreted as the client cancelling its request", with an explicit `CancelledNotification` being
the intended mechanism instead [R21]. That is a recommendation against inferring cancellation, not a
prohibition — the conclusion to draw is that closing a stream cannot be relied on to cancel anything
there, and nothing stronger.

Two things follow, and neither is optional:

- **Cancellation must be propagated.** Closing the client's stream is not by itself a cancellation
  of the request the gateway has in flight against the backend. The gateway must close that
  connection too, or the backend keeps working with no one listening.
- **Any conclusion here is scoped to a transport revision.** Which revisions are supported is open
  — see `open-questions.md` Q3 — and the answer changes what revocation on an open stream can even
  mean.

**TBD:** whether revocation terminates open streams immediately, and whether an in-flight tool call
is allowed to complete. What is *not* open is that revocation cannot undo an action already taken,
and cannot be promised to stop one in progress; that must be stated to the reviewer either way.
*Closed by:* a decision record — see `open-questions.md` Q4.

## Header sanitisation

Inbound `X-Auth-*` headers are stripped before any other processing. A forged one must have no
effect anywhere, and demonstrating that is an acceptance criterion.

## Audit — the canonical record schema

This is the single definition of the audit record. Any other document describing audit fields
refers here rather than restating them.

| Field | Notes |
| --- | --- |
| timestamp | |
| session identifier | the gateway's own session, not a provider's |
| subject | `(issuer, sub)` — see `decisions/0004` |
| email | personal data |
| display name | personal data |
| roles | as evaluated for this request |
| client identifier | which registered client presented the token |
| resource | the route the request was bound to |
| HTTP status | |
| JSON-RPC method | recorded with its provenance, never bare — see below |
| tool name | recorded with its provenance, never bare — see below |
| policy decision | and, on refusal, which check failed |
| duration | |
| response size | |
| client IP | personal data |

**Method and tool name carry their provenance.** A value taken from `Mcp-Method` or `Mcp-Name` is
something the caller asserted; a value taken from the body is what the request actually contains.
Recording either as though it were simply "the method" launders a claim into a fact, and the audit
trail is precisely where that must not happen. Each is recorded as one of: read from the body; read
from the header under a verified backend contract (see "Proxying MCP traffic"); or asserted by the
client and not verified. On a request rejected *because* header and body disagreed, both values are
recorded, as the two different things they are.

Never recorded: tokens, secrets, request or response bodies. Tool arguments only behind a flag that
is off by default.

Both authorization modes — upstream OIDC and static token — produce the same records through the
same path. There is no route that skips the audit.

**The whole record is personal data, not three fields of it.** The marking above says which fields
are personal *on their own*; it does not partition the record. `(issuer, sub)` identifies the user
by this design's own definition, the session identifier links to them, and every remaining field
describes what that identified person did. Removing the three marked fields would not anonymise the
log. Treat the audit trail as an identifiable history of user activity, and say so to a reviewer
rather than presenting a short list as the extent of it.

Retention is bounded by the component itself, and the file is readable without root. See
`audit-readiness.md`.

## Network exposure

Hosted clients connect from the vendor's cloud rather than from the user's machine, including
desktop applications on a laptop inside a VPN, so the gateway must be publicly reachable [R17].
Discovery requests to the authorization server arrive from the same egress range as the MCP
requests, so an edge rule that blocks one blocks the other [R17]. A redirect to a different host
drops the `Authorization` header [R17], so the registered URL must be the one the server actually
serves.

Native clients connect from the user's own machine [R16], which is a different exposure profile.
Which of the two this gateway supports is the open decision recorded above.

An allow-list restricting inbound traffic to a published egress range excludes the rest of the
internet. It is not authorization and is never counted as any.

The backend must also validate the `Origin` header against DNS rebinding and bind to loopback when
running locally [R18]; the gateway does not relieve it of that.
