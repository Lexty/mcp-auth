# References

Every external fact the other documents rest on. **A reference entry without a quote is not a
reference** — entries that could not be quoted from a source read in full are segregated below
under "Carried, not verified", and a document may not rely on one of those for a decision.

Checked **2026-09-09**. Every one of these sources is a moving target, and during validation four
of them contradicted a confident recollection. Re-check before relying on one, and update the date.

---

# Verified

## MCP specification

**[R1] Dynamic Client Registration is deprecated.**
> "Dynamic Client Registration is deprecated. New implementations should use Client ID Metadata
> Documents instead. This option remains available for backwards compatibility with authorization
> servers that do not support Client ID Metadata Documents."

Client preference order:
> "1. Use pre-registered client information for the server if the client has it available
> 2. Use Client ID Metadata Documents if the Authorization Server indicates that it supports them
> … 3. Use Dynamic Client Registration as a fallback if the Authorization Server supports it …
> 4. Prompt the user to enter the client information if no other option is available"

Note this order is a **SHOULD** for clients that support all options.
<https://modelcontextprotocol.io/specification/draft/basic/authorization/client-registration>

**[R2] Client ID Metadata Documents — obligations on the authorization server.**
> "The `client_id` URL **MUST** use the "https" scheme and contain a path component, e.g.
> `https://example.com/client.json`"
> "The metadata document **MUST** include at least the following properties: `client_id`,
> `client_name`, `redirect_uris`"

For authorization servers:
> "**MUST** validate that the fetched document's `client_id` matches the URL exactly"
> "**SHOULD** cache metadata respecting HTTP cache headers"
> "**MUST** validate redirect URIs presented in an authorization request against those in the
> metadata document"

Advertised as `"client_id_metadata_document_supported": true`. And:
> "Client IDs based on Client ID Metadata Documents are portable across authorization servers,
> since they are self-hosted HTTPS URLs resolved by the authorization server on demand."
<https://modelcontextprotocol.io/specification/draft/basic/authorization/client-registration>

**[R9] Confused deputy problem, and the mandatory mitigation.**
Vulnerable when *all* of: a static client ID used with a third-party authorization server;
clients that register dynamically, each getting its own `client_id`; a consent cookie set by the
third-party server after first authorization; and no per-client consent at the proxy before
forwarding.
> "To prevent confused deputy attacks, MCP proxy servers **MUST** implement per-client consent and
> proper security controls as detailed below."

Per-client consent storage — MCP proxy servers **MUST**:
> "Maintain a registry of approved `client_id` values per user"
> "Check this registry **before** initiating the third-party authorization flow"

The consent page **MUST**:
> "Clearly identify the requesting MCP client by name"
> "Display the specific third-party API scopes being requested"
> "Show the registered `redirect_uri` where tokens will be sent"
> "Implement CSRF protection (e.g., state parameter, CSRF tokens)"
> "Prevent iframing via `frame-ancestors` CSP directive or `X-Frame-Options: DENY`"

Redirect URI validation — the proxy **MUST**:
> "Validate that the `redirect_uri` in authorization requests exactly matches the registered URI"
> "Use exact string matching (not pattern matching or wildcards)"

State ordering:
> "The consent cookie or session containing the `state` value **MUST NOT** be set until **after**
> the user has approved the consent screen at the MCP server's authorization endpoint. Setting
> this cookie before consent approval renders the consent screen ineffective, as an attacker could
> bypass it by crafting a malicious authorization request."

State values must be single-use, short-lived, and validated at the callback.
<https://modelcontextprotocol.io/specification/draft/basic/security_best_practices>

**[R10] SSRF when an authorization server resolves client metadata.**
> "When an authorization server supports Client ID Metadata Documents, the authorization server
> takes a URL as input from an unknown client and fetches that URL. A malicious client could use
> this to trigger the authorization server to make requests to arbitrary URLs, such as requests to
> private administration endpoints the authorization server has access to."

Mitigations named: require HTTPS; block private, loopback and link-local ranges — explicitly
including `169.254.0.0/16` "(including cloud metadata endpoints)"; do not follow redirects
blindly; beware DNS rebinding between validation and use. And:
> "Avoid implementing IP validation manually. Attackers exploit encoding tricks (octal, hex,
> IPv4-mapped IPv6) that custom parsers often miss."
<https://modelcontextprotocol.io/specification/draft/basic/security_best_practices>

**[R11] Token passthrough is forbidden.**
> "MCP servers **MUST NOT** accept any tokens that were not explicitly issued for the MCP server."

Accepting a token with the wrong audience and forwarding it downstream is named as a route into
the confused deputy problem. Audience validation failure is described as breaking "a fundamental
OAuth security boundary".
<https://modelcontextprotocol.io/specification/draft/basic/security_best_practices>

**[R15] Statelessness, and state handles are not authentication.**
> "MCP is stateless and has no protocol-level sessions."

On handles a server mints for multi-request state:
> "MCP servers that implement authorization **MUST** verify all inbound requests. MCP servers
> **MUST NOT** treat possession of a state handle as authentication."
> "MCP servers **SHOULD** bind handles server-side to the authenticated user"

The page refers to "the server-assigned session IDs used by protocol version `2025-11-25` and
earlier", which dates the change. For transport detail see [R18].
<https://modelcontextprotocol.io/specification/draft/basic/security_best_practices>

**[R18] Streamable HTTP transport — what a proxy in front of an MCP server must handle.**
The revision that changed the shape:
> "Revision 2026-07-28 changed the behavior of Streamable HTTP. … Changes included: Removal of the
> GET stream endpoint. Removal of protocol-level sessions."

Earlier revisions differ, and a proxy serving them must know it:
> "Protocol versions `2025-03-26` through `2025-11-25` also used the Streamable HTTP transport,
> but in a different shape: servers could assign a session via the `Mcp-Session-Id` header
> (terminated with HTTP DELETE), clients could open a standalone SSE stream with HTTP GET …
> and streams were resumable via `Last-Event-ID`. None of these mechanisms are part of this
> revision."

**Long-lived streams remain**, which is what makes the revocation boundary a real question:
> "Long-lived notification streams are obtained by sending a `subscriptions/listen` request. The
> server's response is itself an SSE stream that stays open and delivers the change notifications
> the client opted in to"

**Buffering must be disabled**, and this is aimed at proxies:
> "When initiating an SSE stream, servers **SHOULD** include the `X-Accel-Buffering: no` header in
> the HTTP response. This instructs reverse proxies (such as nginx) to disable response buffering"

**Closing the stream is the cancellation signal — in this revision, and note which verbs are which:**
> "Closing the SSE response stream **MUST** be treated by the server as cancellation of that
> request. Because each request has its own response stream, the transport-level disconnect is
> unambiguous. The server **SHOULD** stop work on the cancelled request as soon as practical and
> **MUST NOT** send any further messages for it."

Treating the close as cancellation is a `MUST`; **stopping work is only a `SHOULD`**; sending nothing
further is a `MUST`. So closing a stream reliably silences a response, and does not reliably stop
the work behind it. This conclusion is also scoped to this revision — the earlier one goes the other way [R21].

**Method and tool name are mirrored into HTTP headers, explicitly for intermediaries:**
> "The Streamable HTTP transport mirrors selected JSON-RPC body fields into HTTP headers so that
> intermediaries (load balancers, gateways, observability tooling) can route and inspect requests
> without parsing the body."

`Mcp-Method` carries `method`; `Mcp-Name` carries `params.name` or `params.uri` for `tools/call`,
`resources/read` and `prompts/get`. "These headers are **REQUIRED** for compliance." Values may be
Base64-wrapped in a `=?base64?…?=` sentinel and must be decoded before comparison.

**And a warning written for exactly this component:**
> "Intermediaries that enforce policy based on mirrored headers (e.g., routing or rate-limiting by
> tenant) **SHOULD** verify that the `MCP-Protocol-Version` header indicates a version that
> requires header–body validation. If the version is older or the header is absent, the
> intermediary **SHOULD** reject the request rather than trusting unvalidated header values."

Unknown parameter headers must be passed through:
> "Intermediate servers that do not recognize an `Mcp-Param-{Name}` header **MUST** forward it and
> otherwise ignore it"

Also: servers **MUST** validate the `Origin` header against DNS rebinding, and **SHOULD** bind to
`127.0.0.1` when running locally.
<https://modelcontextprotocol.io/specification/draft/basic/transports/streamable-http>

---

## Claude connector documentation

**[R3] Supported authentication types — a property of the client, not of any identity provider.**
`oauth_dcr` and `oauth_cimd` are both listed "Supported out of the box"; `oauth_anthropic_creds`
and `custom_connection` require contacting Anthropic; `static_headers` — a fixed credential entered
by an organisation administrator and sent as a request header — is in beta; `none` for authless
servers.

CIMD selection is conditional on the **authorization server's** metadata:
> "Claude selects CIMD only when your authorization server metadata advertises **both**
> `"client_id_metadata_document_supported": true` **and** `"none"` in
> `token_endpoint_auth_methods_supported` — the second is required because Claude's CIMD client
> authenticates as a public client at your token endpoint. If either is missing, Claude falls back
> to DCR."

On preference:
> "For servers expecting high traffic from the directory, prefer **CIMD or `oauth_anthropic_creds`
> over DCR**. DCR causes Claude to register a new client on every fresh connection, which can
> result in very large numbers of registered clients on your authorization server."

For custom connectors:
> "Supplying your own pre-registered client ID (and secret, if your server requires one) as static
> client credentials is a good option when you want a stable OAuth client per organization: it
> avoids dynamic client registration entirely, and the credentials are scoped to the organization
> that entered them."

PKCE is unconditional:
> "Claude includes a PKCE `code_challenge` with `code_challenge_method=S256` on every authorization
> request, regardless of which registration mechanism it uses."
<https://claude.com/docs/connectors/building/authentication>

**[R13] Token refresh behaviour.**
> "Claude refreshes tokens **reactively on a 401 response**, with a proactive refresh up to five
> minutes before the stored expiry."

> "Return RFC 6749-compliant error codes (`invalid_grant`, not `invalid_request` or a custom code)
> when a refresh token is no longer valid"

> "Rotate refresh tokens for public-client connections. DCR and CIMD register Claude as a public
> client … If you rotate, return the new refresh token in the same response that invalidates the
> old one."

> "Your `/token` endpoint must accept `Content-Type: application/x-www-form-urlencoded` … Dynamic
> client registration (`/register`) uses `application/json` … so don't assume the same parser works
> for both."
<https://claude.com/docs/connectors/building/authentication>

**[R16] Discovery, metadata, redirect URIs and timing.**
> "The `401` status is required — Claude does not honor a `WWW-Authenticate` header on a `200`
> response"

> "The protected resource metadata document's `resource` field must match your MCP server URL
> exactly as the user enters it in Claude, including any path component."

> "The metadata's `authorization_servers` field must list your authorization server's issuer URL.
> If you list more than one, Claude uses the first entry and does not fall back to later entries"

> "Claude also appends `offline_access` when your authorization server metadata lists it in
> `scopes_supported`, to obtain a refresh token."

> "Claude waits up to **10 seconds** for a response from your OAuth discovery, registration, and
> token endpoints, and up to **30 seconds** for refresh token requests."

**Hosted and native clients have different redirect URIs.** For hosted surfaces the registered
redirect URI is `https://claude.ai/api/mcp/auth_callback`. For the native client:
> "**Claude Code** is a native client and uses an RFC 8252 loopback redirect on an ephemeral port
> … The port varies per session. Claude Code declares `http://localhost/callback` and
> `http://127.0.0.1/callback` in its Client ID Metadata Document, so your authorization server must
> accept both with the port component ignored."

And the caveat that goes with it:
> "A Client ID Metadata Document can't prevent loopback impersonation on its own — any local
> process can bind a port and claim to be the legitimate client."
<https://claude.com/docs/connectors/building/authentication>

**[R4] Microsoft Entra ID rejects the resource value — and the documented fix.**
> "If your authorization server is Microsoft Entra ID and the token request fails with
> `AADSTS9010010` (sometimes surfaced as `invalid_target`), Entra is rejecting the `resource` value
> Claude sends because it does not match any Application ID URI registered on your app. Claude sets
> `resource` to your MCP server URL, including the path, and Entra issues a token when that value
> is listed under **Expose an API** → **Application ID URI** (`identifierUris` in the manifest) on
> the app registration that represents your protected API. The default `api://{client-id}` URI
> alone is not sufficient here, because Claude sends the full MCP server URL as the resource
> value."

The value "must match exactly, including the path, without a trailing slash".
<https://claude.com/docs/connectors/building/troubleshooting>

**[R5] The canonical resource form Claude sends, and how a server should compare it.**
> "Claude sends the RFC 8707 `resource` parameter on authorization and token requests, set to the
> canonical form of your MCP server URL — lowercase scheme and host, no trailing slash, no
> fragment, no default port — including any path component. Your authorization server should issue
> tokens with that audience, and your MCP server should accept the canonical value when checking
> `aud` rather than doing a strict byte-for-byte comparison against what the user typed."

Note this describes what **the client sends** and how a server should compare — it is not a licence
for an authorization server to rewrite arbitrary input into a canonical form. See
`security-model.md`.
<https://claude.com/docs/connectors/building/troubleshooting>

**[R17] Network reachability and where connections come from.**
> "claude.ai connectors run on Anthropic's infrastructure and reach your server over the public
> internet."

> "Before making any request, Claude resolves your server's hostname and validates the result. If
> **any** resolved address is not globally routable, Claude rejects the connection before any HTTP
> request leaves Anthropic's network."

Rejected: private ranges, carrier-grade NAT `100.64.0.0/10`, loopback, link-local, a mix of public
and non-public addresses, and a hostname with no `A` record — "connectors are IPv4-only".

> "If your registered MCP URL returns a `301`/`302`/`307`/`308` redirect to a different host …
> the `Authorization` header is dropped on the redirect per standard HTTP client security
> behavior."

This applies to the hosted surfaces. The native client connects from the user's own machine — see
[R16].
<https://claude.com/docs/connectors/building/troubleshooting>

Two further statements on this subject come from the **Authentication** page, not troubleshooting:
> "Discovery requests to the authorization server come from the same IP range as requests to your
> MCP server, so a WAF in front of your identity provider can break the flow even when your MCP
> server is reachable."
> "Anthropic's outbound traffic to your server originates from `160.79.104.0/21`."
<https://claude.com/docs/connectors/building/authentication#cross-host-authorization-servers>

---

## Microsoft Entra ID

**[R6] The `aud` claim in a v2.0 access token is the API's client ID, not a URL.**
> "`aud` — String, an Application ID URI or GUID. Identifies the intended audience of the token. In
> v2.0 tokens, this value is always the client ID of the API. In v1.0 tokens, it can be the client
> ID or the resource URI used in the request. … This value must be validated, reject the token if
> the value doesn't match the intended audience."

On roles:
> "`roles` … For user tokens, this set of values contains the assigned roles of the user on the
> target application."

On identity, relevant to `(issuer, sub)`:
> "`sub` … The subject is a pairwise identifier that's unique to a particular application ID. If a
> single user signs into two different applications using two different client IDs, those
> applications receive two different values for the subject claim."
> "`oid` … The immutable identifier for the requestor … Two different applications signing in the
> same user receive the same value in the `oid` claim."

On session and token identifiers:
> "`sid` — String, a GUID. Represents an unique identifier for a session and will be generated when
> a new session is established."
> "`uti` — Token identifier claim, equivalent to `jti` in the JWT specification. Unique, per-token
> identifier"

Nothing on that page states that `sid` is present in access tokens by default or that it is stable
across refresh. And a general warning:
> "Applications should not take hard dependency on claims being present or in specific order."

On the overage claim, which is why roles are preferred to groups:
> "If a user is a member of more groups than the overage limit (150 for SAML tokens, 200 for JWT
> tokens), then Microsoft Entra ID doesn't emit the groups claim in the token. Instead, it includes
> an overage claim … that indicates to the application to query the Microsoft Graph API"
<https://learn.microsoft.com/en-us/entra/identity-platform/access-token-claims-reference>

---

## OpenID Connect

**[R7] A refresh response need not contain an `id_token`.**
OIDC Core §12.2, Successful Refresh Response:
> "Upon successful validation of the Refresh Token, the response body is the Token Response of
> Section 3.1.3.3 except that it might not contain an `id_token`."

Consequence: a successful refresh does not, by itself, deliver an updated set of claims — including
roles. Re-reading entitlements must be a deliberate mechanism.

*Verification note:* the specification page is too large to retrieve in full through the tooling
used here; the quoted sentence was confirmed against the specification text by search rather than
by reading the whole document. Treat it as verified for the wording, and re-read §12.2 directly
before it becomes load-bearing for an implementation decision.
<https://openid.net/specs/openid-connect-core-1_0.html#RefreshTokenResponse>

---

## Keycloak

**[R8] Keycloak as an MCP authorization server.**
Resource indicators (RFC 8707) are **not supported**:
> "The Keycloak community is planning to support Resource Indicators for OAuth 2.0 (RFC 8707)."

Keycloak cannot recognise the `resource` parameter directly; the documented workaround is client
scopes with audience mappers binding tokens to specific MCP server URLs via `aud`. MCP 2025-06-18
and later are rated "Partially Supported without Resource Indicators for OAuth 2.0". Dynamic Client
Registration is supported. Client ID Metadata Document support is
> "an experimental feature. It may introduce breaking changes in future versions."

requiring `--features=cimd` and a client profile with the `client-id-metadata-document` executor.
<https://www.keycloak.org/securing-apps/mcp-authz-server>

Community discussion of the RFC 8707 gap:
<https://github.com/keycloak/keycloak/discussions/35743>

---

## Orchestration

**[R19] Kubernetes `command` and `args` map to `ENTRYPOINT` and `CMD`.**
> "command field corresponds to ENTRYPOINT"
> "args field corresponds to CMD"

Defining both overrides the image's `ENTRYPOINT` and `CMD` entirely; defining only `args` keeps the
image's entrypoint with new arguments. Note the contrast with Compose [R22], where `command`
replaces `CMD` while `ENTRYPOINT` survives.
<https://kubernetes.io/docs/tasks/inject-data-application/define-command-argument-container/>

**[R20] What `docker compose down` removes.**
By default it removes "Containers for services defined in the Compose file", "Networks defined in
the networks section of the Compose file", and "The default network, if one is used".
> "Networks and volumes defined as external are never removed."
> "Anonymous volumes are not removed by default."

Options, quoted precisely, because two of them are easy to misdescribe:
> "`-v`, `--volumes`: Remove named volumes declared in the 'volumes' section of the Compose file
> and anonymous volumes attached to containers"
> "`--remove-orphans`: Remove containers for services not defined in the Compose file"
> "`--rmi`: Remove images used by services. 'local' remove only images that don't have a custom tag"

So `--remove-orphans` is about services missing from the *current* file — not about containers the
project did not create — and `--rmi local` spares any image carrying a custom tag.
<https://docs.docker.com/reference/cli/docker/compose/down/>


**[R21] Transport revision 2025-11-25 — disconnection is *not* cancellation, and sessions exist.**
The rule this revision states, with its exact normative verb:
> "Disconnection **MAY** occur at any time (e.g., due to network conditions). Therefore:
> Disconnection **SHOULD NOT** be interpreted as the client cancelling its request. To cancel, the
> client **SHOULD** explicitly send an MCP `CancelledNotification`."

Note this is `SHOULD NOT`, not `MUST NOT` — it is a recommendation against inferring cancellation,
which is the opposite direction from the current revision's rule [R18], but it is not an absolute
prohibition. The conclusion to draw is that closing a stream cannot be relied on to cancel anything
in this revision; nothing stronger.

This revision also has the session machinery the current one removed: a server **MAY** assign a
session at initialization via the `MCP-Session-Id` response header, clients **MUST** then send it on
every subsequent request, a server **MAY** terminate a session and must then answer `404`, and a
client **SHOULD** send an HTTP DELETE to end one. A standalone SSE stream via HTTP GET exists, and
streams are resumable via `Last-Event-ID`. All of that is state a proxy for this revision has to pass
through faithfully.
<https://modelcontextprotocol.io/specification/2025-11-25/basic/transports>

**[R22] Compose `command` overrides the image's `CMD`.**
The Compose specification states that `command` overrides the default command declared by the
image's `CMD` instruction; a non-null `entrypoint` still runs. That is the mechanism behind the
"Compose appends, Kubernetes replaces" effect: Compose replaces `CMD` while `ENTRYPOINT` survives,
whereas in Kubernetes `command` replaces `ENTRYPOINT` itself [R19].
> "Unlike the `CMD` instruction in a Dockerfile, the `command` field doesn't automatically run
> within the context of the `SHELL` instruction defined in the image."
<https://docs.docker.com/reference/compose-file/services/#command>


---

# Carried, not verified

These claims were raised during validation, sourced by a peer, and are recorded here because
documents refer to them. **They have not been independently checked against the source, and no
decision may rest on one of them.** Each states what would verify it.

**[C1] Application ID URI values are subject to restrictions.**
Whether an arbitrary HTTPS URL may be registered as an Application ID URI — which the fix in [R4]
requires — is said to depend on Microsoft's identifier URI restrictions and on tenant policy.
*Verify by:* reading the page below, then confirming against the actual tenant used in M0.
<https://learn.microsoft.com/en-us/entra/identity-platform/identifier-uri-restrictions>

**[C2] Entra refresh and revocation properties.**
Reported: Entra issues a new refresh token without automatically invalidating the previous one;
revoking one access token does not prevent obtaining a new one by refresh; Entra cannot directly
revoke a session issued by an application; default access token lifetime is 60–90 minutes.
*Verify by:* reading the three pages below, and by observation in M0/M2.
<https://learn.microsoft.com/en-us/entra/identity-platform/refresh-tokens>,
<https://learn.microsoft.com/en-us/entra/identity/users/users-revoke-access>,
<https://learn.microsoft.com/en-us/entra/identity-platform/access-tokens>

**[C3] Entra supports neither Dynamic Client Registration nor Client ID Metadata Documents.**
Asserted in the original brief for DCR, and inferred for CIMD from its absence in Entra's
documentation. Neither has been confirmed against a primary source here. What M0 Experiment A
actually depends on is that **pre-registration works**, which is independent of whether the other
two are absent; the absences matter only for describing Entra accurately, not for the experiment.
*Verify by:* Entra's application registration documentation, and by attempting it in M0.

**[C4] The reported failure to POST to `/token`.**
Two issue reports are cited in the brief. They have not been read here. What is recorded is that a
peer found the later one to reference the earlier one's observations, making them one report rather
than two independent ones.
*Verify by:* reading both issues. Note that reading them establishes what was reported, not the
cause — see `open-questions.md` Q2.
<https://github.com/anthropics/claude-ai-mcp/issues/506>,
<https://github.com/anthropics/claude-ai-mcp/issues/632>
