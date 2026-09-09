# Validation

Date: 2026-09-09. Method: two agents (Claude and Codex) working as peers, each checking the
other's claims against primary sources rather than recollection.

**Verdict: conditional yes.** The architecture the brief proposes is sound. The reasoning the
brief gives for it is not. Two of the three founding premises are wrong, the third is unproven,
and the real justification is something the brief does not mention at all.

This distinction matters more than it might appear. The brief states its premises as settled and
instructs the reader not to re-check them, and it says "the whole architecture grows out of
this". If the premises are wrong and the architecture is right, then the architecture is right by
accident, and every decision derived from those premises has to be re-derived.

## 1. The refuted premises

The brief's section "Context that is not in the code — already established, no need to re-check"
gives three independent reasons why a Claude connector cannot be pointed directly at Microsoft
Entra ID.

### 1.1 "Entra has no DCR, and MCP clients go looking for it first" — true but not load-bearing

Entra is not known to implement RFC 7591 Dynamic Client Registration — an absence carried from the
brief and not checked against a primary source here [C3]. Suppose it holds: it still does not
support the conclusion, for two reasons.

First, the client does not require DCR. Its documented authentication types include Client ID
Metadata Documents (`oauth_cimd`) as "Supported out of the box", Anthropic-held client credentials,
and — for custom connectors — a client ID and optional secret entered by an administrator, which
the documentation describes as a good option that "avoids dynamic client registration entirely"
[R3].

**A distinction that is easy to lose here:** those are capabilities of the *client*. CIMD requires
the *authorization server* to resolve metadata documents and to advertise that it does [R2][R3];
support in the client implies nothing about support in Entra. For a path that points the client
directly at Entra, the option that actually applies is **pre-registration** — a stable client ID
and secret entered by an administrator. CIMD becomes relevant only once the gateway is the
authorization server, where it is ours to implement.

Second, the direction of travel is away from DCR. The MCP specification marks Dynamic Client
Registration deprecated: "New implementations should use Client ID Metadata Documents instead.
This option remains available for backwards compatibility" [R1]. The client preference order is
pre-registration, then CIMD, then DCR, then manual entry.

So "no DCR" is a fact about Entra that no longer implies "cannot be used". Note also that the
absence itself is carried from the brief and has not been checked against a primary source here
[C3].

### 1.2 "`resource` and the Application ID URI are mutually exclusive" — refuted

The brief states that Claude sends the RFC 8707 `resource` parameter set to the MCP server URL,
that Entra validates `resource` against the Application ID URI from the app manifest, and that
the RFC 9728 canonical-resource check rejects an Application ID URI, so the two requirements
cannot both be satisfied.

Anthropic's own troubleshooting documentation contradicts this and gives the fix. The failure
mode is the error `AADSTS9010010`, and the remedy is to register the MCP server URL itself as an
additional Application ID URI under **Expose an API**; the default `api://{client-id}` value
alone is not sufficient precisely because Claude sends the full MCP server URL. There is no
contradiction, because once configured the canonical resource *is* the Application ID URI.

The same page also states that the MCP server should accept the canonical form when checking
`aud` rather than doing a byte-for-byte comparison against what the user typed.

One caveat, raised by Codex and worth carrying: whether an arbitrary HTTPS URL can be added as an
Application ID URI depends on Microsoft's identifier URI restrictions and on tenant policy. The
fix is documented; its applicability in a given tenant is a configuration question to confirm,
not an assumption.

See references [R4], [R5].

### 1.3 "The backend never POSTs to `/token`" — unproven, not refuted

This one stands as an open question rather than a refuted claim. The brief cites two issues as
independent evidence. Neither has been read here; what is recorded is that a peer found the later
one to reference the earlier one's observations, which if correct makes them one report rather than
two [C4]. Either way they establish that users reported a failure, not why the flow stopped.

It is also plausible — but only plausible — that the reported symptom is the `AADSTS9010010`
rejection seen from the operator's side. Nothing here establishes that.

**And M0 will not establish it either.** M0 can show whether the direct path works today with a
corrected configuration; succeeding at that says nothing about why a different configuration failed
before. Attributing the historical cause would need the original configuration or trace, or a
deliberate reproduction with one controlled variable. The two questions are separated in
`open-questions.md` as Q2a and Q2b, and only Q2a is on M0's list.

## 2. The justification that actually holds

The requirement to support **Keycloak as well as Entra** is what exposed the brief's stated reasons
as inadequate, and the brief predates that requirement. It is not by itself what makes a broker
necessary — that is our own requirement, stated at the end of this section.

The client sends the RFC 8707 `resource` parameter on both authorization and token requests,
always. The two candidate providers stand very differently to that, and the difference matters:

- **Keycloak does not implement RFC 8707 at all.** Its own MCP guide describes resource indicators
  as something "the Keycloak community is planning to support", states that Keycloak "cannot
  recognize the `resource` parameter directly", and recommends audience mappers on client scopes as
  a workaround. The same guide rates MCP 2025-06-18 and later as only partially supported for this
  reason. Its CIMD support is experimental, behind `--features=cimd` [R8]. In the front-facing role
  this is disqualifying — but for a narrower reason than "no binding is possible": its audience
  mappers do bind a token to a resource at issuance; what is absent is honouring the `resource` the
  client requested, so the binding follows the scope asked for rather than the resource named.
- **Entra implements it, at an administrative cost.** The resource value must be registered as an
  Application ID URI on the app registration [R4], and the resulting `aud` is the API's client ID
  rather than the resource URL [R6].

  Being careful here, because the first draft of this document overstated it: a GUID is a perfectly
  valid audience binding, and routes of one application are not obliged to have distinct audiences.
  Separating them is available — separate application registrations, or separation by scope. What
  it costs is that every route added behind the gateway is also a change in the identity system, in
  a second console, forever, and that the separation lives somewhere the gateway does not control.

So the justification is not a defect of a particular provider. It is a requirement of ours:
**one uniform, specification-complete OAuth surface towards the client, and sessions the gateway
itself controls** — enumerable, absolutely bounded, revocable on the next request. Adding a route
becomes a configuration change in this component rather than in whichever identity system a given
deployment happens to run. Of the upstream we then ask sign-in — plus the entitlement-freshness
contract set out in `architecture.md`, which ordinary OIDC does not supply on its own.

That reframing also fixes the brief's notion of universality, which is currently stated only
downwards ("the gateway does not know what server is behind it"). It must be stated upwards too:
**the gateway does not know what identity provider is above it.**

Two qualifications, both from Codex, both accepted:

- "Ordinary OIDC is enough" is too strong, and so is "of the upstream we ask only sign-in".
  Ordinary OIDC is enough *for sign-in*. Role freshness is a separate contract: OIDC Core §12.2
  permits a refresh response to omit `id_token` entirely [R7], so a successful refresh does not by
  itself deliver an updated role set. Each supported upstream needs a verified contract covering
  where roles come from, how entitlements are re-read within a live session, when a disabled
  account starts being refused, and what happens when the provider is unreachable. Support is per
  verified configuration, not a claim about OIDC in general.
- Keycloak's limitation is a limitation of one candidate in one role, not a proof that the
  authorization server must be written from scratch. See `open-questions.md`.

See references [R6], [R7], [R8].

## 3. Alternatives considered and rejected

**Point the connector directly at the identity provider; the gateway is only a resource server.**
This is the smallest possible design and it was seriously considered — after §1.2 fell, it briefly
looked like the leading candidate. It requires the identity provider to be a complete authorization
server for MCP. Entra can be made to work, at the administrative cost described in §2. Keycloak
cannot do it properly: the per-endpoint scope-and-audience-mapper arrangement is an operational
cost rather than a technical impossibility, but it does not implement RFC 8707 — a client
requesting `resource` for one route and a scope for another would be served according to the scope.
Rejected because the requirement to support Keycloak makes the guarantee unavailable exactly where
it matters, and because it places session control outside the component that is accountable for it.

**Adopt an existing authorization server as the broker (for example Keycloak brokering to
Entra).** This is not rejected outright; it is deferred. But note that it does not escape the
problem by itself: a product placed in the broker position is now the thing facing the MCP
client, and must therefore handle `resource` honestly. Keycloak in that position inherits the
exact gap that motivated introducing a broker. Hence the asymmetry worth writing down plainly:
**Keycloak is supported as an upstream identity provider, not as the front towards the MCP
client.** Whether some other product qualifies is an open question with a defined entry filter.

**Support both modes — broker and passive resource server — as configuration.** Rejected for v1.
The cost is not the extra token validator. It is that the same administrative action means
different things in the two modes: revoking one connection, bounding a session to an absolute
lifetime, and listing active sessions are gateway-controlled guarantees in broker mode and
upstream-dependent ones in passive mode. Two modes means maintaining two security models, two
sets of documentation and two acceptance suites.

## 4. Gaps in the brief, independent of the above

These are requirements the brief omits rather than gets wrong.

1. **Per-client consent is mandatory, not optional.** Once the gateway is an authorization server
   with dynamic client registration in front of a single upstream client, it matches the MCP
   specification's confused-deputy configuration exactly, and the specification's mitigation is a
   `MUST`. See `security-model.md`.
2. **Identity must be `(issuer, sub)`.** The brief fixes `X-Auth-Subject` to Entra's `oid`, which
   is provider-specific. `oid` remains a useful additional attribute.
3. **Three distinct revocation events are conflated** under "revocation works": a local session
   revocation, an account disabled at the identity provider, and a role removed from a still-active
   user. The third is the easy one to miss — a successful refresh does not prove the entitlement
   survived.
4. **Revocation on an open stream is undefined.** "Refused on the next request" says nothing about
   an SSE stream already in flight or a tool call already executing.
5. **A provider may not invalidate the previous refresh token** when it issues a new one; this is
   reported for Entra and not verified here [C2]. Rotating our own tokens protects our chain; it
   would not change that property upstream.
6. **Token lifetime cannot simply be declared.** Upstream token lifetimes are the provider's
   policy — a default of 60–90 minutes is reported for Entra but not verified here [C2] — so the
   brief's "1 hour" is a policy to be configured, not a given, in any design relying on upstream
   tokens directly.

## 5. What this validation does not establish

- That the broker flow works with a real Claude connector. Only M0 shows that.
- That the authorization server should be written rather than adopted. See `open-questions.md`.
- That the reported `/token` failure has the cause guessed at in §1.3.
