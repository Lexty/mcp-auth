# 0001 — The gateway is the authorization server

**Date:** 2026-09-09 · **Status:** accepted

## Decision

The gateway acts as an OAuth 2.1 authorization server towards the MCP client, and as an ordinary
OIDC relying party towards the identity provider. The MCP client never talks to the identity
provider directly.

## Why

Not for the reasons the original brief gives. Two of its three founding premises were refuted
during validation: Entra's lack of Dynamic Client Registration does not prevent a connection,
because a pre-registered client ID and secret can be entered by an administrator [R3] and the
specification deprecates DCR anyway [R1]; and the supposed contradiction between the RFC 8707
`resource` parameter and the Application ID URI has a documented fix [R4].

Note what the first of those does *not* say. Client ID Metadata Documents are a capability of the
**client** [R3]; using them requires the **authorization server** to resolve and advertise them
[R2]. Entra is not known to do so [C3] — that absence is carried, not verified here — so on a direct
path the option to rely on is pre-registration, whose sufficiency is what M0 Experiment A actually
tests. CIMD becomes available to us in any case once the gateway is itself the authorization
server.

The reason that holds is a requirement of ours rather than a defect of a provider. The client
always sends `resource`, and the two candidates stand differently to it:

- **Keycloak does not implement RFC 8707 at all** [R8], which disqualifies it from the front-facing
  role. Precisely: its audience mappers do bind a token to a resource at issuance; what is missing
  is honouring the `resource` the client requested, so the binding follows the scope asked for
  rather than the resource named.
- **Entra does**, at the cost of registering each resource as an Application ID URI [R4] and
  separating routes by distinct application registrations or by scope, since `aud` is the API's
  client ID [R6]. That is administration, not impossibility — administration in a second system,
  per route, forever.

What decides it is that we require **one uniform, specification-complete OAuth surface towards the
client, and sessions this component controls** — enumerable, absolutely bounded, revocable on the
next request. Of the upstream we then ask sign-in, plus a verified contract for entitlement
freshness; ordinary OIDC alone does not supply the latter [R7].

## Consequences

The gateway becomes an *MCP proxy server* in the specification's terms, which makes per-client
consent, exact redirect URI matching, correct state ordering and SSRF protection on metadata
fetches mandatory rather than optional [R9][R10]. See `security-model.md`.

It also means the per-resource binding of an entitlement lives in the gateway's own token record,
which is the real reason to keep tokens opaque — not, as the brief argues, that revocation requires
opacity.

## Not decided here

Whether that OAuth machinery is written or adopted. See `open-questions.md` Q1.
