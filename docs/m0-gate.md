# M0 — the gate

M0 is a gate, not a first sprint. Until it passes, nothing beyond a throwaway spike is built.
Its output is **recorded observation**, not code. Every later stage depends on what is learned
here, and the reason is stated plainly in the brief: the MCP client's OAuth behaviour is poorly
documented, and the last time it was reasoned about from documentation and recollection, two of
three founding premises turned out to be wrong.

## Two experiments, in this order

The brief describes one experiment. There must be two, because the premises that made the direct
path look impossible have been refuted and the direct path therefore has to be tried before a
broker is justified by anything other than argument.

### Experiment A — the direct path, as a control

Point a real custom connector at the identity provider directly. The gateway is a minimal
resource server: it validates the upstream token, and calls one tool.

- Use a pre-registered client [R3]. The identity provider need not support dynamic registration,
  and Entra is not known to support Client ID Metadata Documents either [C3] — support in the
  client implies nothing about support in the authorization server [R2].
- Register the MCP server URL as an additional Application ID URI, exactly, including the path and
  without a trailing slash [R4]. Confirm first that tenant policy permits it — whether an arbitrary
  HTTPS URL is acceptable there is itself unverified [C1].

The purpose is to avoid building a solution on refuted premises. It is a control, not a
competition.

**Its success does not remove the requirements for gateway-controlled sessions. Its failure does
not prove that a broker would work.**

### Experiment B — the broker path

A minimal authorization server of our own: no identity provider, no policy, in-memory storage,
identity hard-coded. Drive a real custom connector to the state where OAuth completes and a tool
is called.

Experiment B is required regardless of how A turns out. Choosing the broker architecture on the
strength of argument alone, without having seen a real client complete a flow against our own
authorization server, is the failure mode this gate exists to prevent.

## Departure from this order, recorded 2026-09-09

Experiment B was built and run first, because Experiment A needs an Entra tenant that does not yet
exist. This is a departure from the order above and is written down rather than quietly taken.

It is defensible only because B is required regardless of how A turns out. It is **not** a
substitute for the control experiment, and **M0 is not passed**. Two conditions remain open:

- Experiment A has not been attempted at all.
- The client observed so far is a **native** client running on the operator's own machine. A
  successful tool call through a real custom connector on a hosted surface is a separate mandatory
  result. The two profiles differ in where the connection originates, in the redirect URI, and in
  the exposure they require [R16][R17]; observing one says little about the other.

## What must be recorded

The deliverable is the observation log. Absent branches are recorded as absent — "not observed"
is a finding, and silence is not.

**Client registration**
- Which registration mechanism was actually selected: pre-registration, CIMD, or DCR.
- If CIMD: what the client's metadata document contained, and whether both required pieces of
  authorization server metadata had to be advertised for it to be chosen.
- If DCR: the exact registration request, the redirect URIs registered, whether an application
  type was sent, and whether a new client was registered per connection.

**Authorization and token**
- Whether `resource` was sent, on which requests, and with exactly what value.
- Which scopes were requested, and where they came from.
- The PKCE method used.
- The exact form of the token request, including content type.

**Refresh and expiry**
- Whether the client refreshes at all, and when relative to expiry.
- What it does on a `401`.
- Whether it re-authorises without user interaction, or prompts.
- Whether a rotated refresh token is accepted and used.
- Which error code on a failed refresh produces a clean re-authorisation rather than a stuck
  connection.

**Transport**
- The protocol version negotiated, which determines whether protocol-level sessions and a GET
  stream exist at all [R18].
- Whether a session identifier header is used, and whether the proxy has to preserve it.
- Whether the `Mcp-Method` and `Mcp-Name` headers are present and agree with the body [R18].
  **Observing that a well-behaved client sends them correctly proves nothing about enforcement.**
  What has to be tested is the negative case: send a request whose header and body disagree, and
  record whether the backend rejects it with `HeaderMismatch` before executing, or executes the
  body. That answer, not the positive observation, decides whether per-tool policy can ever be
  enforced from headers. See `security-model.md`.
- Whether a client stream closing propagates to the backend request, and whether the backend
  actually stops — stopping work is only a `SHOULD` [R18].
- Whether long-lived streams appear, and how they behave when the connection is interrupted.

**Entitlement lifecycle** (in Experiment A, against a real identity provider)
- What claims arrive after a refresh, compared with the initial sign-in.
- What happens when a role is removed from an active user, and how long it takes to matter.
- What happens when the account is disabled, and how long it takes to matter.
- What two parallel connections by the same user look like, and whether anything distinguishes
  them.

**Timing**
- Observed latency of discovery, registration and token endpoints, against the client's documented
  timeouts of 10 seconds for discovery, registration and token, and 30 seconds for refresh [R16].

## Recording rules

- Secrets, tokens and authorization codes are redacted in the log. Their presence, shape and
  length may be recorded; their values may not.
- Record what was observed, separately from what it is thought to mean.
- A single user report is not evidence of a cause. Where an external issue report motivated an
  experiment, record what this run observed, not what the report concluded.

## Exit criteria

Two classes of observation, and only one of them may be left unobserved.

**Mandatory and reproducible.** Each must be exercised deliberately, not waited for, and each must
be reproduced at least once:

1. A real client completes OAuth against the minimal authorization server and calls a tool
   (Experiment B).
2. An access token expires and the client obtains a new one, or demonstrably fails to. Force expiry
   with a short lifetime rather than waiting for a default.
3. The client is served a `401` on a request it believes is authorized, and its reaction is
   recorded.
4. A rotated refresh token is issued and the client's next refresh is observed — whether it
   presents the new one, and what happens if it presents the old.
5. A refresh is refused with `invalid_grant`, and it is recorded whether the client
   re-authorises cleanly or the connection is left stuck.
6. The direct path has been attempted and its outcome recorded, whatever it was (Experiment A).

Without 2 through 5 the gate is weaker than the design needs, because token lifetime, rotation and
the absolute session bound all rest on how the client behaves at expiry — and every one of those is
a number this component must choose.

**Permissibly unobserved.** Client behaviour that did not arise on its own — a particular
registration mechanism not selected, a transport revision not negotiated, a stream type not opened.
These are recorded as not observed, which is a finding rather than a blank.

Passing M0 licenses choosing an authorization server implementation. It does not by itself license
promoting the spike into a production component — see `open-questions.md` Q1.
