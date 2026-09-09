# Open questions

Deliberately undecided. Each entry states what would decide it, so that it is closed by evidence
rather than by whoever writes code first.

---

## Q1. Write the authorization server, or adopt one?

**Status: open. Not to be decided before M0.**

That the broker architecture is justified does not establish that its OAuth machinery should be
written from scratch. Adopting a mature authorization server would move the cryptographically
dangerous part into audited third-party code, and a reviewer may well trust that more than a
hand-written one. The counter-argument — that operating a separate identity system is its own
burden — is real but is a matter for the operator, not a technical finding.

**Entry filter for any candidate.** The product would be the thing facing the MCP client, so it
must handle resource indicators honestly:

- an authorization request naming an unknown resource is rejected;
- a conflict between `resource` and requested scope does not widen access;
- a token issued for one resource is not accepted at another.

Beyond that filter it must also offer per-client consent, controllable revocation of a whole
session chain, and a storage model compatible with the deployment constraints. The filter is an
entry condition, not the full acceptance.

**What M0 added.** The client sends `resource` on both the authorization and token requests, so a
candidate can be tested against real traffic rather than against a reading of the RFC. It also
registers by Client ID Metadata Document, so a candidate must resolve those, with an admission
policy — not merely expose a registration endpoint.

**What is already known.** Keycloak does not pass the filter in this role: it does not implement
RFC 8707 [R8]. Note the asymmetry — as an *upstream* it is a good fit, because nothing in that role
depends on resource indicators. (Not because "only sign-in is required": every upstream still owes
the entitlement-freshness contract in `architecture.md`.) In the broker position it would inherit
the exact gap that motivates having a broker at all. Whether some other product passes has not been
established; a quick search did not settle it, and guessing is worse than leaving it open.

**Decided by:** M0 observations, plus an evaluation of candidates against the filter above.

---

## Q2a. Does the direct path work today?

**Status: open. This is what M0 Experiment A answers.**

Whether a real client, pointed at Entra with a pre-registered client and the MCP server URL
registered as an Application ID URI [R4], completes OAuth and calls a tool.

**Decided by:** M0 Experiment A. A success is a fact about today's configuration and today's
software versions, and it is worth exactly that.

*Narrowed 2026-09-09:* the broker path now works end to end with **both** a native client and a
hosted custom connector (`m0-observations.md`). That still says nothing about the direct path to an
identity provider, which is what this question is about.

## Q2b. What caused the historically reported failure to POST to `/token`?

**Status: hypothesis only, and M0 is not obliged to close it.**

The brief cites this as a reason the client cannot be pointed at Entra. The cited issue reports have
not been read here; what is recorded is that a peer found the later one to reference the earlier
one's observations, making them one report rather than two [C4].

A plausible explanation is that the symptom is the `AADSTS9010010` resource rejection [R4] seen from
the operator's side. Plausible is not established, and **Experiment A cannot establish it**:
succeeding with a corrected configuration shows that this configuration works, not why a different
one failed. Attributing a cause would need the original configuration or trace, or a deliberate
reproduction of the failure with one controlled variable changed.

**Decided by:** nothing currently planned, and that is an acceptable answer. Reopen only if the
direct path fails in a way that resembles the reports.

---

## Q3. Which transport revision must the proxy support?

**Status: open.**

The specification now describes MCP as stateless, and refers to server-assigned session
identifiers as belonging to protocol version 2025-11-25 and earlier [R15]. A gateway that proxies
for arbitrary backends cannot simply drop the session header on that basis: the supported client
and backend versions have to be pinned first. The gateway does not need an MCP session of its
own — its OAuth session is separate state — but it may need to pass one through faithfully.

**Narrowed 2026-09-09.** The version observed in the field is **`2026-07-28`** — no protocol
sessions, no GET stream, `server/discover` instead of `initialize`, and mirrored `Mcp-Method` and
`Mcp-Name` headers that agreed with the body on every request (`m0-observations.md`). What remains
open is how far back to support, which depends on the backends, not on the client.

**Decided by:** the versions the intended backends speak.

---

## Q4. What is the revocation boundary on an open stream?

**Status: open, and it is a product decision as much as a technical one.**

Long-lived streams remain in the current transport — a `subscriptions/listen` response stream stays
open [R18] — so a revocation can land while a stream is open and a tool call is executing.
Terminating the stream immediately is defensible; so is letting an in-flight call finish. What is
not defensible is leaving it undefined and discovering the answer during an incident.

The transport supplies a mechanism if we choose termination, but it delivers less than it looks
like — and it differs by revision. The precise position, with the normative verbs, is in
`security-model.md` under "Revocation boundary on open streams"; the short version is that closing a
stream reliably silences the response and does not reliably stop the work behind it.

Whatever is chosen is stated in `security-model.md` and demonstrated, and the reviewer is told
either way that revocation cannot undo an action already taken.

**Decided by:** an explicit decision record, informed by what M0 shows about stream lifetimes.

---

## Q5. How are entitlements re-read within a live session?

**Status: open.**

A role removed from a still-active user must stop granting access, and a successful upstream
refresh does not guarantee that information arrives — a refresh response may omit `id_token`
entirely [R7]. So re-reading entitlements is a mechanism the gateway must implement deliberately. The options
differ in cost and in blast radius: re-reading on every request, on a fixed interval, on refresh,
or only at session renewal.

Each supported upstream needs this written as a contract: where roles come from, in what shape,
how often they can be re-read without becoming a load problem, and what happens when the provider
is unreachable at that moment.

**Decided by:** measurement in M2 against both Entra and Keycloak, plus the timing the security
review will accept.

---

## Q6. Session lifetime defaults

**Status: open by design.**

The brief proposes one hour for an access token and twenty-four hours as an absolute session
bound, and says the final word belongs to the security reviewers. That remains true, and the
defaults in configuration are a starting point for that conversation rather than a conclusion.

Note also that upstream token lifetimes are the provider's policy, not ours — a 60–90 minute
default is reported for Entra but unverified here [C2] — so any design depending on upstream token
expiry cannot simply declare a number.

**Narrowed 2026-09-09, and one end of the range is now fixed.** The client refreshes proactively
up to five minutes before expiry, measured at 288.7 seconds (`m0-observations.md`). So an access
token lifetime at or below five minutes would be refreshed essentially on issue: the shortest
useful lifetime is bounded by the client's refresh window, not by our preference. Refresh rotation
is safe — five rotations, no replay of a retired token — so the design is not forced to weaken it.

**Decided by:** the security review, for the upper end.

---

## Q7. Are native clients supported, or only hosted ones?

**Status: open.**

The two client profiles differ in ways that reach the security model. Hosted clients connect from
the vendor's cloud and use a fixed HTTPS redirect URI [R17]. Native clients connect from the user's
machine over an RFC 8252 loopback redirect on an ephemeral port, and require the authorization
server to match `http://localhost/callback` and `http://127.0.0.1/callback` with the port ignored
[R16].

That exception weakens redirect matching, and the same source says why it cannot be repaired by
metadata alone: "any local process can bind a port and claim to be the legitimate client" [R16].
Supporting only hosted clients keeps redirect matching absolutely exact, which is one fewer thing to
justify to a reviewer — at the cost of not serving developers on their own machines.

*Sharpened 2026-09-09:* the exception is exercised in practice, not hypothetically. The observed
client registered two port-less loopback URIs and presented `http://localhost:57104/callback`
(`m0-observations.md`). Supporting native clients therefore means the port-agnostic match is real
code on a real path, not a footnote.

**Decided by:** a decision record, informed by whether local use is wanted at all.

---

## Q8. What happens when the identity provider is unreachable?

**Status: open, and currently referred to as undecided by every document that touches it.**

The cases are enumerated in `security-model.md`: a live session with no upstream call due; a live
session when a refresh or entitlement re-read is due and fails; a new sign-in; and whether
discovery reachability belongs in readiness.

The hard one is the second. Distinguishing "the provider says no" from "the provider did not
answer" matters: treating an absence of answer as a denial is fail-closed and may log everyone out
during an outage, while treating it as an approval is fail-open and unacceptable. There is a real
choice in between — a bounded grace period — and it has to be chosen deliberately, with the bound
written down.

**Decided by:** a decision record, informed by M2 measurements against both upstreams and by what
the security review will accept.
