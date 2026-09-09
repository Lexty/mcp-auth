# Audit readiness

**Requirement.** The gateway must be ready to pass a security review at an enterprise organisation
without special preparation. Audit readiness is a property of the system at all times, not a
document produced at the end. If a reviewer asks a question and the answer requires new work, that
is a defect.

This is binding, on the same footing as correctness. It constrains design: a mechanism that works
but cannot be explained, evidenced or bounded is not acceptable here.

## Status

There is no code yet, so nothing below has evidence. Recording that honestly is the point of this
table — a review-readiness document that reads as though answers exist is worse than none.

| Question a reviewer will ask | Where it is answered | Status |
| --- | --- | --- |
| What are the trust boundaries and what crosses them? | `architecture.md` | Written |
| What does the gateway see, and what can it not see? | `architecture.md` | Written |
| What is stored, where, in what format? | `architecture.md`, `operations.md` | **Format not chosen** |
| How is a backup taken, and what does restoring it undo? | `operations.md` | **Open — depends on the format** |
| What is written to the audit log, and what is deliberately not? | `security-model.md`, canonical schema | Written |
| How is access granted, and how is it revoked? | `security-model.md` | Written |
| How fast does each kind of revocation take effect? | `security-model.md`, three revocation events | **Two of three bounds are TBD** |
| What happens to an open stream when access is revoked? | `security-model.md` | **Open decision** |
| What happens when the identity provider is unreachable? | `security-model.md` | **Open decision** |
| How are secrets supplied and rotated? | `operations.md` | Requirement written, procedure not yet performed |
| What third-party code is in it, and why? | `operations.md`, dependencies | Requirement written, inventory empty (no code) |
| Can the build be reproduced? | `operations.md`, build | Requirement written, no build yet |
| What does this explicitly not protect against? | below | Written |
| What personal data does it hold, and for how long? | below, and the canonical schema | Fields written; whole record is identifiable; retention not implemented |

An entry moves from a requirement to evidence when a command or a test demonstrates it. Until then
it says so.

## Evidence, not assertions

Every acceptance criterion must be demonstrable by a command a reviewer can run, with output they
can read. "The backend is not reachable from outside" is an assertion; a connection attempt from
outside, failing, is evidence. The acceptance criteria in `brief.md` are written in that style
deliberately, and the style is binding:

- a forged inbound `X-Auth-*` header changes nothing — shown by a request carrying one;
- the backend is unreachable from outside — shown, not claimed;
- the audit log contains no tokens or secrets — shown by a search over a log from a real session;
- a session revoked through the admin surface is refused on the next request — shown with
  timestamps;
- static-token mode produces the same audit records as OIDC mode — shown side by side.

Where a criterion cannot be demonstrated by a command, it is demonstrated by a test in the
repository that a reviewer can read and run.

## Readable in an evening

The brief makes this a requirement rather than a wish. It is repeated here because it is the
property most likely to be traded away silently, one reasonable addition at a time.

Consequences, binding:

- Prefer the standard library. Every dependency is something the reviewer must also evaluate.
- Prefer one obvious way to do a thing over a configurable choice between two. This is the reason
  v1 has a single OAuth mode (`decisions/0003`).
- Security-relevant logic lives in a small number of named places, not spread thin behind
  abstraction. The JSON-RPC parsing boundary is the deliberate exception, and it exists to keep the
  proxy from being rewritten later, not to add generality now.
- Out-of-scope work stays out: WAF behaviour, rate limiting beyond the primitive, DDoS protection,
  response rewriting, multi-tenancy, general API gateway duties, browser SSO for humans.

## Stated non-protections

A review goes better when the component states its limits before being asked. These are design
positions, not gaps to be closed later:

- Not a WAF. No content inspection of request or response bodies beyond what policy evaluation
  requires.
- No defence against denial of service. Placing it behind whatever the organisation already uses
  for that is expected.
- It does not protect a backend that is separately reachable. Backend isolation is a deployment
  property the gateway cannot enforce, which is why it is on the acceptance list.
- A network allow-list restricting inbound traffic to a client vendor's published egress range
  reduces exposure. It is not authorization and is never counted as any.
- It trusts its upstream identity provider's assertions about identity and roles. It validates
  them; it cannot detect a compromised identity provider.
- It does not bound what an authorized user does with an authorized tool. That is the backend's
  concern.
- Revocation cannot undo an action already taken.

## Privacy surface

The audit trail is an identifiable history of user activity — not a neutral log with three personal
fields in it. `(issuer, sub)` identifies the user by this design's own definition, the session
identifier links to them, and the remaining fields describe what that identified person did.
Removing the fields marked as personal would not anonymise it. The canonical field list lives in
`security-model.md` and is not restated here, so that the two cannot drift apart.

What this document adds:

- Request and response bodies are never recorded. Tool arguments only behind a flag that is off by
  default, whose risk is documented where the flag is configured.
- Retention is bounded and configurable, and the bound is enforced by the component itself rather
  than by an external log rotation the operator may not have configured. **Not implemented.**
- The log is readable without root, which makes its permissions a deliberate choice that must be
  justified rather than inherited.
