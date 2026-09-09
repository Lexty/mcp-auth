# 0005 — Audit readiness and operability are requirements, not deliverables

**Date:** 2026-09-09 · **Status:** accepted

## Decision

Two properties are binding requirements on the same footing as correctness:

1. **The gateway is ready to pass a security review at an enterprise organisation at any time**,
   without special preparation.
2. **The gateway is convenient to operate**, by someone who did not write it.

They are documented in `audit-readiness.md` and `operations.md`.

## Why

The brief treats the security package as an M4 deliverable — a document produced at the end. That
is the wrong shape. If a reviewer's question can only be answered by doing new work, the answer
arrives late, under pressure, and is written to justify what was built rather than to describe it.
Audit readiness maintained continuously costs less and produces a better system, because it
constrains design: a mechanism that works but cannot be explained, evidenced or bounded does not
get built in the first place.

Operability is a security property here, not a convenience. This component decides who may reach
an internal service. A gateway that is awkward to deploy, diagnose or upgrade will be operated
badly — stale secrets, an unnoticed misconfiguration, a restart nobody wants to risk — and a badly
operated authorization gateway fails open in practice even when it fails closed in code.

## Consequences

- Acceptance criteria are demonstrable by a command with readable output. "The backend is not
  reachable from outside" is an assertion; the failed connection attempt is evidence.
- Limits are stated by the component before being asked for: what it does not protect against, and
  what personal data its audit trail carries.
- Diagnosis is designed for. Every denial is explainable from the audit record, and the four
  failure modes this component will actually have — clock skew, an expired client secret, an
  unreachable discovery endpoint, a wrong issuer — are distinguishable from each other in the error
  output.
- Configuration is validatable without starting the process, and refusing to start beats starting
  in a state that silently permits access.
- "Small enough to read in an evening" is enforced as an acceptance criterion, which means a
  dependency, a mode, or an abstraction layer must earn its place against it.
