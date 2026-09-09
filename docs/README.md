# Documentation

These documents are the design record, not notes, and they live in the repository so that a
security reviewer can read the reasoning and the result together.

**One document is not normative: `brief.md`.** It is the historical statement of intent, preserved
as written, and it contains requirements and arguments that validation refuted. Where it disagrees
with anything else here, the other document wins. Everything apart from `brief.md` is binding.

## How they compose

The set is a chain of custody for the design: what was asked, what survived checking, what
follows from that, and what the whole thing rests on.

```
brief.md ───────────► validation.md ───────────► architecture.md
what was asked        which premises held        what we build
                             │                          │
                             │                ┌─────────┴─────────┐
                             │                ▼                   ▼
                             │        security-model.md   audit-readiness.md
                             │        what the protocol    what a reviewer
                             │        obliges              will ask for
                             │                │                   │
                             ▼                │                   ▼
                      open-questions.md       │            operations.md
                      what stays undecided    │            how it is run
                             │                │                   │
                             └────────┬───────┴───────────────────┘
                                      ▼
                             decisions/NNNN-*.md
                             choices, with reasons
                                      │
                                      ▼
                               references.md
                          every external fact, quoted
                                      ▲
                                      │
                                  m0-gate.md
                          the experiment that adds new facts
```

`references.md` sits under everything. No document above it may assert an external fact that does
not appear there with a quote and a link.

## Reading order

1. **`brief.md`** — the original requirement, translated and de-branded. **Historical, not
   normative.** Read it for intent, not for facts.
2. **`validation.md`** — the outcome of checking that brief against primary sources. Two of three
   founding premises were refuted; the architecture survives on a different justification. This is
   the most important document here.
3. **`architecture.md`** — the shape that follows, and the shapes that were rejected.
4. **`security-model.md`** — the obligations the MCP specification places on this design, and the
   revocation semantics the brief left ambiguous.
5. **`audit-readiness.md`** — the standing requirement that a security review can happen at any
   time without preparation, and what that constrains.
6. **`operations.md`** — the standing requirement that the thing is pleasant to run, and what that
   constrains.
7. **`m0-gate.md`** — the gate. Two control experiments, and the observations they must produce.
8. **`open-questions.md`** — what is deliberately not decided, and what would decide it.
9. **`decisions/`** — one record per decision taken, newest number last.
10. **`references.md`** — the evidence base. Consult it whenever a claim above matters to you.

## Conventions

- English throughout. No organisation-specific names, tenants, hostnames or deployment details.
- A decision record is superseded, never rewritten. If a decision reverses, add a new record and
  mark the old one superseded by it.
- A claim about the MCP specification, the Claude connector, Microsoft Entra or Keycloak must cite
  `references.md`. Those four are moving targets, and every one of them contradicted a confident
  recollection during validation.
- A `[R…]` tag points at a quoted, checked source. A `[C…]` tag points at a claim carried from a
  peer and **not** independently verified: no decision may rest on one.
- An unresolved point is written as **TBD** or **open**, with what would close it, and never as a
  guarantee awaiting detail. A document may not refer to another document's undecided behaviour as
  though it were settled.
- Requirements written before there is code say so. `audit-readiness.md` carries the status table
  that keeps that honest.
- Dates are absolute.
