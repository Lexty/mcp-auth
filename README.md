# mcp-gate

A small reverse proxy that sits in front of **any** MCP server (Streamable HTTP) and owns
everything about "who is asking, and what are they allowed to do". The MCP server behind it
knows nothing about authorization and is not exposed: the gateway is the only public process,
the backend listens on loopback or a private network address.

Universality means one thing here: the gateway does not know what server is behind it, and does
not know what identity provider is above it. Documentation search, log access, query tools —
that is configuration, not code.

The goal is not primarily technical. A security reviewer must be able to **trust this and
operate it**: identity comes from an existing identity provider, access is granted through
mechanisms already in place, revocation works, actions are visible in an audit trail, and the
gateway is small enough to be read end to end in an evening. That last one is a requirement, not
a wish.

## Status

**Idea validated. No code yet. M0 not started.**

Validation was done jointly by two agents (Claude and Codex) on 2026-09-09 and reached a
conditional yes: the broker architecture is justified, but *not* for the reasons the original
brief gives. Two of the brief's three founding premises were refuted against primary sources.
Read [`docs/validation.md`](docs/validation.md) before doing anything else — several statements
the brief marks as "already established, do not re-check" are wrong, and building on them would
produce the wrong system.

Nothing here is settled until M0 passes. M0 is a gate, not a first sprint.

## Documentation

Start at [`docs/README.md`](docs/README.md), which explains how the documents compose and in
what order to read them.

| Document | What it answers |
| --- | --- |
| [`docs/brief.md`](docs/brief.md) | What was originally asked for |
| [`docs/validation.md`](docs/validation.md) | Which of those premises survived contact with the sources |
| [`docs/architecture.md`](docs/architecture.md) | What we are actually building |
| [`docs/security-model.md`](docs/security-model.md) | What the protocol obliges us to do |
| [`docs/audit-readiness.md`](docs/audit-readiness.md) | What a security review will ask for, and what that constrains |
| [`docs/operations.md`](docs/operations.md) | How it is deployed, diagnosed and upgraded |
| [`docs/m0-gate.md`](docs/m0-gate.md) | The experiment that decides whether any of this proceeds |
| [`docs/references.md`](docs/references.md) | Every external fact the above rests on, quoted and linked |
| [`docs/open-questions.md`](docs/open-questions.md) | What is deliberately undecided |
| [`docs/decisions/`](docs/decisions/) | Decisions taken, with the reasoning that produced them |

## Working in this repository

See [`AGENTS.md`](AGENTS.md). It is canonical for both human and agent contributors;
[`CLAUDE.md`](CLAUDE.md) points at it and adds Claude Code specifics.

## License and scope

A personal project. It is deliberately generic: no organisation-specific names, endpoints,
tenants or deployment details belong in this repository.
