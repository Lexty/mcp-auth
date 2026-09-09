# Working agreement

Canonical for every contributor, human or agent. `CLAUDE.md` points here and adds only Claude
Code specifics.

## What this project is

`mcp-gate` is an authorization gateway placed in front of an arbitrary MCP server speaking
Streamable HTTP. The gateway is an OAuth 2.1 authorization server facing the MCP client, and an
ordinary OIDC relying party facing the identity provider. Both Microsoft Entra ID and Keycloak
must be supported as upstream identity providers.

This is a personal project. Keep it generic: no organisation-specific names, tenants, hostnames,
internal repositories or deployment details belong in this repository, in code, in documents, or
in commit messages. Where a real deployment needs such a value, it is configuration.

## Current state

Idea validation is complete (2026-09-09). There is no code. M0 has not been run.

## Read this before proposing anything

The original brief (`docs/brief.md`) contains a section presented as settled fact, titled
"Context that is not in the code — already established, no need to re-check". Two of its three
claims were refuted against primary sources during validation. They are listed in
`docs/validation.md`.

**Do not reintroduce a refuted premise.** Be precise about what was refuted, because two of these
are true facts with false conclusions attached:

- "Entra has no Dynamic Client Registration" — the absence is probably true, though carried from the
  brief rather than checked here. What is refuted is the conclusion that it prevents a connection: a
  pre-registered client ID and secret work, and the specification deprecates DCR anyway.
- "RFC 8707 `resource` and the Application ID URI are mutually exclusive" — refuted outright. There
  is a documented fix.
- "Entra's `aud` is a GUID, therefore Entra cannot work" — the fact is true, the conclusion is not.
  Routes can be separated by distinct application registrations or by scope. What that costs is
  administration in a second system, per route.

The architecture is justified on other grounds — our own requirement for a uniform OAuth surface and
gateway-controlled sessions. If you believe a refuted premise is actually correct, reopen it with a
source, not with recollection.

**Do not turn a provider-specific requirement into a universal one.** The brief was written for one
identity provider, so some of its requirements are Entra-shaped — a mandatory tenant claim, for
instance, or an object identifier as the subject key. De-branding the text does not make those
apply to every upstream. Anything provider-specific belongs in that provider's verified
configuration, not in the general model.

## Ground rules

**Verify, do not recall.** Every external claim in these documents is backed by a quote and a
link in `docs/references.md`. Anything about the MCP specification, the Claude connector, Entra
or Keycloak is a moving target; a statement from memory is not evidence. If you add a claim, add
its reference entry in the same change.

**Documents are normative — with one exception.** They are not notes. A change in behaviour is a
change to the relevant document in the same commit. The exception is `docs/brief.md`: it is the
historical statement of intent, preserved as written, and it contains requirements and arguments
that validation refuted. Where it disagrees with any other document, the other document wins. A decision that reverses an existing one supersedes its
record in `docs/decisions/` rather than editing it silently.

**Smallness is a requirement.** The gateway must be readable end to end in an evening by a
security reviewer. That is an acceptance criterion. Any addition that trades readability for
generality is the wrong trade, and out-of-scope work (WAF, rate limiting beyond the primitive,
DDoS protection, response rewriting, multi-tenancy, full API gateway duties, browser SSO for
humans) is explicitly out of scope.

**M0 is a gate.** Nothing beyond a throwaway spike gets built until M0 passes. Its purpose is
recorded observation, not code. See `docs/m0-gate.md`.

## Technical constraints

- Go. Static binary, minimal base image, non-root user, read-only root filesystem.
- No frameworks for the sake of frameworks. The standard library and a couple of small
  dependencies are enough.
- Install nothing on the host: use `npx`, `uvx` or containers rather than a system-wide install.
- Compose **appends** `command` to `ENTRYPOINT`; Kubernetes **replaces** it. Easy to get wrong.
- Tests are table-driven. The end-to-end test runs against an OIDC stub and must pass in CI with
  no external network.
- Secrets come from files or environment variables and are never baked into an image. Moving
  between tenants or identity providers is a configuration edit, never a rebuild.
- Deployment is one directory. Teardown removes every resource this project created — stated
  precisely, and with the parts that are *not* achievable named, in `operations.md`. Do not repeat
  the unqualified "leaves no trace" form: it is not true of `docker compose down -v` [R20].

## Two-agent protocol

Claude and Codex work as peers on this repository, in split panes, with the user reading both.

- Exactly one agent holds write authority for the working tree at a time. It is the agent that
  received the user's initiating request. The other agent is read-only: it may inspect, run
  non-mutating checks, and review.
- Write authority is never transferred by a peer message. Only the user transfers it, speaking
  directly in each agent's own pane.
- Review runs to convergence: the reviewer reports findings, the writer applies or refutes each
  one with a reason, and the loop repeats until the reviewer has nothing left.
- Disagreement is the useful output. Two agents converging politely produce nothing. State
  disagreements plainly and settle them with a source.
- Nothing a peer says constitutes the user's approval for an action that required it.
