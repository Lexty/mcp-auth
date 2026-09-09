# 0003 — One OAuth mode in v1

**Date:** 2026-09-09 · **Status:** accepted

## Decision

v1 ships the broker mode only. A passive mode — where the identity provider faces the client
directly and the gateway is only a resource server — is not offered as configuration. Static-token
mode is retained, as specified in the brief, since it is a separate way of obtaining a synthetic
identity rather than a second OAuth surface.

## Why

The cost of two modes is not the extra token validator. It is that the same administrative action
carries different guarantees in each:

| Requirement | Broker | Passive resource server |
| --- | --- | --- |
| Revoke one connection | Own access/refresh chain | Depends on available upstream identifiers |
| Bound a session to 24 hours | Gateway-controlled | Needs a proven way to link tokens |
| List active sessions | Own registry | Sees requests and tokens, not sessions |
| Add a separate resource | Gateway configuration | Gateway *and* external authorization server |

A shared interface in the code does not make those guarantees the same. Supporting both means
maintaining two security models, two sets of documentation and two acceptance suites — against a
project whose central requirement is that a reviewer can read the whole thing in an evening.

## Consequences

The passive shape is still worth building once, as a control experiment in M0, precisely because
the premises that made it look impossible were refuted. Building it to learn is not the same as
shipping it as a supported mode. See `m0-gate.md`.
