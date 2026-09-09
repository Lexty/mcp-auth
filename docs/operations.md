# Operations

**Requirement.** The gateway must be pleasant to run. Operability is a first-class property, not a
consequence of the code happening to work: a component that is correct but awkward to deploy,
diagnose or upgrade will be operated badly, and a badly operated authorization gateway is a
security problem.

The audience is an operator who did not write the code and is reading this at an inconvenient hour.

Nothing here is implemented yet. This document states requirements; `audit-readiness.md` tracks
which of them have evidence behind them.

## Deployment

- **One directory.** Configuration, secrets, state file and audit log all live under a single
  deployment directory.
- **No global installation.** Nothing is installed on the host: use `npx`, `uvx` or containers
  instead of installing tools system-wide.
- **Moving is a configuration edit.** Changing tenant, identity provider, backend or route set is
  a configuration change and a restart. Never a rebuild, never a code change.
- `command` differs between orchestrators, and the difference is precise rather than
  approximate. In Compose, `command:` replaces the image's `CMD` while `ENTRYPOINT` still runs — so
  the effect is that it is appended to the entrypoint. In Kubernetes, `command:` replaces
  `ENTRYPOINT` and `args:` replaces `CMD` [R19]; in Compose, `command:` replaces the image's `CMD`
  while `entrypoint` still runs [R22]. A manifest written as though the two were the same
  silently drops the entrypoint or duplicates it.

### Teardown, stated precisely

The brief's criterion is that `docker compose down -v` leaves no trace outside the deployment
directory. Taken literally that is not achievable, and the exact reasons matter more than the
summary [R20]:

- `down` removes containers for services **defined in the Compose file**, networks declared in it,
  and the default network. `--remove-orphans` extends that to "containers for services not defined
  in the Compose file" — that is, services *removed from* the file since they were started, not
  containers belonging to something else.
- "Networks and volumes defined as external are never removed", and anonymous volumes are not
  removed by default; `-v` covers named volumes declared in the file plus anonymous volumes
  attached to containers.
- Images are never removed without `--rmi`, and `--rmi local` removes "only images that don't have
  a custom tag" — so a tagged project image survives it.

The requirement is therefore stated as a checkable property of *this project's* resources:

- The compose file declares no `external:` volume or network, and no anonymous volumes. Everything
  it creates, it owns and declares.
- `docker compose down -v --remove-orphans` removes every container, volume and network this
  project created, verified by comparing `docker ps -a`, `docker volume ls` and `docker network ls`
  filtered by the project label, before and after.
- Images are shared Docker resources and are explicitly outside the promise. Removing a tagged
  project image is `docker image rm`, deliberately, and it is the operator's choice.
- No file is written outside the deployment directory. Verified by running with that directory as
  the only writable mount.

## Configuration

- One configuration file, holding every value that distinguishes a laboratory from production. No
  behaviour is configurable in more than one place.
- **Validated at startup, and validatable without starting.** A subcommand checks a configuration
  file, reports every problem it finds rather than only the first, and exits non-zero. This is what
  an operator runs before a deployment and what CI runs on a configuration change.
- Errors name the specific setting, what was expected, and — **for non-secret values only** — the
  value that was rejected. A setting marked as a secret is reported by name and by the nature of
  the fault ("empty", "not valid base64", "file not readable"), never by value, and never in a way
  that leaks its length beyond what the fault requires.
- Refusing to start beats starting in a degraded or surprising state. In particular the gateway
  does not start with a configuration that would silently permit access.

## Secrets

- Supplied from files or environment variables. Never baked into an image, never committed, never
  printed — including in error messages, diagnostics and the audit log.
- Rotation is documented as a procedure with expected downtime, and the procedure is the one the
  maintainers actually use. A rotation that has never been performed is one that will not go
  cleanly at three in the morning.
- On startup the gateway reports which secrets it loaded and from where, by name and source only.

## Running it

- **Health and readiness are separate.** Health says the process is alive; readiness says it can
  serve. Whether reaching the identity provider's discovery document is part of readiness is
  **open** — it interacts with the undecided behaviour when the provider is unreachable
  (`security-model.md`), and stating it here would pre-decide that.
- **Metrics in Prometheus format**, on the administrative listener only.
- **The administrative surface is never on the public port.** Loopback or a private network address.
- **The same operations are subcommands of the binary**: list sessions, revoke one session, revoke
  every session of a subject. It is a Go binary; a separate client is unnecessary.
- Operational logs are structured and go to stdout. The audit trail is a separate file and is not
  mixed with them.

## Diagnosing

The commonest failure in a system like this is a configuration mismatch between three parties — the
client, the gateway and the identity provider — each behaving correctly by its own lights.
Diagnosis has to be designed for.

- **Every denial is explainable.** The audit record for a rejected request states which check
  failed. The client is told only what it needs to know.
- **A rejection is never a `500`.** A user without the required role gets a clear refusal and an
  audit line. This is an acceptance criterion because the alternative produces support tickets
  nobody can answer.
- A diagnostic subcommand exercises the upstream path — discovery, and a token request where
  possible — and reports what it found, so that "the provider is unreachable from here" is
  distinguishable from "the client secret expired" without reading source.
- Clock skew, an expired client secret, an unreachable discovery endpoint and a wrong issuer are
  each distinguishable from the others in the output. Those four will account for most of this
  component's failures.
- A runbook covers them symptom-first, because the symptom is what the operator has.

## State, backup and upgrades

The token and session store is a single file in the deployment directory and survives restart. Its
format is documented and versioned.

**Backup is not simply copying the file, and restoring is not simply safe.** Two things have to be
said plainly, because the first draft of this document got the second one wrong:

- *Consistency.* A live store cannot be copied byte-for-byte without a defined quiescent point or a
  snapshot mechanism. What constitutes a consistent backup depends on the storage format, which is
  not yet chosen; the format decision must include it.
- *Restoring moves state backwards, and that direction is not safe.* A backup taken before a
  revocation restores the revoked session as valid. A backup taken before a refresh restores a
  refresh token that has since been used, defeating one-time rotation. Restoring is therefore a
  security event, not a routine one.

  The mitigation must be part of the design rather than the runbook. Options include a monotonic
  epoch that a restore is required to advance, invalidating everything issued before it, or a
  revocation record kept separately from the session store so that revocations survive a restore of
  the sessions. **Open until the storage format is chosen**; until then the documentation must not
  promise that restoring is safe in any direction.

Other properties:

- A format change migrates forward automatically on startup, or refuses to start with a message
  naming what to run. It never starts by silently discarding state.
- Upgrades state their effect on live sessions explicitly. An upgrade that invalidates every
  session is acceptable if documented; one that does so unexpectedly is not.

## Dependencies

- Few, pinned to exact versions, and each justified in one line in the inventory: what it does and
  why the standard library was not enough.
- The inventory lives in the repository beside the module file and is updated in the same change
  that adds or removes a dependency. A dependency added without an inventory line is a defect.
- Every dependency is code a reviewer must also evaluate, which is the whole reason the list is
  meant to stay short.

## Build

- Reproducible from the repository, with no network access to anything beyond a declared module
  proxy.
- Static binary, minimal base image, non-root user, read-only root filesystem. The image contains
  the binary and nothing else useful to an attacker: no shell, no package manager.
- The binary reports its own version and build provenance on request, so a running process can be
  tied to a commit.

## Failure behaviour

- The gateway fails closed: if policy cannot be evaluated, access is refused.
- Behaviour when the identity provider is unreachable is **not yet decided** — see
  `security-model.md`, which lists the cases and what would settle them.
- If the gateway is down the backend is unreachable. That is the intended topology, and the
  consequence is documented for the reviewer rather than discovered during an incident.
- The audit log does not grow without bound, and it is readable without root.
