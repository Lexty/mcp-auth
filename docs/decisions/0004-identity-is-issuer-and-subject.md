# 0004 — Identity is `(issuer, sub)`

**Date:** 2026-09-09 · **Status:** accepted · **Supersedes:** the brief's `X-Auth-Subject` definition

## Decision

The primary key for a principal is the pair `(issuer, sub)`. Provider-specific identifiers are
additional attributes, never the primary key.

## Why

The brief fixes `X-Auth-Subject` to Entra's `oid`. That claim is specific to one provider, and the
gateway must work with at least two. Making a provider-specific field structurally mandatory
contradicts the property the design depends on: that the gateway does not know what identity
provider is above it.

Including the issuer matters as much as the subject: `sub` is only unique within an issuer, and a
gateway that accepts more than one upstream over its lifetime would otherwise be able to collide
two different people.

## Consequences

`X-Auth-Subject` carries the pair, or a stable derivation of it, and Entra's `oid` is forwarded as
its own attribute for backends that want it. Anything keyed on identity — the consent registry,
the session store, audit correlation, revoking every session of a subject — keys on the pair.

Note that Entra's `sub` is pairwise per application, while `oid` is stable across applications in
a tenant [R6]. Changing the upstream client registration therefore changes `sub`. That is
acceptable and is the correct behaviour, but it must be stated in the operations documentation
before someone discovers it during a migration.
