# 0002 — Keycloak is an upstream identity provider, not the front towards the client

**Date:** 2026-09-09 · **Status:** accepted

## Decision

Keycloak is supported as an upstream identity provider alongside Microsoft Entra ID. It is not
used as the authorization server facing the MCP client.

## Why

The roles demand different things, and Keycloak is asymmetric between them.

As an **upstream**, the demanding part of the protocol is not exercised: authorization code with
PKCE, discovery, and a claim carrying roles. Keycloak does that well. It is not literally "only
sign-in" — the entitlement-freshness contract below applies to every upstream — but nothing in the
upstream role depends on resource indicators.

As the **front towards the client**, it would have to handle the RFC 8707 `resource` parameter
honestly, because that is where the binding between an entitlement and a specific resource is
established. Keycloak does not implement resource indicators — its own guide lists them as a
roadmap item and states that Keycloak cannot recognise the parameter directly, rating MCP
2025-06-18 and later as only partially supported for that reason [R8]. Its Client ID Metadata
Document support is experimental.

The point generalises: anything placed in the broker position inherits that obligation. Keycloak
in that position would inherit the exact gap that motivates having a broker at all, and the
audience-mapper workaround would simply move up one storey without a gain.

## Consequences

"Supported upstream" means a verified configuration, not a claim about OIDC in general. For each
upstream we owe a written contract: where identity and roles come from and in what shape, how
entitlements are re-read inside a live session, when a disabled account starts being refused, and
what happens when the provider is unreachable. Support for ordinary OIDC does not imply any of
these — a refresh response may omit `id_token` entirely [R7].
