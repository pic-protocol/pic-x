<!-- Copyright (c) 2022 Nitro Agility S.r.l. -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# Security posture

What this codebase defends against, what it deliberately delegates, and the constraints future work
has to respect. The threat analysis behind this page lives in the review history; this is the part
that has to stay true.

## What a surface defends itself against

Every listener — public, administrative and telemetry alike — serves inside the bounds the `limits`
block of [config.template.yml](../config.template.yml) documents: connection pool and per-address
share, handshake, header and request deadlines, header and body byte caps, request concurrency with
load shedding, a write-stall bound, and an optional connection lifetime. Each is tested as the attack
it stops, not as a getter.

Mutual TLS is **authentication and authorisation, separately**. `client_ca` decides which
certificates are genuine; the `allow` list beside it decides which of those peers the surface is
for — because an authority signs every client it was ever asked to. An authenticated peer off the
list gets `403` and a log record naming it; an empty list means the handshake is the whole decision.
The administrative surface keeps its own list under `admin.allow`, checked on every call and audited
both ways.

Revocation-list expiry is **enforced**: a CRL past its `nextUpdate` refuses every mutual-TLS
handshake, deliberately — an expired list is revocation data nobody is maintaining, and the
alternative is a revoked client that stays admitted for months.
`picx_tls_crl_expiry_timestamp_seconds` exists so that moment is predicted by an alert, not
discovered as an outage.

## Constraints on future work

These are design decisions, not omissions. Changing one is a review, not a refactor.

- **Rate limiting belongs in front of the server.** None of the limits is a rate limiter, because
  rate limiting needs to know who a client *is* over time — an identity question, owned by the
  ingress or by a build with a notion of tenant. **The constraint this creates:** no endpoint that
  verifies a credential — the token-exchange endpoints the realms already describe configuration
  for — ships without a per-principal throttle in front of it, at the ingress or in process. An
  unthrottled credential check is a brute-force oracle.
- **The file audit sink is for administrative cadence, never per-request.** It flushes each record
  to disk synchronously, on the runtime thread, because ordering the trail is the point. A realm
  that audits per data-plane request needs a sink that batches; putting request-rate traffic through
  this one turns a slow disk into a reactor stall.
- **The environment is a development-grade secret store.** `secrets.provider: environment` outside
  `development_mode` is allowed — the deployment decides — and warned about at startup: a process's
  environment is readable through `/proc` and inherited by every child.

## Delegated, and to what

- **Network segregation of the telemetry surface** is the deployment's job: telemetry has a listen
  address of its own precisely so a firewall or NetworkPolicy can allow scraping and refuse
  everything else. A deployment that exposes it alongside the public surface has removed that
  separation itself.
- **Real client addresses behind a load balancer.** The per-address connection share counts the
  address on the socket. Behind a balancer that is the balancer, so either exempt its block with
  `limits.peer_exempt` or set `limits.connections_per_peer: "0"` and count at the ingress.

## Roadmap

Accepted gaps, in the order they should close:

1. **The audit seal must leave the machine.** Today the chain and its signed seals live on the
   volume they attest to, which makes tampering evident to whoever holds the trail and to nobody
   else. The design anticipates the fix — one digest attests to everything before it — and the
   shipping mechanism (a remote sink, an append-only store, even the structured log stream) is not
   built yet.
2. **Deployment manifests that segregate telemetry by default** — when Kubernetes material ships
   for this repository, it ships with a NetworkPolicy allowing telemetry ingress only from the
   scraping namespace.

## Reporting

Report vulnerabilities privately to the maintainers, never through a public issue.
