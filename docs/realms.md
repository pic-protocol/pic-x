# Realms

A realm is an **issuer**: its own token-signing keys, its own audit trail, its own pseudonymisation.
One deployment can host many. The server that hosts them is not one of them — it seals the system
trail and lists the realms, and it issues nothing.

If you host a single issuer, you need none of this: leave `realms:` out and the server serves
everything under its own root. Realms are additive.

## Server, or realm

| | the server (control plane) | a realm (an issuer) |
| --- | --- | --- |
| issues tokens | no | yes |
| token-signing keys | none | `realms/<name>/keys/` — published at its `jwks_uri`, reserved until token issuance exists |
| operations keys (seal the trail) | `operations/keys/` — the **system trail** | `realms/<name>/operations/keys/` — that realm's trail |
| audit trail | `operations/audit/` | `realms/<name>/operations/audit/` |
| pseudonymisation key | `operations/secrets/audit-pseudonym` | `realms/<name>/operations/secrets/audit-pseudonym` — a *distinct* key |

A realm's pseudonymisation key is its own on purpose: the same subject pseudonymised in two realms
must not be recognisable as the same subject across them. That per-tenant key is the privacy property
a realm exists to give.

### Two rings, two domains

The keys split by **who has to trust them**:

- **operations keys** protect the deployment's own records — they seal a trail. Their public halves
  are an operator's concern, reached through the administrative surface (or `pic-x keys export`) and
  **never served over HTTP**. Their private half is deleted at `keys.retain`; their public half stays
  (`archived`) until `audit.retention`, so a seal keeps verifying for as long as the trail it covers
  is kept.
- **token keys** sign what a realm hands to third parties. Their public halves are the realm's
  `jwks_uri`, read by relying parties worldwide, and are short-lived — a token older than `retain` has
  expired, so nothing needs to verify it. This ring is reserved (`realms/<name>/keys/`) and does not
  exist until token issuance does; until then a realm's `jwks_uri` publishes an empty set.

The server, being control plane, has an operations ring only.

## The surfaces

Resolution is by **path** — part of the request line, never a header a client can set. A realm decides
which key signs and which trail records; letting a client choose it with a header would be a
cross-tenant escalation.

```text
/.well-known/server-configuration                 the deployment: product, version, listed realms
/realms/<name>/.well-known/pic-x-configuration     that realm's issuer discovery (endpoints, capabilities)
{issuer}/keys  (i.e. /realms/<name>/keys)          that realm's token keys — empty until issuance exists
```

The server publishes **no key set**: it issues nothing, and its operations key is internal. The realm
discovery document roots every endpoint (`token_endpoint`, `jwks_uri`, `attestations_endpoint`,
`trust_anchors_endpoint`) at the realm's `issuer`.

The server document is a generic envelope over a `profiles` array — today one entry, the PIC profile
`https://pic-protocol.org/profiles/0.2`, carrying the realms. A future profile is another entry, not
a new shape.

## Configuration

```yaml
# ... the common server configuration: web, telemetry, grpc, tls, log, limits, keys, audit ...

issuer: https://pic-x.example.com     # the server's own public URL, if it has one

realms:
  - name: acme                        # required; unique; [a-z0-9-], 1–40 chars (a URL path and a directory)
    issuer: https://acme.example.com  # optional; the realm advertises this
    listed: true                      # optional; default false — see below
    keys:                             # optional; any field absent inherits the server's
      rotate_every: 90d
      retain: 400d
    audit:                            # optional
      retention: 365d
      pseudonym:
        key_version: "v2"
    secrets:                          # optional
      provider: environment           # this realm resolves its key from the environment instead
  - name: beta                        # states nothing but its name → inherits everything
```

**Base ⊕ override.** A realm inherits every server setting it does not state, and overrides only what
it does: its identity (`issuer`, `listed`), its key lifecycle (`keys.enabled/publish_ahead/
rotate_every/retain`), its audit trail (`audit.sink/retention` and `audit.pseudonym.*`), and where it
resolves secrets (`secrets.provider/env_prefix`). Resolution happens once, at load; the rest of the
build reads a realm's complete, already-resolved configuration and never "the server's unless…".

Whatever the policy, a realm always keeps its **own** keys, trail and pseudonymisation key in its own
directory — the override changes the *cadence and destination*, never the *isolation*. Two realms with
the same rotation policy still rotate independently, because each has its own ring maintained by the
one loop.

**Secrets, per realm.** With `secrets.provider: directory` (the default), a realm's key lives in
`realms/<name>/operations/secrets/` — isolated, and autogenerated in development. With
`provider: environment`, it resolves from an environment variable under a per-realm prefix that
defaults to `<server-prefix>_<REALM>` (e.g. `PIC_X_SECRET_ACME_AUDIT_PSEUDONYM`), so two realms cannot
collide. A realm's key lifecycle is held to the same overlap rules as the server's, per realm — an
override does not buy an exemption from arithmetic that would strand its own signatures.

### `listed` is fail-closed

Default **false**. A realm appears in the server's public catalogue only if it opts in — a zero-trust
deployment does not enumerate its tenants to the world. A realm that is not listed is still reachable
at its own path: a client that knows the name can always fetch the keys it needs to verify a token.

## One process, one loop

Hosting many realms costs a loop, not a thread. The key service maintains the server's ring and every
realm's ring in **one sequential pass** on one timer — a broken realm is logged and skipped, never a
task apiece. TLS reload stays server-wide; audit seals happen inline; shutdown seals every realm's
trail in sequence. Nothing about a second realm adds a second moving part.

## Telemetry and logs

Every realm-scoped record carries `realm=<name>` (`realm=server` for the control plane), so the log
separates issuers. `picx_keys_active{realm="…"}` publishes, per issuer, whether it currently has a key
that will sign — the one number worth alerting on per realm.

## On disk

```text
<volume>/
├── operations/                         the server's own record-keeping subsystem
│   └── keys/  audit/  secrets/  state/
└── realms/
    ├── acme/
    │   ├── keys/                        acme's token ring (reserved until issuance exists)
    │   └── operations/                  acme's own keys/ audit/ secrets/ state/ — isolated
    └── beta/
        ├── keys/
        └── operations/
```

Each realm is self-contained: a broken realm cannot corrupt another's trail or keys. Back it all up
together — see [backup-and-restore.md](backup-and-restore.md).
