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
| token-signing keys | none | `realms/<name>/keys/` — enabled and rotating, published at its `jwks_uri` |
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
  expired, so nothing needs to verify it (`verify_retain` = `retain`, no archive phase). This ring
  (`realms/<name>/keys/`) is enabled and rotating; the `token_endpoint` that would use it answers
  `POST` with `501 Not Implemented` until issuance is built.

The server, being control plane, has an operations ring only.

## The surfaces

Resolution is by **path** — part of the request line, never a header a client can set. A realm decides
which key signs and which trail records; letting a client choose it with a header would be a
cross-tenant escalation.

```text
/.well-known/server-configuration                 the deployment: product, version, listed realms
/realms/<name>/                                    a human landing for that realm, pointing at its documents
/realms/<name>/.well-known/pic-x-configuration     that realm's issuer discovery (endpoints, capabilities)
{issuer}/keys  (i.e. /realms/<name>/keys)          that realm's token keys (GET)
{issuer}/token (i.e. /realms/<name>/token)         token exchange (POST) — 501 until issuance is built
```

The server publishes **no key set**: it issues nothing, and its operations key is internal. The realm
discovery document roots its endpoints (`token_endpoint`, `jwks_uri`) at the realm's `issuer`. Only
the token surface is advertised — this deployment hosts no revocation, attestation or trust-anchor
endpoints.

The realm discovery document exposes PIC-specific capability blocks under
`pic_context_of_authority`, `pic_continuity_proposals`, and `pic_continuity`.

The server document is a generic envelope over a `profiles` array — today one entry, the PIC profile
`https://pic-protocol.org/profiles/0.2`, carrying the realms. A future profile is another entry, not
a new shape.

## Configuration

```yaml
# ... public, telemetry, admin, tls, log, limits, and the shared `operations` block ...

public:
  url: https://pic-x.example.com  # realm issuers default to {public.url}/realms/<name>

realms:
  - name: acme                        # required; unique; [a-z0-9-], 1–40 chars (a URL path and a directory)
    issuer: https://acme.example.com  # optional; defaults to {public.url}/realms/acme — https outside dev
    listed: true                      # optional; default false — see below
    keys:                             # REQUIRED; the realm's TOKEN keys — its own lifecycle, never inherited
      publish_ahead: 1h
      rotate_every: 90d
      retain: 400d
    operations:                       # optional; overrides the shared operations block below
      audit:
        retention: 365d
        pseudonym:
          key_version: "v2"
      secrets:
        provider: environment         # this realm resolves its key from the environment instead
  - name: beta                        # inherits every operations setting, but still states its own keys
    keys:
      publish_ahead: 1h
      rotate_every: 30d
      retain: 365d
```

**Base ⊕ override, with one exception.** A realm inherits every server setting it does not state, and
overrides only what it does: its identity (`issuer`, `listed`) and its **operations** — the keys that
seal its trail, the trail, and its pseudonymisation (`operations.keys.*`, `operations.audit.*`,
`operations.secrets.*`). The exception is its **token keys** (`keys.publish_ahead/rotate_every/
retain`): signing policy is security, so a realm that signs tokens — every realm, unless it sets
`keys.enabled: false` — states its own token-ring lifecycle explicitly. It is **never** inherited from
`operations.keys` (a different key, sealing a different thing) and this build defaults none; a realm
that omits it is refused at load. Resolution happens once, at load; the rest of the build reads a
realm's complete, already-resolved configuration and never "the server's unless…".

Whatever the policy, a realm always keeps its **own** keys, trail and pseudonymisation key in its own
directory — the override changes the *cadence and destination*, never the *isolation*. Two realms with
the same rotation policy still rotate independently, because each has its own ring maintained by the
one loop.

**Issuers are https.** A realm's issuer — explicit, or derived from `public.url` — is a public
identity: it is what a relying party is told to trust and fetches keys from, and RFC 8414 requires it
to use https. A plaintext issuer is refused at load outside development mode, loopback included. The
listener is a separate question: behind an ingress or a service mesh that terminates TLS the process
serves this issuer over plain http on the wire and is right to, which is why the check is on the URL
clients are *told*, never the address the process binds.

**Secrets, per realm.** With `operations.secrets.provider: directory` (the default), a realm's key
lives in `realms/<name>/operations/secrets/` — isolated, and autogenerated in development. With
`provider: environment`, it resolves from an environment variable under a per-realm prefix that
defaults to `<server-prefix>_<REALM>` (e.g. `PIC_X_SECRET_ACME_AUDIT_PSEUDONYM`), so two realms cannot
collide. Both of a realm's key rings are held to the same overlap rules as the server's, per realm —
an override does not buy an exemption from arithmetic that would strand its own signatures.

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
    │   ├── keys/                        acme's token ring (enabled, rotating, published at jwks)
    │   └── operations/                  acme's own keys/ audit/ secrets/ state/ — isolated
    └── beta/
        ├── keys/
        └── operations/
```

Each realm is self-contained: a broken realm cannot corrupt another's trail or keys. Back it all up
together — see [backup-and-restore.md](backup-and-restore.md).
