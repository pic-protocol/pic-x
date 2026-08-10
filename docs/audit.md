# Audit Trail

PIC-X can write audit events to the log stream or to a file trail. The local and production sample
configs use the file trail.

## What It Is

| Part | Meaning |
| --- | --- |
| Records | JSON audit events for server lifecycle and admin actions |
| Chain | Each record links to the previous record digest |
| Day files | The file trail rolls by UTC day |
| Seals | The current head can be signed by the deployment key ring |
| Pseudonyms | Person subjects can be keyed and versioned instead of written in clear text |

The file trail is tamper-evident, not tamper-proof. It can show that records, days or seals no longer
verify; it cannot stop an attacker who can rewrite local disk from trying.

## Verify It

Local volume:

```sh
task audit:verify
```

Explicit directory:

```sh
pic-x audit verify --directory /var/lib/pic-x/operations/audit
```

With seal signature checks:

```sh
pic-x audit verify \
  --directory /var/lib/pic-x/operations/audit \
  --keys /backups/pic-x/jwks-2026-08-09.json
```

Use `--keys` with a JWKS exported from outside the restored or suspected host. Checking against keys
read from the same machine proves less.

## Export Keys for Audit Evidence

The keys that seal the trail are the operations ring's, and that ring is never served over HTTP.
Export its public halves from the ring on disk — it works with the server stopped:

```sh
pic-x keys export --directory /var/lib/pic-x/operations/keys > /backups/pic-x/jwks-2026-08-09.json
```

Keep exported key sets for at least as long as the audit trail. An operations key's public half is
kept until `audit.retention` even though its private half is deleted at `keys.retain`, so a seal
verifies for as long as the records it covers are kept — against a set exported before the key was
forgotten.

## Pseudonymisation

Production config enables:

```yaml
operations:
  audit:
    pseudonym:
      enabled: true
      key_ref: audit-pseudonym
      key_version: "v1"
```

`key_ref` is resolved by the configured secret store. Rotate the secret and `key_version` together.
The server keeps a witness under `operations/state/` so a changed key with the same version is
detected on the next start.

## Operating Rules

- Let shutdown complete; the audit sink is released last.
- Back up `audit/`, `keys/`, `state/` and the exported JWKS together.
- Protect the pseudonymisation secret like signing material.
- Use an off-host or append-only destination before treating the trail as enterprise evidence.
