# Backup and Restore

This is the runbook for the PIC-X `working_dir` volume. Back up the whole directory, export the JWKS
from the running deployment, and prove the restore before trusting it.

## At a Glance

| Rule | Why it matters |
| --- | --- |
| Back up the whole `working_dir` | `keys/`, `audit/` and `state/` must describe the same moment |
| Export `/.well-known/jwks.json` with each backup | Seal signatures should be checked against keys copied from outside the restored host |
| Prefer point-in-time snapshots | Copying a live filesystem can catch a day rollover or key change halfway through |
| Restore with the server stopped | A running process can append to the same files you are replacing |
| Verify before restart | A backup that has not been restored and checked is only an assumption |

## What to Save

| Path | Contains | If lost |
| --- | --- | --- |
| `keys/` | Signing key ring, including private material | Existing seals may no longer be signature-verifiable |
| `audit/` | Daily JSONL audit files and seals | The lost days are gone; verification reports the gap |
| `state/` | Local continuity state, including pseudonym key witnesses | PIC-X cannot distinguish a key rotation from a silent key swap |
| `secrets/` | Pseudonymisation key when `secrets.provider: directory` is used | New pseudonyms no longer match old pseudonyms |
| `data/` | Storage backend files, when a backend uses it | The shipped build currently uses memory storage, so there is no durable app data here yet |
| `tls/` | Local/demo certificates and private keys, if stored in the volume | Usually re-issue instead of restoring old transport certificates |

Save the whole volume as one unit. Do not restore `audit/` from one backup and `keys/` from another.

A deployment that hosts realms keeps a `keys/`, `audit/` and `secrets/` **per realm** under
`realms/<name>/`, alongside the server's own at the root:

```text
<volume>/
├── keys/  audit/  secrets/  state/     the server's own
└── realms/
    ├── acme/{keys,audit,secrets}/
    └── beta/{keys,audit,secrets}/
```

Each realm's ring signs that realm's trail, so a realm's seals verify against that realm's key set and
no other. Saving the whole volume together is what keeps every trail matched to the ring that sealed
it — see [realms.md](realms.md).

## Export the Key Set

The published key set is served from the active key ring and is not saved as a file in the volume.
Export it beside every backup:

```sh
curl -sf https://pic-x.example.com/.well-known/jwks.json > /backups/pic-x/jwks-2026-08-09.json
```

Use that exported file when verifying restored audit seals:

```sh
pic-x audit verify --directory /var/lib/pic-x/audit --keys /backups/pic-x/jwks-2026-08-09.json
```

If the host is under suspicion, do not fetch the JWKS from that same host after the restore and treat
it as independent evidence.

## Backup Schedule

| Item | Minimum rhythm | Notes |
| --- | --- | --- |
| Full volume snapshot | Daily | Snapshot storage is better than a live `tar` |
| JWKS export | With every volume backup and after key rotation | Keep it at least as long as the audit trail |
| Restore test | Regularly, and after changing storage or key settings | The test proves the procedure, not just the files |

Backup retention should be at least `keys.retain`. Audit retention is only useful for periods where
the corresponding signing keys can still verify seals.

## Restore Procedure

Restore into a clean directory first, verify, then swap it into place.

```sh
# 1. Stop PIC-X first.

# 2. Restore the complete volume into a clean directory.
mkdir -p /var/lib/pic-x.restore
cp -a /backups/pic-x/2026-08-09/. /var/lib/pic-x.restore/
chown -R 65532:65532 /var/lib/pic-x.restore

# 3. Verify the restored audit trail against the JWKS exported with the backup.
pic-x audit verify \
  --directory /var/lib/pic-x.restore/audit \
  --keys /backups/pic-x/jwks-2026-08-09.json

# 4. Move the verified volume into place, then start PIC-X.
mv /var/lib/pic-x /var/lib/pic-x.before-restore
mv /var/lib/pic-x.restore /var/lib/pic-x
pic-x /etc/pic-x/config.yaml
```

The container image runs as UID/GID `65532:65532`, so restored files mounted into the image must be
readable and writable by that identity.

## Permissions

`cp -a` preserves modes. Avoid `cp -r` for restores.

The directory secret store refuses secrets that are writable by anyone except the owner and warns
when they are readable by others. Mounted Kubernetes secrets are commonly readable by group or world;
that works, but writable secrets do not.

## What Verification Proves

`pic-x audit verify` checks:

- record digests;
- sequence continuity, including day boundaries;
- missing days inside the retained trail;
- seal coverage;
- seal signatures, when `--keys` is supplied.

The restore flow is covered by `tests/restore.rs`: the test starts the real binary, writes and seals a
trail, copies the volume, deletes the original, restores the copy, verifies it and starts the server
again.
