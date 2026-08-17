# Backup and Restore

This is the runbook for the PIC-X `working_dir` volume. Back up the whole directory, export the
operations key set from the ring on disk, and prove the restore before trusting it.

## At a Glance

| Rule | Why it matters |
| --- | --- |
| Back up the whole `working_dir` | `operations/keys/`, `operations/audit/` and `operations/state/` must describe the same moment |
| Export the operations key set with each backup | Seal signatures should be checked against keys copied from outside the restored host |
| Prefer point-in-time snapshots | Copying a live filesystem can catch a day rollover or key change halfway through |
| Restore with the server stopped | A running process can append to the same files you are replacing |
| Verify before restart | A backup that has not been restored and checked is only an assumption |

## What to Save

The record-keeping subsystem lives under `operations/`, so it backs up as one unit:

| Path | Contains | If lost |
| --- | --- | --- |
| `operations/keys/` | The ring that seals the trail, including private material | Existing seals may no longer be signature-verifiable |
| `operations/audit/` | Daily JSONL audit files and seals | The lost days are gone; verification reports the gap |
| `operations/state/` | Local continuity state, including pseudonym key witnesses | PIC-X cannot distinguish a key rotation from a silent key swap |
| `operations/secrets/` | Pseudonymisation key when `secrets.provider: directory` is used | New pseudonyms no longer match old pseudonyms |
| `data/` | Storage backend files, when a backend uses it | The shipped build currently uses memory storage, so there is no durable app data here yet |
| `tls/` | Local/demo certificates and private keys, if stored in the volume | Usually re-issue instead of restoring old transport certificates |

Save the whole volume as one unit. Do not restore `operations/audit/` from one backup and
`operations/keys/` from another.

A deployment that hosts realms keeps the same `operations/` subsystem **per realm** under
`realms/<name>/operations/`, and — once it issues tokens — that realm's token ring at
`realms/<name>/keys/`, alongside the server's own at the root:

```text
<volume>/
├── operations/keys  audit  secrets  state     the server's own
└── realms/
    ├── acme/{keys, operations/{keys,audit,secrets,state}}
    └── beta/{keys, operations/{keys,audit,secrets,state}}
```

Each realm's operations ring seals that realm's trail, so a realm's seals verify against that realm's
key set and no other. Saving the whole volume together is what keeps every trail matched to the ring
that sealed it — see [realms.md](realms.md).

## Export the Key Set

The keys that seal the trail are the operations ring's. That ring's public halves are **not** served
over HTTP — they are internal — so export them from the ring on disk. `keys export` reads the ring
directly, which works with the server stopped, and prints the JWKS the verifier wants:

```sh
pic-x keys export --directory /var/lib/pic-x/operations/keys > /backups/pic-x/jwks-2026-08-09.json
```

Use that exported file when verifying restored audit seals:

```sh
pic-x audit verify \
  --directory /var/lib/pic-x/operations/audit \
  --keys /backups/pic-x/jwks-2026-08-09.json
```

Export it beside every backup, from the volume being backed up — not from a restored host under
suspicion. Keys taken from that host afterwards would check a signature against a key the same
attacker could have replaced. A realm's trail is verified the same way, against that realm's ring:
`pic-x keys export --directory /var/lib/pic-x/realms/<name>/operations/keys`.

## Backup Schedule

| Item | Minimum rhythm | Notes |
| --- | --- | --- |
| Full volume snapshot | Daily | Snapshot storage is better than a live `tar` |
| Key-set export | With every volume backup and after key rotation | Keep it at least as long as the audit trail |
| Restore test | Regularly, and after changing storage or key settings | The test proves the procedure, not just the files |

An operations key's public half is kept until `audit.retention` even though its private half is
deleted at `keys.retain`, so a restored seal verifies against the exported set for as long as the
records it covers are kept — provided that set was exported before the key was forgotten.

## Restore Procedure

Restore into a clean directory first, verify, then swap it into place.

```sh
# 1. Stop PIC-X first.

# 2. Restore the complete volume into a clean directory.
mkdir -p /var/lib/pic-x.restore
cp -a /backups/pic-x/2026-08-09/. /var/lib/pic-x.restore/
chown -R 65532:65532 /var/lib/pic-x.restore

# 3. Verify the restored audit trail against the key set exported with the backup.
pic-x audit verify \
  --directory /var/lib/pic-x.restore/operations/audit \
  --keys /backups/pic-x/jwks-2026-08-09.json

# 4. Move the verified volume into place, then start PIC-X.
mv /var/lib/pic-x /var/lib/pic-x.before-restore
mv /var/lib/pic-x.restore /var/lib/pic-x
pic-x /etc/pic-x/config.yml
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
