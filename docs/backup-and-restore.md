# Backing up the volume, and restoring it

Everything this deployment keeps lives in one directory — the `working_dir` — and the reason it is one
directory is this document: what has to be saved together is saved together, and there is no second
place to forget.

A backup nobody has restored is not a backup. The last section is the one that matters.

## What is in there, and what losing it costs

| directory | what it is | what losing it costs |
| --- | --- | --- |
| `keys/` | the signing key ring, private material included | **every seal ever written becomes unverifiable.** The published key set is derived from this ring; without it there is nothing left to check a signature against, and the audit trail keeps its chain but loses its attestation |
| `audit/` | one file per UTC day, each carrying the digest of the day before, plus the seals | the days you lost. The chain still verifies across what remains, and `audit verify` reports the gap rather than hiding it |
| `secrets/` | the pseudonymisation key, when it is resolved from here | pseudonyms written after the loss no longer match the ones written before, so "did this account do that" stops being answerable *across* the loss. Usually a mounted secret, in which case it is backed up wherever secrets are |
| `state/` | what the server remembers about its own configuration — including what each pseudonym key version produces | the server can no longer tell a rotated key from a swapped one, which is the check that stops a silent ruin of the trail |
| `data/` | whatever the store keeps | depends on the store. The shipped build keeps this in memory, so today: nothing |
| `tls/` | certificates and private keys | usually nothing worth restoring — re-issue instead. A restored certificate is one you have to remember to stop trusting |

The first two are the ones this product exists to protect. Everything else is replaceable.

### One thing that is not in the volume

The **published key set** — `/.well-known/jwks.json` — is served from the ring in memory and is not
written to disk. It is what `audit verify --keys` checks a seal's signature against, and it has to
come from somewhere an attacker could not have edited, which is exactly why it is not read from the
machine under suspicion by default.

So export it beside every backup, from the running deployment:

```sh
curl -sf https://pic-x.example.com/.well-known/jwks.json > /backups/pic-x/jwks-2026-08-09.json
```

Keep those alongside the volume snapshots and for at least as long. A seal is only worth what the key
set that checks it is worth.

## What has to be saved together

`keys/`, `audit/` and `state/` are one unit, not three.

A seal names the key that signed it (`kid`), and that key has to be findable in the published set for
the seal to be checkable. Restoring an audit trail beside an older key ring produces seals signed by
keys the ring has since retired and dropped — signatures that were valid when made and cannot be
checked now. Restoring a newer ring beside an older trail has the same effect from the other
direction.

So: snapshot the whole volume, not selected directories inside it. If the storage underneath can take
a point-in-time snapshot of the filesystem, that is the right mechanism; it is atomic, and a `tar`
running while a day rolls over is not.

## How often

| | when | why |
| --- | --- | --- |
| `audit/` | daily, after 00:00 UTC | a day's file is appended to all day and closed at midnight. Copying it after the roll means copying something that will not change again |
| `keys/` | after every rotation, or daily | `rotate_every` says how often it changes. Daily covers any setting longer than a day, which is every production setting |
| everything else | daily | it changes rarely and costs nothing to include |

Retention on the backups themselves should be at least `keys.retain` — the window over which a
signature made in the past still has to verify. Keeping audit backups for less time than the trail's
own `retention` is a way of shortening it without meaning to.

## Restoring

```sh
# 1. Stop the process. A restore under a running server races the server.
# 2. Put the whole volume back, exactly as it was.
rm -rf /var/lib/pic-x && cp -a /backups/pic-x/2026-08-09 /var/lib/pic-x
chown -R 65532:65532 /var/lib/pic-x        # the container runs as uid 65532

# 3. Check the trail before trusting it, against a key set from outside this machine.
pic-x audit verify --directory /var/lib/pic-x/audit --keys /backups/pic-x/jwks-2026-08-09.json

# 4. Start it.
pic-x /etc/pic-x/config.yaml
```

Step 3 is not a formality, and it is the reason to restore into a scratch directory first: the answer
distinguishes a backup that is intact from one that is merely present.

`audit verify` reports three separable things — that each day chains onto the one before, that no day
is missing, and that every seal still matches the prefix it attests to. A restore that fails only the
third has an intact trail and a key ring from a different moment, which is the mistake this document's
middle section exists to prevent.

## Permissions

The secret store refuses to read a secret that anyone but its owner can write to, and warns about one
others can read. A restore performed as `root` and left that way will start; a restore that widened
the mode along the way will not, and will say which file.

`cp -a` preserves modes. `cp -r` does not.

## Testing it

`tests/restore.rs` performs the whole cycle against the real binary on every run of the suite: it
starts a server, lets it write and seal a trail, copies the volume, destroys the original, restores
the copy, verifies the trail, and starts the server again on what came back.

That test exists because the failure it prevents is not "the backup was missing". It is "the backup
was there, and nobody had ever tried it".
