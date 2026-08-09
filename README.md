<p align="center">
  <img src="assets/pic-x-logo.png" alt="PIC-X logo" width="100%">
</p>

<h1 align="center">PIC-X</h1>

<p align="center">
  Provenance Identity Continuity Exchange.<br>
  Verifiable Authority Continuity across execution boundaries.
</p>

> ⚠️ **Experimental — not production-ready yet.**
>
> The infrastructure below works and is tested. The domain it exists to serve — continuities,
> exchanges, provenance records — is not written yet. See [What is here, and what is not](#what-is-here-and-what-is-not).

---

## Start it

Rust 1.97 or later. Nothing else to set up: the server creates the directory it needs and, in
development, generates the material it is missing.

```sh
task run
```

That starts against [`config.local.yaml`](config.local.yaml) and creates `.volume/` beside the
repository, with a signing key, a pseudonymisation secret and an audit trail inside it.

```sh
curl http://127.0.0.1:7556/
curl http://127.0.0.1:7556/.well-known/jwks.json
```

For the same thing with transport security — a local authority, a server certificate and a client
certificate for the administrative surface, all generated on the first start:

```sh
task run-as-local-tls

curl --cacert .volume/tls/ca.pem https://localhost:7556/

grpcurl -cacert .volume/tls/ca.pem \
        -cert .volume/tls/client.pem -key .volume/tls/client.key \
        -import-path crates/pic-x-admin/proto -proto picx/admin/v1/admin.proto \
        localhost:7557 picx.admin.v1.Admin/GetVersion
```

A client certificate that authority signed but which is **not named in `grpc.allow`** is refused with
`PERMISSION_DENIED`. That difference — between *who is this* and *may they* — is the point of the
administrative surface, and it is worth seeing once.

## The three surfaces

| surface | port | what it is | who reaches it |
| --- | --- | --- | --- |
| **public** | 7556 | discovery documents, the published key set | the world |
| **admin** | 7557 | gRPC; everything that changes state | named operators, over mutual TLS |
| **telemetry** | 7558 | `/healthz`, `/readyz`, `/metrics` | a collector and a kubelet |

Three ports rather than one, so a mistake in a reverse proxy cannot expose administration by
accident. They are deliberately not Dex's 5556/5557/5558, so both can run on one host.

## Configuration

Four files, and each has one job:

| file | what it is |
| --- | --- |
| [`config.template.yaml`](config.template.yaml) | every setting there is, what it does, and what happens if you get it wrong. Nothing runs it |
| [`config.local.yaml`](config.local.yaml) | development, in the clear — `task run` |
| [`config.local-tls.yaml`](config.local-tls.yaml) | development, TLS and mutual TLS — `task run-as-local-tls` |
| [`config.prod.yaml`](config.prod.yaml) | production, and what the container image ships — `task run-as-prod` |

The template is kept honest by a test: it is uncommented mechanically and a server is started from
the result, so it cannot document a setting that no longer exists.

Values resolve through five layers, each overwriting only what it declares — defaults, build
metadata, the file, the environment, then the command line. So `PIC_X_LOG_LEVEL` beats `log.level`
in the file, and `--log-level` beats both: a file travels with the build and describes the
*product*, the environment is set by whoever runs this instance and describes the *deployment*.

## The crates

```text
pic-x-core       the contracts everything agrees on        anyhow serde serde_norway zeroize
pic-x-std        the default implementations               audit keys provision pseudonym secrets storage
pic-x-transport  one listener: TLS, mTLS, revocation, reload
pic-x-admin      the gRPC surface
pic-x-wellknown  the public surface
pic-x-telemetry  probes and metrics
pic-x-server     the host, the service registry, the command line
pic-x            the binary — the only place that names a concrete implementation
```

**Why the split stops there.** A crate boundary buys four things a module does not: its own
dependency set, its own compilation unit, its own version, and acyclicity enforced by cargo. It does
**not** buy replaceability — a trait in a module is as implementable from outside as one in a crate
of its own.

So the boundary that pays for itself is between *contracts* and *implementations*, and measurably:
a crate implementing one of these contracts depends on `pic-x-core` and links **22 crates**; if the
contracts lived beside the implementations it would link **71**, and would ship a
certificate-authority-minting library in order to name a trait.

Inside `pic-x-std` each area is a Cargo feature, so a build links only what it uses. `provision` is
outside the default set on purpose: it is the one implementation that can mint a certificate
authority, and getting it has to be written down rather than inherited.

## Extending it

Every crate receives its collaborators instead of resolving them. A build that needs Vault instead of
a directory, Postgres instead of memory, or an HSM instead of a local key ring writes its own binary
and reuses everything else — no fork:

```rust
App::new(identity, build_settings,
    Box::new(DefaultServerHost::new()),
    Box::new(PostgresStorage::new(&url)),          // yours
    Box::new(SplunkAuditSink::new(&token)))        // yours
  .with_secrets_factory(|c| Ok(Some(Box::new(VaultStore::new(c)))))   // yours
  .with_keys_factory(|c| Ok(Some(Arc::new(HsmKeyManager::new(c)))))   // yours
  .with_service(Box::new(pic_x_telemetry::TelemetryService::new()))   // ours
  .with_service(Box::new(MyPolicyService::new()))                     // yours
  .run().await
```

`scripts/check-composition-root.sh` enforces that `src/main.rs` stays the only place in this
repository that names a concrete implementation, and `scripts/check-core-dependencies.sh` keeps the
contracts crate to its dependency allowlist. Both run in CI.

## What is here, and what is not

**Working, and tested against real handshakes, real certificates and a real container:**

- three surfaces, TLS and mutual TLS, with the protocol floor at 1.3
- client-certificate revocation through a CRL the authority publishes
- certificates re-read without a restart — on a timer, or immediately on `SIGHUP`
- authorisation on the administrative surface: the certificate's identity checked against a list,
  and both outcomes recorded
- an Ed25519 key ring that publishes at `/.well-known/jwks.json`, and rotates itself: a key is
  published before it signs and stays published after it stops
- an audit trail written to files, each record carrying the digest of the one before it, so an edit,
  a removed line or a missing day stops the chain verifying — `task audit:verify`
- a **seal** on every day the trail closes: the head, signed by the key ring, written beside the
  trail and emitted to the log stream. It catches the one edit the chain cannot — a trail rewritten
  from the beginning, which verifies against itself and no longer agrees with what was sealed
- audit subjects that are people recorded as keyed, versioned pseudonyms rather than in the clear
- a startup that refuses configurations which would look fine and be wrong: an administrative surface
  the world can reach with no client certificate, a key that would start signing before verifiers
  could have fetched it, a pseudonymisation key changed without its version

**Not here yet:**

- **the domain** — `continuity`, `exchange` and `provenance` do not exist as types. This is the
  product; everything above is the scaffolding it will stand on
- **anything else that signs** — the key ring signs the audit seals, and nothing else yet
- **durable domain storage** — the store is in memory, which costs nothing today because nothing
  depends on it. Its shape is a question the domain answers

## Development

```sh
task              # every task, with what it does
task check        # lint, structural checks, supply chain, tests — everything CI runs
task test         # the test suite
task run-as-docker
```

`task check` is the gate: `clippy` with warnings denied, the two structural checks above,
`cargo deny` over advisories, licences and sources, and the tests.

## Licence

Apache-2.0. See [LICENSE](LICENSE).
