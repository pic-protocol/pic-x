<p align="center">
  <img src="assets/pic-x-logo.png" alt="PIC-X logo" width="100%">
</p>

<h1 align="center">PIC-X</h1>

<p align="center">
  Provenance Identity Continuity Exchange.<br>
  Verifiable Authority Continuity across execution boundaries.
</p>

> ⚠️ **Experimental — not production-ready yet.**

---

## Learn

Learn about PIC-X through the following articles:

- [PIC-X: From Specification to Architecture](https://www.ngallo.it/blog/2026-08-01/pic-x-from-spec-to-arch/)
- [PIC-X: Exchanging Tokens to PCA](https://www.ngallo.it/blog/2026-08-01/pic-x-exchanging-token-to-pca/)
- [PIC-X: Well-Known Configuration](https://www.ngallo.it/blog/2026-08-01/pic-x-well-known-config/)

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

Five files, and each has one job:

| file | what it is |
| --- | --- |
| [`config.template.yaml`](config.template.yaml) | every setting there is, what it does, and what happens if you get it wrong. Nothing runs it |
| [`config.local.yaml`](config.local.yaml) | development, in the clear — `task run` |
| [`config.local-tls.yaml`](config.local-tls.yaml) | development, TLS and mutual TLS — `task run-as-local-tls` |
| [`config.dev.yaml`](config.dev.yaml) | development, in a container — `task run-as-docker-dev` |
| [`config.prod.yaml`](config.prod.yaml) | production, and what the image runs by default. Refuses to start without its TLS material — `task run-as-docker` |

The template is kept honest by a test: it is uncommented mechanically and a server is started from
the result, so it cannot document a setting that no longer exists.

What lives in the volume, what to save and how to put it back:
[docs/backup-and-restore.md](docs/backup-and-restore.md).

Values resolve through five layers, each overwriting only what it declares — defaults, build
metadata, the file, the environment, then the command line. So `PIC_X_LOG_LEVEL` beats `log.level`
in the file, and `--log-level` beats both: a file travels with the build and describes the
*product*, the environment is set by whoever runs this instance and describes the *deployment*.

## Development

```sh
task              # every task, with what it does
task check        # lint, structural checks, supply chain, tests — everything CI runs
task test         # the test suite
task run-as-docker-dev  # the image, with nothing to set up first
```

`task check` is the gate: `clippy` with warnings denied, the two structural checks above,
`cargo deny` over advisories, licences and sources, and the tests.

## Licence

Apache-2.0. See [LICENSE](LICENSE).
