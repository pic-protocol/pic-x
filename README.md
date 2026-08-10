<p align="center">
  <img src="assets/pic-x-logo.png" alt="PIC-X logo" width="100%">
</p>

<h1 align="center">PIC-X</h1>

<p align="center">
  Provenance Identity Continuity Exchange.<br>
  Verifiable Authority Continuity across execution boundaries.
</p>

> Experimental: this repository is not production-ready yet.

## Quick Start

Requirements: Rust 1.97 or later. The examples use [Task](https://taskfile.dev/); without it, use
the `cargo run` commands shown in [docs/start-server.md](docs/start-server.md).

```sh
task run
```

This starts the local development config, creates `.volume/`, writes a file audit trail, creates the
pseudonymisation secret and maintains a signing key ring.

```sh
curl http://127.0.0.1:7556/
curl http://127.0.0.1:7556/.well-known/server-configuration
curl http://127.0.0.1:7558/healthz
```

To exercise TLS and mutual TLS locally:

```sh
task run-as-local-tls
```

```sh
curl --cacert .volume/tls/ca.pem https://localhost:7556/.well-known/server-configuration

grpcurl -cacert .volume/tls/ca.pem \
        -cert .volume/tls/client.pem -key .volume/tls/client.key \
        -import-path crates/pic-x-admin/proto -proto picx/admin/v1/admin.proto \
        localhost:7557 picx.admin.v1.Admin/GetVersion
```

The product APIs are still scaffolding. Today the useful surfaces are discovery/JWKS, health,
metrics, the admin version endpoint and audit verification.

## Surfaces

| Surface | Default port | Purpose | Intended access |
| --- | --- | --- | --- |
| Public | 7556 | Discovery documents and JWKS | Clients and verifiers |
| Admin | 7557 | gRPC operations that change state | Named operators, preferably over mTLS |
| Telemetry | 7558 | `/healthz`, `/readyz`, `/metrics` | Probes and collectors |

The ports are separate so administration is not accidentally exposed through the public surface.

## Operator Docs

| Need | Read |
| --- | --- |
| Start locally, with TLS, or with production validation | [docs/start-server.md](docs/start-server.md) |
| Run the image and understand the volume | [docs/docker.md](docs/docker.md) |
| Verify and operate the audit trail | [docs/audit.md](docs/audit.md) |
| Back up and restore the volume | [docs/backup-and-restore.md](docs/backup-and-restore.md) |
| Use the Taskfile shortcuts | [docs/tasks.md](docs/tasks.md) |

## Config Files

| File | Use |
| --- | --- |
| [config.local.yaml](config.local.yaml) | Local development, no TLS, loopback only; used by `task run` |
| [config.local-tls.yaml](config.local-tls.yaml) | Local development with TLS and mTLS; used by `task run-as-local-tls` |
| [config.dev.yaml](config.dev.yaml) | Container development, no TLS; used by `task run-as-docker-dev` |
| [config.prod.yaml](config.prod.yaml) | Production-shaped default copied into the image; refuses missing TLS/secrets |
| [config.template.yaml](config.template.yaml) | Full annotated reference; not meant to be run directly |

Runtime values are layered: defaults, build metadata, config file, environment, then CLI flags. A CLI
flag such as `--log-level trace` wins over `PIC_X_LOG_LEVEL`, which wins over `log.level` in the file.

## Development

```sh
task --list
task check
task test
task run-as-docker-dev
```

`task check` is the local CI gate: clippy with warnings denied, architecture checks, supply-chain
checks and the test suite.

## Learn

Articles:

- [PIC-X: From Specification to Architecture](https://www.ngallo.it/blog/2026-08-01/pic-x-from-spec-to-arch/)
- [PIC-X: Exchanging Tokens to PCA](https://www.ngallo.it/blog/2026-08-01/pic-x-exchanging-token-to-pca/)
- [PIC-X: Well-Known Configuration](https://www.ngallo.it/blog/2026-08-01/pic-x-well-known-config/)

## License

Apache-2.0. See [LICENSE](LICENSE).
