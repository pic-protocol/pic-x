# Starting the Server

PIC-X serves by default. The direct form is:

```sh
pic-x <CONFIG_FILE>
```

During development, the Taskfile wraps that command so the common modes are easy to run.

## Choose a Mode

| Mode | Command | Config | Security posture |
| --- | --- | --- | --- |
| Local quick start | `task run` | `config.local.yaml` | Loopback only, no TLS, development mode |
| Local TLS and mTLS | `task run-as-local-tls` | `config.local-tls.yaml` | TLS on public/telemetry, mTLS on admin |
| Production-shaped local run | `task run-as-prod` | `config.prod.yaml` | Refuses to start until required TLS and secrets exist |
| Docker development | `task run-as-docker-dev` | `config.dev.yaml` | No TLS; do not expose outside your machine |
| Docker production default | `task run-as-docker` | `config.prod.yaml` inside the image | Requires mounted production material |

## Local Quick Start

```sh
task run
```

Check the public and telemetry surfaces:

```sh
curl http://127.0.0.1:7556/
curl http://127.0.0.1:7556/.well-known/jwks.json
curl http://127.0.0.1:7558/readyz
```

This creates `.volume/` beside the repository. The shipped storage backend is in memory, but the
local config still writes audit files, signing keys and pseudonymisation material to that volume.

## Local TLS and mTLS

```sh
task run-as-local-tls
```

The first start generates a local authority, server certificate and client certificate under
`.volume/tls/`.

```sh
curl --cacert .volume/tls/ca.pem https://localhost:7556/.well-known/jwks.json

grpcurl -cacert .volume/tls/ca.pem \
        -cert .volume/tls/client.pem -key .volume/tls/client.key \
        -import-path crates/pic-x-admin/proto -proto picx/admin/v1/admin.proto \
        localhost:7557 picx.admin.v1.Admin/GetVersion
```

A client certificate must both be signed by the configured authority and match `grpc.allow`.

## Direct Cargo Form

Use this when Task is not installed:

```sh
cargo run --bin pic-x -- config.local.yaml
cargo run --bin pic-x -- config.local-tls.yaml
```

Runtime overrides are passed after the config file:

```sh
cargo run --bin pic-x -- config.local.yaml \
  --web-http-addr 127.0.0.1:7556 \
  --telemetry-addr 127.0.0.1:7558 \
  --grpc-addr 127.0.0.1:7557 \
  --log-level debug \
  --log-format terminal
```

## Stop Cleanly

Stop with `Ctrl-C` locally, or send `SIGTERM` in a supervisor/container. A clean shutdown lets the
server stop services, flush storage and release the audit sink last.
