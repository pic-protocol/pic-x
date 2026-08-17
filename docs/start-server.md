# Starting the Server

PIC-X serves by default. The direct form is:

```sh
pic-x <CONFIG_FILE>
```

During development, the Taskfile wraps that command so the common modes are easy to run.

## Choose a Mode

| Mode | Command | Config | Security posture |
| --- | --- | --- | --- |
| Local quick start | `task run-as-local` | `config.local.yml` | Loopback only, no TLS, development mode |
| Local TLS and mTLS | `task run-as-local-tls` | `config.local-tls.yml` | TLS on public/telemetry, mTLS on admin |
| Single Docker container | `task run-as-docker` | `config.docker.yml` | No TLS; do not expose outside your machine |
| Single Docker container, TLS | `task run-as-docker-tls` | `config.docker-tls.yml` | TLS on public/telemetry, mTLS on admin |
| Docker Compose lab | `task lab-up` | `config.lab.yml` | No TLS, localhost-bound; Keycloak and trust-lab beside it |

A production configuration is written by copying from `config.template.yml`; the container image
ships no configuration and refuses to start until one is mounted. See [docker.md](docker.md).

## Local Quick Start

```sh
task run-as-local
```

Check the public and telemetry surfaces:

```sh
curl http://127.0.0.1:7556/
curl http://127.0.0.1:7556/.well-known/server-configuration
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
curl --cacert .volume/tls/ca.pem https://localhost:7556/.well-known/server-configuration

grpcurl -cacert .volume/tls/ca.pem \
        -cert .volume/tls/client.pem -key .volume/tls/client.key \
        -import-path crates/pic-x-admin/proto -proto picx/admin/v1/admin.proto \
        localhost:7557 picx.admin.v1.Admin/GetVersion
```

A client certificate must both be signed by the configured authority and match `admin.allow`.

## Direct Cargo Form

Use this when Task is not installed:

```sh
cargo run --bin pic-x -- config.local.yml
cargo run --bin pic-x -- config.local-tls.yml
```

Runtime overrides are passed after the config file:

```sh
cargo run --bin pic-x -- config.local.yml \
  --public-http-addr 127.0.0.1:7556 \
  --telemetry-addr 127.0.0.1:7558 \
  --admin-addr 127.0.0.1:7557 \
  --log-level debug \
  --log-format terminal
```

## Stop Cleanly

Stop with `Ctrl-C` locally, or send `SIGTERM` in a supervisor/container. A clean shutdown lets the
server stop services, flush storage and release the audit sink last.
