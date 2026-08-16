# Docker

The Docker image builds a static `pic-x` binary and runs it from `scratch` as UID/GID `65532:65532`.
It exposes three ports and stores runtime state under `/var/lib/pic-x`.

Published images are available from GitHub Container Registry:

<https://github.com/pic-protocol/pic-x/pkgs/container/pic-x>

```sh
docker pull ghcr.io/pic-protocol/pic-x:0.2
```

| Port | Surface |
| --- | --- |
| `7556` | Public discovery and JWKS |
| `7557` | Admin gRPC |
| `7558` | Health, readiness and metrics |

## Development Container

```sh
task run-as-docker-dev
```

This builds the image and runs `/etc/pic-x/config.dev.yaml`. It starts with an empty mounted volume
and generates the missing development material.

```sh
curl http://localhost:7556/.well-known/server-configuration
curl http://localhost:7558/metrics

grpcurl -plaintext \
  -import-path crates/pic-x-admin/proto -proto picx/admin/v1/admin.proto \
  localhost:7557 picx.admin.v1.Admin/GetVersion
```

Do not expose this mode to other machines. It has no transport security and the admin surface is a
development-only surface.

## Production Default

```sh
task run-as-docker
```

This runs the image default, `/etc/pic-x/config.yaml`, copied from `config.prod.yaml`. With an empty
volume it should fail, because production config requires material supplied from outside the process.

Minimum mounted material before a production-shaped start:

| Path in `/var/lib/pic-x` | Purpose |
| --- | --- |
| `tls/server.pem` | Certificate served by public, admin and telemetry surfaces |
| `tls/server.key` | Private key for `tls/server.pem` |
| `tls/operators.pem` | CA bundle used to verify admin client certificates |
| `secrets/audit-pseudonym` | Pseudonymisation key for audit subjects; use 32 random bytes |

On first successful start, PIC-X can maintain its signing key ring under `keys/`. Back up the whole
volume, not just the files listed above.

## Image Facts

| Fact | Value |
| --- | --- |
| Entry point | `/usr/local/bin/pic-x` |
| Default command | `/etc/pic-x/config.yaml` |
| Production config in image | `/etc/pic-x/config.yaml` |
| Development config in image | `/etc/pic-x/config.dev.yaml` |
| Runtime user | `65532:65532` |
| Volume path | `/var/lib/pic-x` |

If a host directory is mounted as the volume, its permissions must allow UID/GID `65532:65532` to
write audit files, keys and state.

## Custom Config

The image entry point is `/usr/local/bin/pic-x`; the command is the config file path. The default command
is `/etc/pic-x/config.yaml`, so mounting a file there uses a custom config without changing the command:

```sh
docker run --rm --init \
  --publish 7556:7556 --publish 7557:7557 --publish 7558:7558 \
  --volume "$PWD/config.prod.yaml:/etc/pic-x/config.yaml:ro" \
  --volume "$PWD/pic-x-state:/var/lib/pic-x" \
  ghcr.io/pic-protocol/pic-x:0.2
```

To keep the image's built-in production config untouched, mount the file somewhere else and pass that
path as the command:

```sh
docker run --rm --init \
  --publish 7556:7556 --publish 7557:7557 --publish 7558:7558 \
  --volume "$PWD/my-realm.yaml:/run/pic-x/config.yaml:ro" \
  --volume "$PWD/pic-x-state:/var/lib/pic-x" \
  ghcr.io/pic-protocol/pic-x:0.2 \
  /run/pic-x/config.yaml
```

## Try the Production Shape Locally

The Taskfile includes a demo path that reuses local TLS material:

```sh
PIC_X_WORKING_DIR=.volume-docker task run-as-local-tls
# Stop it with Ctrl-C once the volume has been generated, then continue:
cp .volume-docker/tls/ca.pem .volume-docker/tls/operators.pem
chmod 600 .volume-docker/operations/secrets/* .volume-docker/tls/*.key
task run-as-docker
```

This is only a local demonstration authority. Real deployments should mount certificates and secrets
created by the deployment platform or secret manager.
