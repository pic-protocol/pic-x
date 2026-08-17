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
task run-as-docker
```

This builds the image and runs it as one container against `config.docker.yml`, mounted at
`/etc/pic-x/config.yml` — the image itself ships no configuration. It starts with an empty mounted
volume and generates the missing development material.

```sh
curl http://localhost:7556/.well-known/server-configuration
curl http://localhost:7558/metrics

grpcurl -plaintext \
  -import-path crates/pic-x-admin/proto -proto picx/admin/v1/admin.proto \
  localhost:7557 picx.admin.v1.Admin/GetVersion
```

Do not expose this mode to other machines. It has no transport security and the admin surface is a
development-only surface.

For the same container over TLS and mutual TLS:

```sh
task run-as-docker-tls
```

The first start generates the authority, server certificate and operator client certificate into the
volume, `.volume-docker-tls/` on the host:

```sh
curl --cacert .volume-docker-tls/tls/ca.pem https://localhost:7556/.well-known/server-configuration

grpcurl -cacert .volume-docker-tls/tls/ca.pem \
  -cert .volume-docker-tls/tls/client.pem -key .volume-docker-tls/tls/client.key \
  -import-path crates/pic-x-admin/proto -proto picx/admin/v1/admin.proto \
  localhost:7557 picx.admin.v1.Admin/GetVersion
```

For the full local stack — PIC-X beside Keycloak and trust-lab — use `task lab-up` instead; see
[keycloak.md](keycloak.md).

## No Configuration Ships in the Image

```sh
docker run --rm ghcr.io/pic-protocol/pic-x:0.2
```

fails on purpose. The image ships no configuration — a baked-in default is a posture somebody else
chose — and the default command names `/etc/pic-x/config.yml`, which is where a deployment mounts
its own file, written by copying from `config.template.yml`. Given nothing, the container refuses to
start and names the file that is missing.

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
| Default command | `/etc/pic-x/config.yml` |
| Config in image | None — mount your own at `/etc/pic-x/config.yml` |
| Runtime user | `65532:65532` |
| Volume path | `/var/lib/pic-x` |

If a host directory is mounted as the volume, its permissions must allow UID/GID `65532:65532` to
write audit files, keys and state.

## Custom Config

The image entry point is `/usr/local/bin/pic-x`; the command is the config file path. The default command
is `/etc/pic-x/config.yml`, so mounting a file there uses it without changing the command:

```sh
docker run --rm --init \
  --publish 7556:7556 --publish 7557:7557 --publish 7558:7558 \
  --volume "$PWD/my-config.yml:/etc/pic-x/config.yml:ro" \
  --volume "$PWD/pic-x-state:/var/lib/pic-x" \
  ghcr.io/pic-protocol/pic-x:0.2
```

Alternatively, mount the file somewhere else and pass that path as the command:

```sh
docker run --rm --init \
  --publish 7556:7556 --publish 7557:7557 --publish 7558:7558 \
  --volume "$PWD/my-realm.yml:/run/pic-x/config.yml:ro" \
  --volume "$PWD/pic-x-state:/var/lib/pic-x" \
  ghcr.io/pic-protocol/pic-x:0.2 \
  /run/pic-x/config.yml
```

## Try the Production Shape Locally

Write a production-shaped configuration by copying from `config.template.yml` — uncommenting every
setting line yields a valid one, and the test suite proves it. Then reuse local TLS material to
satisfy what it demands:

```sh
PIC_X_WORKING_DIR=.volume-docker task run-as-local-tls
# Stop it with Ctrl-C once the volume has been generated, then continue:
cp .volume-docker/tls/ca.pem .volume-docker/tls/operators.pem
chmod 600 .volume-docker/operations/secrets/* .volume-docker/tls/*.key
docker build --tag pic-x:local .
docker run --rm --init \
  --publish 7556:7556 --publish 7557:7557 --publish 7558:7558 \
  --volume "$PWD/my-config.yml:/etc/pic-x/config.yml:ro" \
  --volume "$PWD/.volume-docker:/var/lib/pic-x" \
  pic-x:local
```

This is only a local demonstration authority. Real deployments should mount certificates and secrets
created by the deployment platform or secret manager.
