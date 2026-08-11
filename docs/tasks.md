# Taskfile Shortcuts

`Taskfile.yml` is a thin wrapper around the real Rust and Docker commands. It does not hide a second
configuration system; the config files remain the source of truth.

## Common Tasks

| Task | Use it for |
| --- | --- |
| `task run` | Start local development config |
| `task run-as-local-tls` | Start local TLS and admin mTLS config |
| `task run-as-prod` | Check a production-shaped config locally |
| `task lab-up` | Start the local Keycloak and trust REST lab |
| `task lab-get-idp-config` | Print the example IdP well-known configuration |
| `task lab-get-idp-jwt` | Print an example IdP JWT |
| `task lab-down` | Stop the local Keycloak and trust REST lab |
| `task run-as-docker-dev` | Build the image and run the dev container |
| `task run-as-docker` | Build the image and run the production default |
| `task audit:verify` | Verify the local file audit trail |
| `task test` | Run the test suite |
| `task check` | Run the local CI gate |
| `task --list` | Show every available task |

## Useful Overrides

```sh
task run LOG_LEVEL=trace
task run ADMIN_ADDR=127.0.0.1:6000
task test PKG=pic-x-core
task test FILTER=config
task lab-get-idp-jwt KEYCLOAK_USERNAME=alice KEYCLOAK_PASSWORD=alice-password
task run-as-docker-dev VOLUME=/tmp/pic-x-dev
task run-as-docker TAG=pic-x:experiment VOLUME=/tmp/pic-x-prod
```

The same values can be passed directly to the binary:

```sh
cargo run --bin pic-x -- config.local.yaml --log-level trace
```

## CI Gate

```sh
task check
```

This runs:

- `cargo clippy` with warnings denied;
- the composition-root check;
- the core dependency allowlist check;
- `cargo deny check`;
- the workspace test suite.

Use this before treating a branch as ready for review.
