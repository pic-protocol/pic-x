# Taskfile Shortcuts

`Taskfile.yml` is a thin wrapper around the real Rust and Docker commands. It does not hide a second
configuration system; the config files remain the source of truth.

## Common Tasks

| Task | Use it for |
| --- | --- |
| `task run-as-local` | Start local development config |
| `task run-as-local-tls` | Start local TLS and admin mTLS config |
| `task run-as-docker` | Build the image and run it as a single container |
| `task run-as-docker-tls` | The same single container, with TLS and admin mTLS |
| `task lab-up` | Start the local Keycloak, PIC-X and trust REST lab |
| `task lab-down` | Stop the local Keycloak, PIC-X and trust REST lab |
| `task lab-get-idp-config` | Print the example IdP well-known configuration |
| `task lab-get-idp-jwt` | Print an example IdP JWT |
| `task lab-demo` | Run the local lab walkthrough |
| `task audit:verify` | Verify the local file audit trail |
| `task release` | Tag the next release, push it and publish the release notes, after a confirmation |
| `task test` | Run the test suite |
| `task check` | Run the local CI gate |
| `task --list` | Show every available task |

## Useful Overrides

```sh
task run-as-local LOG_LEVEL=trace
task run-as-local ADMIN_ADDR=127.0.0.1:6000
task test PKG=pic-x-core
task test FILTER=config
task lab-get-idp-jwt KEYCLOAK_USERNAME=alice KEYCLOAK_PASSWORD=alice-password
task lab-demo
task run-as-docker VOLUME=/tmp/pic-x-docker
task run-as-docker-tls TAG=pic-x:experiment
```

The same values can be passed directly to the binary:

```sh
cargo run --bin pic-x -- config.local.yml --log-level trace
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
