# Trust Lab

`trust-lab` is a tiny unauthenticated public REST application used by the local Docker Compose lab.
It is intentionally separate from the main PIC-X workspace: Docker builds it from this directory, and
`task check` for the product does not grow a lab binary by accident.

The service is HTTP-only on purpose. The compose lab publishes it on `127.0.0.1`, so a fresh
developer machine can run it without local certificates or trust-store setup.

## Endpoints

| Method | Path | Purpose |
| --- | --- | --- |
| `GET` | `/` | Return the base public API response |

Example:

```sh
curl -fsS http://localhost:17080/
```
