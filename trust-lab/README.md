# Trust Lab

`trust-lab` is a tiny unauthenticated public REST application used by the local Docker Compose lab.
It is intentionally separate from the main PIC-X workspace: Docker builds it from this directory, and
`task check` for the product does not grow a lab binary by accident.

The service is HTTP-only on purpose. The compose lab publishes it on `127.0.0.1`, so a fresh
developer machine can run it without local certificates or trust-store setup.

On startup it loads `config.lab.json`, creates the configured fake attester keys if they do not
exist, signs the Worker 1 and Worker 2 SD-JWT/JWS credentials from the centralized exchange
walkthrough, and writes minimized presentations to the configured artifact directory.

## Endpoints

| Method | Path | Purpose |
| --- | --- | --- |
| `GET` | `/` | Return the base public API response |
| `GET` | `/attesters` | List fake lab attesters |
| `GET` | `/attesters/acme-por-attester/.well-known/attester-configuration` | Return the fake PoR attester metadata |
| `GET` | `/attesters/acme-por-attester/jwks.json` | Return the fake attester key set |
| `GET` | `/attesters/acme-por-attester/presentations/worker-1` | Return the Worker 1 SD-JWT presentation fixture |
| `GET` | `/attesters/acme-por-attester/presentations/worker-2` | Return the Worker 2 SD-JWT presentation fixture |
| `POST` | `/attesters/acme-por-attester/presentations` | Return a worker presentation by `subject` |

## Artifacts

With the compose lab, artifacts are written under:

```text
.volume/trust-lab/artifacts/attesters/acme-por-attester/
```

Each worker directory contains:

```text
issuer-signed.jwt
presentation.sd-jwt
processed-payload.json
manifest.json
issued-disclosures-summary.json
```

`presentation.sd-jwt` contains only the selected `corporation` and `department` disclosures. The
other eight issued disclosures are intentionally not present in the presentation.

Example:

```sh
curl -fsS http://localhost:17080/
curl -fsS http://localhost:17080/attesters/acme-por-attester/.well-known/attester-configuration
```

The repository-level lab walkthrough is:

```sh
task lab-demo
```
