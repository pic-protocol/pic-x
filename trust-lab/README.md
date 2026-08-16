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
| `POST` | `/attesters/acme-por-attester/credentials` | Issue a credential for a caller-supplied key and claim set |

## Issuing a credential

The two worker fixtures reproduce the centralized-exchange walkthrough, so their `cnf.jwk` values
are the article's public keys and nobody holds the matching private halves. A workload that has to
*sign* candidate PIC artifacts therefore generates its own key pair and asks for a credential bound
to it:

```sh
curl -fsS -X POST http://localhost:17080/attesters/acme-por-attester/credentials \
  -H 'Content-Type: application/json' \
  -d '{
        "cnf_jwk": {"kty":"EC","crv":"P-256","kid":"my-worker","x":"...","y":"..."},
        "claims": {"corporation":"ACME","department":"sensitive-documents"},
        "validity_seconds": 900
      }'
```

The response carries the issuer-signed JWT and **every** issued Disclosure. The workload is the
RFC 9901 Holder: it picks the Disclosures a given hop needs and joins them with `~`, ending the
presentation with a trailing `~`. Claims it does not present are absent from the wire — the
credential commits only to their digests.

Each claim gets a fresh 128-bit salt, so two issuances of the same claim set share no Disclosure
string and no digest.

> This endpoint issues credentials to anyone who asks, for any key, without authenticating the
> caller or proving that it holds the matching private key. That is deliberate for a lab, and the
> reason `trust-lab` must never stand in for a real attestation issuer.

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
