# Local Lab

Use `docker-compose.lab.yml` when you need a local OpenID Connect issuer beside a tiny
unauthenticated public REST service. The stack starts Keycloak in development mode, imports the realm in
`dev/keycloak/acme-idp-realm.json`, builds PIC-X from the local checkout with `config.lab.yml`, and
builds the Rust service in `trust-lab/`.

The lab is intentionally HTTP-only and bound to localhost. That keeps it easy to run on a fresh
developer machine: no local CA, no certificate trust-store changes, no browser-specific setup. Do not
use this setup outside local development: it uses static credentials and Keycloak development mode.

## Start

```sh
task lab-up
```

Keycloak is exposed at <http://localhost:18080/>, PIC-X at <http://localhost:17556/> and the trust
lab REST service at <http://localhost:17080/>. All ports are published on `127.0.0.1` only by the
compose file. Open the admin console at <http://localhost:18080/admin/> with:

| Field | Value |
| --- | --- |
| Username | `admin` |
| Password | `admin` |

The local example IdP realm, client and user are:

| Item | Value |
| --- | --- |
| Realm | `acme-idp` |
| Client ID | `acme-idp-client` |
| Client secret | `acme-idp-client-secret` |
| Username | `alice` |
| Password | `alice-password` |

## Inspect The IdP

```sh
task lab-get-idp-config
```

The task prints the realm's raw OpenID Connect well-known configuration. The equivalent request is:

```sh
curl -fsS http://localhost:18080/realms/acme-idp/.well-known/openid-configuration
```

## Generate A Token

```sh
task lab-get-idp-jwt
```

The task prints only the access token JWT. The equivalent request is:

```sh
curl -fsS -X POST \
  "http://localhost:18080/realms/acme-idp/protocol/openid-connect/token" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  --data-urlencode "grant_type=password" \
  --data-urlencode "client_id=acme-idp-client" \
  --data-urlencode "client_secret=acme-idp-client-secret" \
  --data-urlencode "username=alice" \
  --data-urlencode "password=alice-password"
```

To override the configured local user:

```sh
task lab-get-idp-jwt KEYCLOAK_USERNAME=alice KEYCLOAK_PASSWORD=alice-password
```

## Call The Trust Lab

```sh
curl -fsS http://localhost:17080/
```

PIC-X is available in the same lab:

```sh
curl -fsS http://localhost:17556/.well-known/server-configuration
```

## Run The Demo

```sh
task lab-demo
```

The demo checks Keycloak, PIC-X and trust-lab, requests an example IdP token and prints a short,
didactic summary of what happened.

The demo uses terminal colors when stdout is interactive. Override with `LAB_DEMO_COLOR=always` or
disable with `LAB_DEMO_COLOR=never`.

## Stop

```sh
task lab-down
```

If you change the realm import while the container is already running, recreate the container so
Keycloak imports the file again:

```sh
task lab-down
task lab-up
```
