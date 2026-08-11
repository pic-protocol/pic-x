# Local Keycloak

Use `docker-compose.lab.yml` when you need a local OpenID Connect issuer with a user that can
mint tokens immediately. The container starts Keycloak in development mode and imports the realm in
`dev/keycloak/acme-idp-realm.json`.

Do not use this setup outside local development: it uses static credentials and Keycloak development
mode.

## Start

```sh
task lab-up
```

Open the admin console at <http://localhost:18080/admin/> with:

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
