#!/usr/bin/env python3
"""Run the local PIC-X trust lab walkthrough."""

from __future__ import annotations

import json
import os
import sys
import time
import urllib.error
import urllib.parse
import urllib.request


KEYCLOAK_URL = os.environ.get("KEYCLOAK_URL", "http://localhost:18080").rstrip("/")
KEYCLOAK_REALM = os.environ.get("KEYCLOAK_REALM", "acme-idp")
KEYCLOAK_CLIENT_ID = os.environ.get("KEYCLOAK_CLIENT_ID", "acme-idp-client")
KEYCLOAK_CLIENT_SECRET = os.environ.get(
    "KEYCLOAK_CLIENT_SECRET", "acme-idp-client-secret"
)
KEYCLOAK_USERNAME = os.environ.get("KEYCLOAK_USERNAME", "alice")
KEYCLOAK_PASSWORD = os.environ.get("KEYCLOAK_PASSWORD", "alice-password")

PIC_X_URL = os.environ.get("PIC_X_URL", "http://localhost:17556").rstrip("/")
TRUST_LAB_URL = os.environ.get("TRUST_LAB_URL", "http://localhost:17080").rstrip("/")
WAIT_SECONDS = float(os.environ.get("LAB_DEMO_WAIT_SECONDS", "30"))

COLORS = {
    "reset": "\033[0m",
    "bold": "\033[1m",
    "dim": "\033[2m",
    "red": "\033[31m",
    "green": "\033[32m",
    "yellow": "\033[33m",
    "blue": "\033[34m",
    "cyan": "\033[36m",
    "bold_cyan": "\033[1;36m",
}
COLOR_ENABLED = os.environ.get("LAB_DEMO_COLOR", "auto").lower()


class DemoError(Exception):
    """A user-facing demo failure."""


def main() -> int:
    print()
    print_banner("PIC-X local trust lab demo")
    print()
    print_dim("A short local run through IdP, PIC-X and the public trust API.")
    print_dim("No cloud account. No TLS ceremony. Just the path we will extend into exchange.")
    print()
    print_flow_map()
    print()

    try:
        print_step("1", f"Checking lab services (up to {WAIT_SECONDS:g}s)")
        keycloak_config = wait_for_json(
            "Keycloak IdP",
            f"{KEYCLOAK_URL}/realms/{KEYCLOAK_REALM}/.well-known/openid-configuration",
        )
        print_ok("Keycloak IdP", keycloak_config.get("issuer", "<issuer missing>"))

        trust_lab = wait_for_json("Trust Lab public API", f"{TRUST_LAB_URL}/")
        print_ok("Trust Lab API", trust_lab.get("message", "<message missing>"))

        pic_x = wait_for_json(
            "PIC-X public API", f"{PIC_X_URL}/.well-known/server-configuration"
        )
        print_ok("PIC-X public API", describe_pic_x(pic_x))
        print()

        print_step("2", "Requesting a token from the example IdP")
        print_kv("realm", KEYCLOAK_REALM)
        print_kv("client", KEYCLOAK_CLIENT_ID)
        print_kv("user", KEYCLOAK_USERNAME)
        token = request_access_token()
        print()

        print_step("3", "Access token")
        print_token(token)
        print()

        print_step("4", "What this proves")
        print_bullet("Keycloak is issuing a real local OIDC token.")
        print_bullet("The trust dependencies are reachable from the local lab.")
        print_bullet("PIC-X is running from the local source image with config.lab.yaml.")
        print_bullet("The next demo step can exchange this token with pic_context_of_authority.")
        print_bullet("Then we can propagate across nodes and emit relationship/continuity proofs.")
        print()
        print_success("Demo complete.")
        return 0
    except DemoError as error:
        print()
        print_error("Lab is not ready.")
        print_dim(str(error))
        print()
        print("Start it first, or give it a few seconds after startup, with:")
        print(f"  {paint('task lab-up', 'bold')}")
        return 1


def wait_for_json(name: str, url: str) -> dict:
    deadline = time.monotonic() + WAIT_SECONDS
    last_error = "not checked yet"

    while True:
        try:
            return get_json(url)
        except DemoError as error:
            last_error = str(error)

            if time.monotonic() >= deadline:
                break

            time.sleep(1)

    raise DemoError(f"{name} did not answer at {url}: {last_error}")


def get_json(url: str) -> dict:
    request = urllib.request.Request(url, headers={"Accept": "application/json"})
    with open_url(request) as response:
        body = response.read().decode("utf-8")

    try:
        value = json.loads(body)
    except json.JSONDecodeError as error:
        raise DemoError(f"{url} did not return JSON: {error}") from error

    if not isinstance(value, dict):
        raise DemoError(f"{url} returned JSON, but not an object")

    return value


def request_access_token() -> str:
    token_endpoint = (
        f"{KEYCLOAK_URL}/realms/{KEYCLOAK_REALM}/protocol/openid-connect/token"
    )
    body = urllib.parse.urlencode(
        {
            "grant_type": "password",
            "client_id": KEYCLOAK_CLIENT_ID,
            "client_secret": KEYCLOAK_CLIENT_SECRET,
            "username": KEYCLOAK_USERNAME,
            "password": KEYCLOAK_PASSWORD,
        }
    ).encode("utf-8")
    request = urllib.request.Request(
        token_endpoint,
        data=body,
        headers={
            "Accept": "application/json",
            "Content-Type": "application/x-www-form-urlencoded",
        },
        method="POST",
    )

    with open_url(request) as response:
        payload = json.loads(response.read().decode("utf-8"))

    token = payload.get("access_token")
    if not isinstance(token, str) or not token:
        raise DemoError("Keycloak answered without an access_token")

    return token


def open_url(request: urllib.request.Request):
    try:
        return urllib.request.urlopen(request, timeout=3)
    except urllib.error.HTTPError as error:
        detail = error.read().decode("utf-8", errors="replace")
        raise DemoError(f"HTTP {error.code} from {request.full_url}: {detail}") from error
    except urllib.error.URLError as error:
        raise DemoError(f"cannot reach {request.full_url}: {error.reason}") from error
    except TimeoutError as error:
        raise DemoError(f"timeout reaching {request.full_url}") from error


def describe_pic_x(payload: dict) -> str:
    product = payload.get("product") or payload.get("name") or "PIC-X"
    version = payload.get("version")
    if isinstance(version, str) and version:
        return f"{product} {version}"
    return str(product)


def color_is_enabled() -> bool:
    if COLOR_ENABLED in {"1", "true", "yes", "always"}:
        return True
    if COLOR_ENABLED in {"0", "false", "no", "never"}:
        return False
    if "NO_COLOR" in os.environ:
        return False
    return sys.stdout.isatty() and os.environ.get("TERM") != "dumb"


def paint(text: str, color: str) -> str:
    if not color_is_enabled():
        return text
    return f"{COLORS[color]}{text}{COLORS['reset']}"


def print_banner(title: str) -> None:
    label = f":: {title}"
    print(paint(label, "bold_cyan"))
    print(paint("-" * len(label), "cyan"))
    print_dim("local | docker compose | example IdP | public API")


def print_flow_map() -> None:
    print(paint("Flow map", "bold"))
    print(paint("--------", "cyan"))
    print(f"  {paint('current demo', 'cyan')}")
    print("  +----------------+   password grant    +------------------------+")
    print(
        f"  | {flow_cell('lab-demo', 14, 'bold')} | -------------------> "
        f"| {flow_cell('Keycloak example IdP', 22, 'bold')} |"
    )
    print(
        f"  | {flow_cell('local script', 14)} | <------------------- "
        f"| {flow_cell('localhost:18080', 22)} |"
    )
    print("  +----------------+    access token      +------------------------+")
    print("          |")
    print("          +---- discovery check --------> +------------------------+")
    print(
        f"          |                               | "
        f"{flow_cell('PIC-X localhost:17556', 22, 'bold')} |"
    )
    print("          |                               +------------------------+")
    print("          |")
    print("          +---- verify trust deps -------> +------------------------+")
    print(
        f"                                          | "
        f"{flow_cell('Trust Lab public API', 22, 'bold')} |"
    )
    print(f"                                          | {flow_cell('localhost:17080', 22)} |")
    print(f"                                          | {flow_cell('no auth yet', 22)} |")
    print("                                          +------------------------+")
    print()
    print(f"  {paint('target flow', 'yellow')}")
    print("  Keycloak token -> pic_context_of_authority exchange")
    print("     -> node A -> node B -> node C")
    print("     each node emits Proof of Relationship + Proof of Continuity")


def flow_cell(text: str, width: int, color: str = "") -> str:
    value = paint(text, color) if color else text
    return value + (" " * max(width - len(text), 0))


def print_step(number: str, title: str) -> None:
    marker = paint(f"[{number}]", "blue")
    print(f"{marker} {paint(title, 'bold')}")


def print_ok(name: str, detail: str) -> None:
    print(f"    {paint('OK', 'green')}  {paint(name, 'bold')}: {detail}")


def print_kv(key: str, value: str) -> None:
    print(f"    {paint(key + ':', 'cyan')} {value}")


def print_token(token: str) -> None:
    print(paint(token, "cyan"))
    print_dim(f"token length: {len(token)} characters")


def print_bullet(text: str) -> None:
    print(f"  {paint('-', 'green')} {text}")


def print_success(text: str) -> None:
    print(paint(text, "green"))


def print_error(text: str) -> None:
    print(paint(text, "red"))


def print_dim(text: str) -> None:
    print(paint(text, "dim"))


if __name__ == "__main__":
    sys.exit(main())
