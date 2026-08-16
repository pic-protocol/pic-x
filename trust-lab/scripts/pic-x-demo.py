#!/usr/bin/env python3
"""Run the local PIC-X trust lab walkthrough."""

from __future__ import annotations

import json
import os
import base64
import hashlib
import re
import shlex
import sys
import time
import http.client
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path


KEYCLOAK_URL = os.environ.get("KEYCLOAK_URL", "http://localhost:18080").rstrip("/")
KEYCLOAK_REALM = os.environ.get("KEYCLOAK_REALM", "acme-idp")
KEYCLOAK_CLIENT_ID = os.environ.get("KEYCLOAK_CLIENT_ID", "acme-idp-client")
KEYCLOAK_CLIENT_SECRET = os.environ.get(
    "KEYCLOAK_CLIENT_SECRET", "acme-idp-client-secret"
)
KEYCLOAK_USERNAME = os.environ.get("KEYCLOAK_USERNAME", "alice")
KEYCLOAK_PASSWORD = os.environ.get("KEYCLOAK_PASSWORD", "alice-password")
# The audience an RFC 8693 exchange at the IdP targets, used only as a speed yardstick.
KEYCLOAK_EXCHANGE_AUDIENCE = os.environ.get("KEYCLOAK_EXCHANGE_AUDIENCE", "pic-x")

PIC_X_URL = os.environ.get("PIC_X_URL", "http://localhost:17556").rstrip("/")
PIC_X_REALM = os.environ.get("PIC_X_REALM", "acme")
TRUST_LAB_URL = os.environ.get("TRUST_LAB_URL", "http://localhost:17080").rstrip("/")
TRUST_LAB_ATTESTER_ID = os.environ.get("TRUST_LAB_ATTESTER_ID", "acme-por-attester")
TRUST_LAB_ARTIFACT_DIR = Path(
    os.environ.get(
        "TRUST_LAB_ARTIFACT_DIR", ".volume-docker-compose/trust-lab/artifacts"
    )
)
WAIT_SECONDS = float(os.environ.get("LAB_DEMO_WAIT_SECONDS", "60"))
RETRY_SECONDS = float(os.environ.get("LAB_DEMO_RETRY_SECONDS", "3"))

PIC_TOKEN_TYPE = "https://pic-protocol.org/definitions/token-types/pic"
TOKEN_EXCHANGE_GRANT = "urn:ietf:params:oauth:grant-type:token-exchange"
ACCESS_TOKEN_TYPE = "urn:ietf:params:oauth:token-type:access_token"
INITIAL_PROPOSAL_TYPE = (
    "https://pic-protocol.org/definitions/proposal-types/continuity-initial"
)

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


def truthy_env(name: str) -> bool:
    return os.environ.get(name, "").lower() in {
        "1",
        "true",
        "yes",
        "always",
    }


CLI_ARGS = set(sys.argv[1:])
INTERACTIVE = truthy_env("LAB_DEMO_INTERACTIVE") or bool(
    CLI_ARGS & {"interactive", "--interactive", "--guided", "--step"}
)
PRINT_VALUES = INTERACTIVE or truthy_env("LAB_DEMO_PRINT_VALUES") or bool(
    CLI_ARGS & {"print", "--print", "--print-tokens"}
)


class DemoError(Exception):
    """A user-facing demo failure."""


TIMINGS: dict[str, float] = {}

# One entry per PIC-X exchange, in the order they happened. Today the lab performs only the
# OAuth-to-PIC initialization; each future advancement (PCA 0 -> PCA 1, ...) appends one entry and
# the summary table grows with it.
EXCHANGES: list[dict] = []
DISCLOSED_CONTRACT_CLAIMS = {"corporation", "department"}
WORKLOAD_CLAIMS = {
    "corporation": "ACME",
    "department": "sensitive-documents",
    "workload_role": "pipeline-worker",
    "service": "document-pipeline",
    "clearance": "sensitive",
    "reader_region": "eu-west-1",
    "deployment_environment": "local-lab",
    "build_id": "pic-x-demo",
    "host_class": "container",
    "internal_cluster": "compose-lab",
}


def record_exchange(
    step: str, from_label: str, from_value: str, to_label: str, to_value: str, milliseconds: float
) -> None:
    EXCHANGES.append(
        {
            "step": step,
            "from_label": from_label,
            "from_bytes": len(from_value.encode("utf-8")),
            "to_label": to_label,
            "to_bytes": len(to_value.encode("utf-8")),
            "ms": milliseconds,
        }
    )


def timed(label: str, action):
    """Runs `action`, recording how long it took in milliseconds under `label`."""
    start = time.perf_counter()
    value = action()
    TIMINGS[label] = (time.perf_counter() - start) * 1000
    return value


def main() -> int:
    print()
    print_banner("PIC-X local trust lab demo")
    print()
    print_dim("A short local run through IdP, PIC-X and the public trust API.")
    print_dim("No cloud account. No TLS ceremony. OAuth authority becomes a PIC Token JWT.")
    print()
    print_flow_map()
    print()
    interactive_panel(
        "Guide Mode",
        "Each step shows the real request, response, process command, or artifact at the point it moves.",
    )
    interactive_pause("check that the local lab services are reachable")

    try:
        print_step(
            "1",
            f"Checking lab services (retrying every {RETRY_SECONDS:g}s, up to {WAIT_SECONDS:g}s)",
        )
        keycloak_config = wait_for_json(
            "Keycloak IdP",
            f"{KEYCLOAK_URL}/realms/{KEYCLOAK_REALM}/.well-known/openid-configuration",
        )
        print_ok("Keycloak IdP", keycloak_config.get("issuer", "<issuer missing>"))

        trust_lab = wait_for_json("Trust Lab public API", f"{TRUST_LAB_URL}/")
        print_ok("Trust Lab API", trust_lab.get("message", "<message missing>"))
        attester_config = wait_for_json(
            "Trust Lab attester",
            (
                f"{TRUST_LAB_URL}/attesters/{TRUST_LAB_ATTESTER_ID}"
                "/.well-known/attester-configuration"
            ),
        )
        print_ok("Trust Lab attester", str(attester_config.get("issuer", "<issuer missing>")))

        pic_x = wait_for_json(
            "PIC-X public API", f"{PIC_X_URL}/.well-known/server-configuration"
        )
        print_ok("PIC-X public API", describe_pic_x(pic_x))
        print()

        print_step("2", "Requesting a token from the example IdP")
        print_kv("realm", KEYCLOAK_REALM)
        print_kv("client", KEYCLOAK_CLIENT_ID)
        print_kv("user", KEYCLOAK_USERNAME)
        interactive_panel(
            "Command: Keycloak Password Grant",
            "Keycloak issues an OAuth access token. PIC-X later validates that JWT with the IdP JWKS.",
        )
        interactive_pause("request the OAuth access token from Keycloak")
        end_to_end_start = time.perf_counter()
        token = timed("Keycloak password grant -> OAuth access token", request_access_token)
        print()

        print_step("3", "Access token")
        interactive_panel(
            "Object: OAuth Access Token",
            "This is OAuth authority. It is not a PIC token yet.",
        )
        print_token("OAuth access token", token)
        print_jwt_details("OAuth access token", token)
        interactive_pause(
            "inspect the claims that the Exchange Profile uses to build PCA 0"
        )
        print()

        print_step("4", "Decoded access-token facts used by the Exchange Profile")
        access_header, access_payload = decode_jwt(token)
        print_kv("alg", str(access_header.get("alg", "<missing>")))
        print_kv("typ", str(access_header.get("typ", "<missing>")))
        print_kv("iss", str(access_payload.get("iss", "<missing>")))
        print_kv("aud", json.dumps(access_payload.get("aud", "<missing>")))
        pic_scopes = access_payload.get("pic_scopes", [])
        if not isinstance(pic_scopes, list) or not pic_scopes:
            raise DemoError(
                "Keycloak access token has no non-empty pic_scopes claim; recreate the lab so "
                "dev/keycloak/acme-idp-realm.json is imported."
            )
        print_kv("pic_scopes", json.dumps(pic_scopes))
        interactive_panel(
            "Mapping Input",
            "PIC-X maps these OAuth claims and scopes into an indexed authority map.",
        )
        print()

        print_step("5", "Exchanging OAuth authority for PIC Token JWT 0")
        proposal_json = initial_continuity_proposal()
        proposal_wire = b64url_json(proposal_json)
        print_kv("realm token endpoint", f"{PIC_X_URL}/realms/{PIC_X_REALM}/token")
        print_kv("continuity proposal", compact_json(proposal_json))
        if INTERACTIVE:
            interactive_panel(
                "Command: OAuth Access Token -> PIC Token JWT 0",
                "This request validates the OAuth JWT, materializes PCA 0, and signs PIC Token JWT 0.",
            )
            print_json_block("continuity initialization proposal", proposal_json)
            interactive_pause(
                "call PIC-X and initialize the continuity lineage"
            )
        pic_response = timed(
            "PIC-X token exchange -> PIC Token JWT 0",
            lambda: exchange_initial_token(token, proposal_wire),
        )
        TIMINGS["sum of the two above (grant + exchange)"] = (
            time.perf_counter() - end_to_end_start
        ) * 1000
        pic_token = pic_response.get("access_token")
        if not isinstance(pic_token, str) or not pic_token:
            raise DemoError("PIC-X answered without an access_token")
        record_exchange(
            "initialization",
            "OAuth access token",
            token,
            "PIC Token JWT 0",
            pic_token,
            TIMINGS["PIC-X token exchange -> PIC Token JWT 0"],
        )
        interactive_panel(
            "Result: PIC Token JWT 0",
            "The realm signs the JWT and the embedded Continuity/PCA COSE artifacts.",
        )
        print_token("PIC Token JWT 0", pic_token)
        print_pic_token_details("PIC Token JWT 0", pic_token)
        if INTERACTIVE:
            print_checkpoint_focus("PCA 0", pic_token)
        print_kv("issued_token_type", str(pic_response.get("issued_token_type")))
        print_kv("token_type", str(pic_response.get("token_type")))
        interactive_panel(
            "Correlation",
            "JWT jti and PCA lineage_id are the same stable audit correlation id.",
        )
        interactive_pause("review size tables and continue to Proof of Relationship material")
        print()

        print_step("6", "Payload weight")
        print_size_table(token, proposal_json, proposal_wire, pic_token)
        print()

        print_step("7", "Proof-of-Relationship fixtures from disk")
        print_kv("artifact dir", str(TRUST_LAB_ARTIFACT_DIR))
        worker_1, worker_2 = timed(
            "Trust Lab PoR fixtures read from disk",
            lambda: (load_por_artifact("worker-1"), load_por_artifact("worker-2")),
        )
        print_por_artifact(worker_1)
        print_por_artifact(worker_2)
        print_bullet(
            "The Rust trust-lab runtime signs the SD-JWT/JWS and writes the selected presentations to disk."
        )
        interactive_pause(
            "build a workload-signed candidate PIC token and send it to PIC-X"
        )
        print()

        print_step("8", "PIC-to-PIC advancement: two workloads, two attenuations")
        pic_tokens = [pic_token]
        try:
            pic_tokens += run_advancements(pic_token)
        except DemoError as error:
            print_error("advancement did not complete")
            print_dim(str(error))
        print()

        print_step("9", "OAuth Token Exchange at the IdP, for comparison")
        run_oauth_token_exchange(token)
        print()

        print_step("10", "Totals, internal weights and end-to-end timing")
        print_final_summary(token, proposal_wire, pic_tokens, [worker_1, worker_2])
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
            return get_json(url, name)
        except DemoError as error:
            last_error = str(error)

            if time.monotonic() >= deadline:
                break

            time.sleep(RETRY_SECONDS)

    raise DemoError(f"{name} did not answer at {url}: {last_error}")


def get_json(url: str, label: str | None = None) -> dict:
    request = urllib.request.Request(url, headers={"Accept": "application/json"})
    return request_json(label or url, request, response_mode="summary")


def request_access_token() -> str:
    token_endpoint = (
        f"{KEYCLOAK_URL}/realms/{KEYCLOAK_REALM}/protocol/openid-connect/token"
    )
    form = {
        "grant_type": "password",
        "client_id": KEYCLOAK_CLIENT_ID,
        "client_secret": KEYCLOAK_CLIENT_SECRET,
        "username": KEYCLOAK_USERNAME,
        "password": KEYCLOAK_PASSWORD,
    }
    body = urllib.parse.urlencode(form).encode("utf-8")
    request = urllib.request.Request(
        token_endpoint,
        data=body,
        headers={
            "Accept": "application/json",
            "Content-Type": "application/x-www-form-urlencoded",
        },
        method="POST",
    )

    payload = request_json(
        "Keycloak password grant",
        request,
        http_body("application/x-www-form-urlencoded", body, {"form": form}),
    )

    token = payload.get("access_token")
    if not isinstance(token, str) or not token:
        raise DemoError("Keycloak answered without an access_token")

    return token


def exchange_initial_token(access_token: str, proposal_wire: str) -> dict:
    token_endpoint = f"{PIC_X_URL}/realms/{PIC_X_REALM}/token"
    form = initial_exchange_form(access_token, proposal_wire)
    body = urllib.parse.urlencode(form).encode("utf-8")
    request = urllib.request.Request(
        token_endpoint,
        data=body,
        headers={
            "Accept": "application/json",
            "Content-Type": "application/x-www-form-urlencoded",
        },
        method="POST",
    )

    return request_json(
        "PIC-X initial token exchange",
        request,
        http_body("application/x-www-form-urlencoded", body, {"form": form}),
    )


def initial_exchange_form(access_token: str, proposal_wire: str) -> dict:
    return {
        "grant_type": TOKEN_EXCHANGE_GRANT,
        "subject_token": access_token,
        "subject_token_type": ACCESS_TOKEN_TYPE,
        "requested_token_type": PIC_TOKEN_TYPE,
        "continuity_proposal": proposal_wire,
    }


def advancement_exchange_form(candidate_token: str) -> dict:
    return {
        "grant_type": TOKEN_EXCHANGE_GRANT,
        "subject_token": candidate_token,
        "subject_token_type": PIC_TOKEN_TYPE,
        "requested_token_type": PIC_TOKEN_TYPE,
    }


def initial_continuity_proposal() -> dict:
    return {
        "type": INITIAL_PROPOSAL_TYPE,
        "executionContract": {
            "corporation": "ACME",
            "department": "sensitive-documents",
        },
    }


def load_por_artifact(worker_id: str) -> dict:
    worker_dir = (
        TRUST_LAB_ARTIFACT_DIR
        / "attesters"
        / TRUST_LAB_ATTESTER_ID
        / "workers"
        / worker_id
    )
    manifest = read_json_file(worker_dir / "manifest.json")
    presentation = read_text_file(worker_dir / "presentation.sd-jwt")
    processed = read_json_file(worker_dir / "processed-payload.json")

    return {
        "manifest": manifest,
        "presentation": presentation,
        "processed": processed,
    }


def read_json_file(path: Path) -> dict:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as error:
        raise DemoError(f"missing trust-lab artifact {path}") from error
    except json.JSONDecodeError as error:
        raise DemoError(f"trust-lab artifact {path} is not JSON: {error}") from error

    if not isinstance(value, dict):
        raise DemoError(f"trust-lab artifact {path} is not a JSON object")
    return value


def read_text_file(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8")
    except FileNotFoundError as error:
        raise DemoError(f"missing trust-lab artifact {path}") from error


def print_por_artifact(artifact: dict) -> None:
    manifest = artifact["manifest"]
    presentation = artifact["presentation"]
    processed = artifact["processed"]
    worker = str(manifest.get("worker_id", "<worker missing>"))
    role = str(manifest.get("role", "<role missing>"))
    presented = manifest.get("presented_disclosures", [])
    undisclosed = manifest.get("undisclosed_disclosures", [])

    if not isinstance(presented, list) or not isinstance(undisclosed, list):
        raise DemoError(f"{worker} manifest has malformed disclosure lists")

    print_kv(f"{worker}", role)
    print_kv("  PoR issuer", str(manifest.get("issuer", "<issuer missing>")))
    print_kv("  presented disclosures", ", ".join(str(item) for item in presented))
    print_kv("  hidden disclosures", str(len(undisclosed)))
    print_kv("  processed keys", ", ".join(sorted(processed.keys())))
    print_size(
        f"  {worker} SD-JWT presentation",
        len(presentation),
        len(presentation.encode("utf-8")),
    )


def http_body(media_type: str, raw: bytes, decoded: dict) -> dict:
    body = {
        "media_type": media_type,
        "bytes": len(raw),
        "sha256": hashlib.sha256(raw).hexdigest(),
        "wire": raw.decode("utf-8", errors="replace"),
    }
    body.update(decoded)
    return body


def request_json(
    label: str,
    request: urllib.request.Request,
    request_body: dict | None = None,
    response_mode: str = "full",
) -> dict:
    print_http_request(label, request, request_body)
    with open_url(request) as response:
        body_text = response.read().decode("utf-8")
        print_http_response(label, response, body_text, response_mode)

    try:
        value = json.loads(body_text)
    except json.JSONDecodeError as error:
        raise DemoError(f"{request.full_url} did not return JSON: {error}") from error

    if not isinstance(value, dict):
        raise DemoError(f"{request.full_url} returned JSON, but not an object")

    return value


def print_http_request(
    label: str,
    request: urllib.request.Request,
    request_body: dict | None,
) -> None:
    if not INTERACTIVE:
        return
    interactive_panel(
        f"HTTP request: {label}",
        "Captured immediately before the client opens the connection.",
    )
    packet = {
        "method": request.get_method(),
        "url": request.full_url,
        "headers": {key: value for key, value in request.header_items()},
    }
    if request_body is not None:
        packet["body"] = request_body
    print_json_block("request packet", packet)


def print_http_response(label: str, response, body_text: str, response_mode: str) -> None:
    if not INTERACTIVE:
        return
    interactive_panel(
        f"HTTP response: {label}",
        "Captured after the server answered and before the demo parses the body.",
    )
    packet = {
        "url": response.geturl(),
        "status": response.status,
        "reason": response.reason,
        "headers": {key: value for key, value in response.headers.items()},
        "body_bytes": len(body_text.encode("utf-8")),
        "body_sha256": hashlib.sha256(body_text.encode("utf-8")).hexdigest(),
    }
    try:
        value = json.loads(body_text)
    except json.JSONDecodeError:
        if response_mode == "summary":
            packet["text_preview"] = body_text[:800]
            packet["text_truncated"] = len(body_text) > 800
        else:
            packet["text"] = body_text
    else:
        if response_mode == "summary":
            packet["json_summary"] = json_summary(value)
        else:
            packet["json"] = value
    print_json_block("response packet", packet)


def json_summary(value) -> dict:
    if isinstance(value, dict):
        keys = sorted(str(key) for key in value.keys())
        selected_keys = [
            "issuer",
            "jwks_uri",
            "token_endpoint",
            "credentials_endpoint",
            "presentation_endpoint",
            "profile",
            "formats_supported",
            "proof_types_supported",
            "product",
            "version",
            "service",
            "status",
            "message",
        ]
        selected = {key: value[key] for key in selected_keys if key in value}
        return {
            "type": "object",
            "key_count": len(keys),
            "keys": keys[:40],
            "keys_truncated": len(keys) > 40,
            "selected": selected,
        }
    if isinstance(value, list):
        return {
            "type": "array",
            "items": len(value),
            "first_item": value[0] if value else None,
        }
    return {"type": type(value).__name__, "value": value}


def print_process_request(label: str, command: list[str]) -> None:
    if not INTERACTIVE:
        return
    interactive_panel(
        f"Process command: {label}",
        "Captured before the local workload helper starts.",
    )
    print_json_block(
        "process command",
        {
            "cwd": str(Path.cwd()),
            "argv": command,
            "shell": " ".join(shlex.quote(part) for part in command),
        },
    )


def print_process_response(label: str, exit_code: int, stdout: str, stderr: str) -> None:
    if not INTERACTIVE:
        return
    interactive_panel(
        f"Process response: {label}",
        "Captured after the local workload helper exits.",
    )
    print_json_block(
        "process response",
        {
            "exit_code": exit_code,
            "stdout_bytes": len(stdout.encode("utf-8")),
            "stderr_bytes": len(stderr.encode("utf-8")),
            "stderr": stderr,
        },
    )


def print_process_json(label: str, value) -> None:
    if not INTERACTIVE:
        return
    interactive_panel(
        f"Process output JSON: {label}",
        "This is the parsed stdout that the next step consumes.",
    )
    print_json_block("process output", value)


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
    except (OSError, http.client.HTTPException) as error:
        # A service that is still starting accepts the connection and then drops it, which arrives
        # as RemoteDisconnected rather than URLError. Same retryable condition, so it must not
        # escape as a traceback.
        raise DemoError(f"connection dropped: {error}") from error


def describe_pic_x(payload: dict) -> str:
    product = payload.get("product") or payload.get("name") or "PIC-X"
    version = payload.get("version")
    if isinstance(version, str) and version:
        return f"{product} {version}"
    return str(product)


def compact_json(value: dict) -> str:
    return json.dumps(value, separators=(",", ":"), sort_keys=True)


def b64url_json(value: dict) -> str:
    return b64url(compact_json(value).encode("utf-8"))


def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def b64url_decode(value: str) -> bytes:
    padding = "=" * (-len(value) % 4)
    return base64.urlsafe_b64decode(value + padding)


def decode_jwt(token: str) -> tuple[dict, dict]:
    parts = token.split(".")
    if len(parts) != 3:
        raise DemoError("token is not a compact JWT/JWS")
    try:
        header = json.loads(b64url_decode(parts[0]).decode("utf-8"))
        payload = json.loads(b64url_decode(parts[1]).decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as error:
        raise DemoError(f"could not decode JWT: {error}") from error
    if not isinstance(header, dict) or not isinstance(payload, dict):
        raise DemoError("JWT header or payload is not a JSON object")
    return header, payload


# --------------------------------------------------------------------------------------------
# PIC-to-PIC advancement
# --------------------------------------------------------------------------------------------

WORKLOAD_MANIFEST = os.environ.get("LAB_WORKLOAD_MANIFEST", "Cargo.toml")


def workload(*arguments: str) -> dict:
    """Runs the Rust workload helper, which holds the key and signs the candidate artifacts.

    Python has no Ed25519 or COSE in its standard library, so the signing side of a workload lives
    in `examples/workload.rs` and this drives it.
    """
    import subprocess

    command = [
        "cargo",
        "run",
        "--quiet",
        "--manifest-path",
        WORKLOAD_MANIFEST,
        "--example",
        "workload",
        "--",
        *arguments,
    ]
    print_process_request("workload helper", command)
    try:
        finished = subprocess.run(command, capture_output=True, text=True, timeout=300)
    except FileNotFoundError as error:
        raise DemoError("cargo is not on PATH, so the workload helper cannot run") from error
    except subprocess.TimeoutExpired as error:
        raise DemoError("the workload helper timed out") from error

    print_process_response("workload helper", finished.returncode, finished.stdout, finished.stderr)

    if finished.returncode != 0:
        raise DemoError(f"the workload helper failed: {finished.stderr.strip()}")

    try:
        result = json.loads(finished.stdout)
    except json.JSONDecodeError as error:
        raise DemoError(f"the workload helper did not print JSON: {error}") from error
    print_process_json("workload helper", result)
    return result


def request_credential(jwk: dict, claims: dict, selected_claims: set[str]) -> dict:
    """Asks the lab attester for a Proof of Relationship bound to this workload's key."""
    payload = {"cnf_jwk": jwk, "claims": claims, "validity_seconds": 900}
    body = json.dumps(payload).encode()
    request = urllib.request.Request(
        f"{TRUST_LAB_URL}/attesters/{TRUST_LAB_ATTESTER_ID}/credentials",
        data=body,
        headers={"Accept": "application/json", "Content-Type": "application/json"},
        method="POST",
    )
    credential = request_json(
        "Trust Lab credential issuance",
        request,
        http_body("application/json", body, {"json": payload}),
    )

    issued = credential.get("disclosures", [])
    if not issued:
        raise DemoError("the attester issued a credential with no disclosures")

    selected = [
        item
        for item in issued
        if isinstance(item, dict) and item.get("claim") in selected_claims
    ]
    if len(selected) != len(selected_claims):
        found = {str(item.get("claim")) for item in selected}
        missing = ", ".join(sorted(selected_claims - found))
        raise DemoError(f"the attester did not issue required disclosure(s): {missing}")

    selected_names = [str(item["claim"]) for item in selected]
    hidden_names = [
        str(item["claim"])
        for item in issued
        if isinstance(item, dict) and item.get("claim") not in selected_claims
    ]
    presentation = (
        credential["issuer_signed_jwt"]
        + "".join("~" + item["disclosure"] for item in selected)
        + "~"
    )

    return {
        "presentation": presentation,
        "issued_claims": len(issued),
        "selected_claims": selected_names,
        "hidden_claims": hidden_names,
    }


def pca_of(pic_token: str) -> str:
    """The exact signed PIC PCA COSE bytes a settled token carries, as base64url."""
    _, payload = decode_jwt(pic_token)
    root = payload.get("pic", {}).get("root")
    if not isinstance(root, str):
        raise DemoError("the PIC Token JWT has no pic.root")

    continuity = b64url_decode(root)
    parts, _ = cose_sign1_parts(continuity)
    fields, _ = cbor_map_fields(parts[2][0])

    return b64url(field_value(fields, "root")["pca"])


def advance_once(pic_token: str, hop: int, remove_invariant: int, claims: dict) -> str:
    """One workload hop: get a key, get a PoR for it, sign a candidate, have PIC-X settle it."""
    keys = workload("keygen")
    credential = request_credential(keys["jwk"], claims, DISCLOSED_CONTRACT_CLAIMS)
    presentation = credential["presentation"]
    candidate = workload(
        "candidate",
        "--pca",
        pca_of(pic_token),
        "--presentation",
        presentation,
        "--seed",
        keys["seed"],
        "--remove-invariant",
        str(remove_invariant),
    )
    if INTERACTIVE:
        interactive_panel(
            f"Object: Candidate PIC Token JWT {hop - 1} -> {hop}",
            "The workload signs this candidate. It carries the predecessor PCA and one transition.",
        )
        print_token(f"candidate PIC Token JWT {hop - 1} -> {hop}", candidate["token"])
    print_pic_token_details(f"candidate PIC Token JWT {hop - 1} -> {hop}", candidate["token"])
    if INTERACTIVE:
        interactive_panel(
            f"Command: Settle Candidate Into PIC Token JWT {hop}",
            "PIC-X validates PoR, signatures, transition position, challenge continuity, "
            "non-expansion, and execution-contract conformance.",
        )
        interactive_pause(f"send the candidate and materialize PCA {hop}")

    label = f"PIC-X advancement {hop - 1} -> {hop}"
    settled = timed(
        label,
        lambda: post_form(
            f"{PIC_X_URL}/realms/{PIC_X_REALM}/token",
            advancement_exchange_form(candidate["token"]),
            label,
        ),
    )
    next_token = settled.get("access_token")
    if not isinstance(next_token, str) or not next_token:
        raise DemoError(f"PIC-X answered without an access_token: {settled}")

    record_exchange(
        f"advancement {hop}",
        f"candidate JWT {hop - 1}",
        candidate["token"],
        f"PIC Token JWT {hop}",
        next_token,
        TIMINGS[label],
    )

    print_kv(f"hop {hop}", f"worker removes invariant index {remove_invariant}")
    print_kv(
        "  PoR presentation",
        f"{len(presentation)} bytes, issued {credential['issued_claims']} SD claims, "
        f"disclosed {', '.join(credential['selected_claims'])}, "
        f"hidden {len(credential['hidden_claims'])}",
    )
    print_kv(
        "  candidate",
        f"{len(candidate['token'])} bytes"
        f" (transition {candidate['transition_bytes']} B,"
        f" continuity {candidate['continuity_bytes']} B)",
    )
    print_kv("  settled", f"PIC Token JWT {hop}, {len(next_token)} bytes")
    interactive_panel(
        f"Result: PIC Token JWT {hop}",
        "The lineage id stays stable; the PCA position and materialized authority advance.",
    )
    print_pic_token_details(f"PIC Token JWT {hop}", next_token)
    if INTERACTIVE:
        print_checkpoint_focus(f"PCA {hop}", next_token)
        interactive_pause(f"continue after PCA {hop}")

    return next_token


def run_advancements(pic_token: str) -> list:
    """The walkthrough's two hops: read then save, each consuming the authority it used."""
    claims = WORKLOAD_CLAIMS
    tokens = []

    # PCA 0 holds { documents:read:document-42, storage:save }. Worker 1 reads and drops the read
    # invariant; PCA 1 re-indexes, so worker 2 removes index 0 again to drop the save invariant.
    current = pic_token
    for hop, remove in ((1, 0), (2, 0)):
        current = advance_once(current, hop, remove, claims)
        tokens.append(current)
        print_pca_summary(current, hop)

    return tokens


def print_pca_summary(pic_token: str, position: int) -> None:
    """What authority survives at this checkpoint."""
    invariants = invariants_of(pic_token)
    if invariants:
        print_kv(f"  PCA {position} authority", ", ".join(invariants))
    else:
        print_kv(
            f"  PCA {position} authority",
            "none — attenuated to zero executable authority",
        )
    print()


def invariants_of(pic_token: str) -> list:
    """The invariant scopes a settled token's checkpoint carries."""
    pca_bytes = b64url_decode(pca_of(pic_token))
    parts, _ = cose_sign1_parts(pca_bytes)
    fields, _ = cbor_map_fields(parts[2][0])
    authority = field_value(fields, "context_of_authority")
    invariants = authority.get("invariants", {}) if isinstance(authority, dict) else {}

    return [tuple(entry)[0] for entry in invariants.values()]


def pca_payload_of(pic_token: str) -> dict:
    pca_bytes = b64url_decode(pca_of(pic_token))
    parts, _ = cose_sign1_parts(pca_bytes)
    fields, _ = cbor_map_fields(parts[2][0])
    return {name: value for name, value, _ in fields}


def print_checkpoint_focus(label: str, pic_token: str) -> None:
    """Human-sized checkpoint view: the stable id, position, authority and contract."""
    _, jwt_payload = decode_jwt(pic_token)
    pca = pca_payload_of(pic_token)
    authority = pca.get("context_of_authority", {})
    execution_contract = (
        authority.get("execution_contract", {}) if isinstance(authority, dict) else {}
    )

    print_kv(f"{label} JWT jti", str(jwt_payload.get("jti", "<missing>")))
    print_kv(f"{label} PCA lineage_id", str(pca.get("lineage_id", "<missing>")))
    print_kv(f"{label} PCA position", str(pca.get("position", "<missing>")))
    print_json_block(f"{label} materialized context_of_authority", jsonable(authority))
    print_json_block(f"{label} execution_contract", jsonable(execution_contract))


def post_form(url: str, form: dict, label: str | None = None) -> dict:
    body = urllib.parse.urlencode(form).encode("utf-8")
    request = urllib.request.Request(
        url,
        data=body,
        headers={
            "Accept": "application/json",
            "Content-Type": "application/x-www-form-urlencoded",
        },
        method="POST",
    )
    return request_json(
        label or f"POST {url}",
        request,
        http_body("application/x-www-form-urlencoded", body, {"form": form}),
    )


def run_oauth_token_exchange(access_token: str) -> None:
    """RFC 8693 token exchange at Keycloak, as the yardstick PIC-X is measured against.

    It answers the question the timing table otherwise leaves open: is the IdP slow only on the
    first call, or on every exchange it performs?
    """
    form = {
        "grant_type": TOKEN_EXCHANGE_GRANT,
        "subject_token": access_token,
        "subject_token_type": ACCESS_TOKEN_TYPE,
        "client_id": KEYCLOAK_CLIENT_ID,
        "client_secret": KEYCLOAK_CLIENT_SECRET,
        "audience": KEYCLOAK_EXCHANGE_AUDIENCE,
    }
    endpoint = f"{KEYCLOAK_URL}/realms/{KEYCLOAK_REALM}/protocol/openid-connect/token"
    if INTERACTIVE:
        interactive_panel(
            "Command: Keycloak OAuth Token Exchange",
            "This is only a timing comparison against the IdP's own RFC 8693 exchange.",
        )
        interactive_pause("run the Keycloak OAuth token-exchange comparison")

    try:
        exchanged = timed(
            "Keycloak OAuth token exchange -> access token",
            lambda: post_form(endpoint, form, "Keycloak OAuth token exchange"),
        )
    except DemoError as error:
        TIMINGS.pop("Keycloak OAuth token exchange -> access token", None)
        print_kv("skipped", "the IdP did not perform a token exchange")
        print_dim(f"    {error}")
        return

    issued = exchanged.get("access_token")
    if not isinstance(issued, str) or not issued:
        print_kv("skipped", "the IdP answered without an access_token")
        return

    print_kv("grant", TOKEN_EXCHANGE_GRANT)
    print_kv("issued", f"{len(issued)} bytes")
    record_exchange(
        "oauth exchange",
        "OAuth access token",
        access_token,
        "OAuth access token",
        issued,
        TIMINGS["Keycloak OAuth token exchange -> access token"],
    )


def cbor_head(data: bytes, offset: int) -> tuple[int, int, int, int]:
    """Reads one CBOR head, returning (major type, additional info, argument, next offset)."""
    initial = data[offset]
    major = initial >> 5
    minor = initial & 0x1F
    offset += 1

    if minor < 24:
        argument = minor
    elif minor == 24:
        argument = data[offset]
        offset += 1
    elif minor == 25:
        argument = int.from_bytes(data[offset : offset + 2], "big")
        offset += 2
    elif minor == 26:
        argument = int.from_bytes(data[offset : offset + 4], "big")
        offset += 4
    elif minor == 27:
        argument = int.from_bytes(data[offset : offset + 8], "big")
        offset += 8
    else:
        raise DemoError(f"unsupported CBOR additional information {minor}")

    return major, minor, argument, offset


def cbor_value(data: bytes, offset: int = 0) -> tuple[object, int]:
    """Decodes one CBOR value, returning it with the offset just past it."""
    major, minor, argument, offset = cbor_head(data, offset)

    if major in (0, 1):
        return (argument if major == 0 else -1 - argument), offset
    if major in (2, 3):
        raw = data[offset : offset + argument]
        return (raw if major == 2 else raw.decode("utf-8")), offset + argument
    if major == 4:
        items = []
        for _ in range(argument):
            item, offset = cbor_value(data, offset)
            items.append(item)
        return items, offset
    if major == 5:
        entries = {}
        for _ in range(argument):
            key, offset = cbor_value(data, offset)
            value, offset = cbor_value(data, offset)
            entries[key if isinstance(key, (str, int)) else str(key)] = value
        return entries, offset
    if major == 6:
        return cbor_value(data, offset)
    if minor == 20:
        return False, offset
    if minor == 21:
        return True, offset
    if minor == 22:
        return None, offset
    return argument, offset


def cbor_map_fields(data: bytes) -> tuple[list[tuple[str, object, int]], int]:
    """Every map entry as (key, value, encoded size), plus the map header size.

    The entry sizes and the header add up to `len(data)` exactly, which is what lets the weight
    tables below balance instead of approximating.
    """
    major, _, count, offset = cbor_head(data, 0)
    if major != 5:
        raise DemoError("expected a CBOR map")

    header = offset
    fields = []
    for _ in range(count):
        start = offset
        key, offset = cbor_value(data, offset)
        value, offset = cbor_value(data, offset)
        fields.append((str(key), value, offset - start))

    return fields, header


def cose_sign1_parts(data: bytes) -> tuple[list[tuple[object, int]], int]:
    """The four COSE_Sign1 elements as (value, encoded size), plus the tag and array framing."""
    major, _, argument, offset = cbor_head(data, 0)
    if major == 6:
        major, _, argument, offset = cbor_head(data, offset)
    if major != 4 or argument != 4:
        raise DemoError("expected a COSE_Sign1 array of four elements")

    framing = offset
    parts = []
    for _ in range(4):
        start = offset
        value, offset = cbor_value(data, offset)
        parts.append((value, offset - start))

    return parts, framing


def field_size(fields: list[tuple[str, object, int]], name: str) -> int:
    for key, _, size in fields:
        if key == name:
            return size
    return 0


def field_value(fields: list[tuple[str, object, int]], name: str):
    for key, value, _ in fields:
        if key == name:
            return value
    return None


PART_WIDTH = 40
STAGE_WIDTH = 46


def print_parts_table(title: str, rows: list[tuple[str, int]]) -> None:
    """One artifact (or one payload): its parts, and the total they add up to."""
    print(f"    {paint(title, 'bold')}")
    for label, value in rows:
        print(f"    {label:<{PART_WIDTH}} {value:>7}")
    print(f"    {'-' * PART_WIDTH} {'-' * 7}")
    print(f"    {'total':<{PART_WIDTH}} {sum(value for _, value in rows):>7}")
    print()


def print_exchange_table(exchanges: list[dict]) -> None:
    """One row per exchange: what went in, what came out, and how long it took.

    Profile 0.2 advancement adds rows here (PCA 0 -> PCA 1, PCA 1 -> PCA 2, ...) without any
    change to the shape of the table.
    """
    print(f"    {paint('Exchanges — input, output, growth and round-trip time', 'bold')}")
    print(
        f"    {'step':<16} {'from':<22} {'to':<20} {'in':>6} {'out':>6} {'delta':>7} {'ms':>7}"
    )
    print(f"    {'-' * 16} {'-' * 22} {'-' * 20} {'-' * 6} {'-' * 6} {'-' * 7} {'-' * 7}")
    for exchange in exchanges:
        delta = exchange["to_bytes"] - exchange["from_bytes"]
        print(
            f"    {exchange['step']:<16} {exchange['from_label']:<22}"
            f" {exchange['to_label']:<20} {exchange['from_bytes']:>6}"
            f" {exchange['to_bytes']:>6} {delta:>+7} {exchange['ms']:>7.1f}"
        )
    print()



def describe_relative(milliseconds: float, baseline: float | None) -> str:
    """How this operation compares with the IdP exchange it is measured against."""
    if not baseline or milliseconds <= 0:
        return "-"
    if milliseconds == baseline:
        return "baseline"
    if milliseconds < baseline:
        return f"{baseline / milliseconds:.0f}x faster"

    return f"{milliseconds / baseline:.0f}x slower"


def print_speed_comparison() -> None:
    """PIC-X against the IdP that produced its input, so the numbers have a yardstick.

    Every row is a full HTTP round trip measured by this client, so they are comparable: the
    difference is what each server does between receiving and answering.
    """
    rows = [
        (label, milliseconds)
        for label, milliseconds in TIMINGS.items()
        if label.startswith("Keycloak") or label.startswith("PIC-X")
    ]
    if not rows:
        return

    pic_rows = [ms for label, ms in rows if label.startswith("PIC-X")]
    baseline = next(
        (ms for label, ms in rows if "token exchange" in label and label.startswith("Keycloak")),
        None,
    )
    if baseline is None:
        baseline = next((ms for label, ms in rows if label.startswith("Keycloak")), None)

    print(f"    {paint('Speed comparison — same client, same network path', 'bold')}")
    print(f"    {'operation':<{STAGE_WIDTH}} {'ms':>8} {'vs IdP':>9}")
    print(f"    {'-' * STAGE_WIDTH} {'-' * 8} {'-' * 9}")
    for label, milliseconds in rows:
        relative = describe_relative(milliseconds, baseline)
        print(f"    {label:<{STAGE_WIDTH}} {milliseconds:>8.1f} {relative:>9}")

    if pic_rows:
        average = sum(pic_rows) / len(pic_rows)
        print(f"    {'-' * STAGE_WIDTH} {'-' * 8} {'-' * 9}")
        print(
            f"    {'average PIC-X exchange (init + advancements)':<{STAGE_WIDTH}}"
            f" {average:>8.1f}"
            f" {describe_relative(average, baseline):>9}"
        )
    print()

def print_final_summary(
    access_token: str, proposal_wire: str, pic_tokens: list[str], workers: list[dict]
) -> None:
    pic_token = pic_tokens[0]
    access_header, access_payload, access_signature = access_token.split(".")
    pic_header, pic_payload_b64, pic_signature = pic_token.split(".")
    pic_payload_raw = b64url_decode(pic_payload_b64)
    pic_payload = json.loads(pic_payload_raw.decode("utf-8"))
    pic_root_b64 = pic_payload["pic"]["root"]
    continuity_bytes = b64url_decode(pic_root_b64)

    continuity_parts, continuity_framing = cose_sign1_parts(continuity_bytes)
    continuity_payload = continuity_parts[2][0]
    continuity_fields, continuity_header = cbor_map_fields(continuity_payload)
    pca_bytes = field_value(continuity_fields, "root")["pca"]

    pca_parts, pca_framing = cose_sign1_parts(pca_bytes)
    pca_payload = pca_parts[2][0]
    pca_fields, pca_header = cbor_map_fields(pca_payload)
    authority_encoded = extract_field_bytes(pca_payload, "context_of_authority")
    authority_fields, _ = cbor_map_fields(authority_encoded)

    print_parts_table(
        f"OAuth access token JWT — {len(access_token)} bytes, RS256",
        [
            ("header (base64url)", len(access_header)),
            ("payload (base64url)", len(access_payload)),
            ("signature (base64url)", len(access_signature)),
            ("'.' separators", 2),
        ],
    )

    print_parts_table(
        f"PIC Token JWT 0 — {len(pic_token)} bytes, EdDSA",
        [
            ("header (base64url)", len(pic_header)),
            ("payload (base64url)", len(pic_payload_b64)),
            ("signature (base64url)", len(pic_signature)),
            ("'.' separators", 2),
        ],
    )

    # The payload segment is base64url of this JSON, so its parts are counted here rather than
    # against the encoded segment above: the two scales differ by the 4/3 encoding ratio.
    print_parts_table(
        f"PIC Token JWT 0 payload, decoded — {len(pic_payload_raw)} bytes of JSON",
        [
            ("pic.root (base64url of the COSE)", len(pic_root_b64)),
            ("other claims and JSON syntax", len(pic_payload_raw) - len(pic_root_b64)),
        ],
    )

    print_parts_table(
        f"PIC Continuity COSE 0 — {len(continuity_bytes)} bytes, inside pic.root",
        [
            ("protected header (alg, kid)", continuity_parts[0][1]),
            ("payload: root.pca (the PCA COSE)", len(pca_bytes)),
            (
                "payload: pca_hash, profile, transitions",
                continuity_parts[2][1] - len(pca_bytes),
            ),
            ("signature (realm Ed25519)", continuity_parts[3][1]),
            ("COSE framing", continuity_parts[1][1] + continuity_framing),
        ],
    )

    authority_rows = [(f"payload: {name}", size) for name, _, size in authority_fields]
    print_parts_table(
        f"PIC PCA COSE 0 — {len(pca_bytes)} bytes, inside root.pca",
        [
            ("protected header (alg, kid)", pca_parts[0][1]),
            *authority_rows,
            ("payload: challenge.next_challenge", field_size(pca_fields, "challenge")),
            ("payload: profile and position", field_size(pca_fields, "profile")
             + field_size(pca_fields, "position")),
            (
                "payload: keys and CBOR framing",
                pca_parts[2][1]
                - sum(size for _, size in authority_rows)
                - field_size(pca_fields, "challenge")
                - field_size(pca_fields, "profile")
                - field_size(pca_fields, "position"),
            ),
            ("signature (realm Ed25519)", pca_parts[3][1]),
            ("COSE framing", pca_parts[1][1] + pca_framing),
        ],
    )

    for artifact in workers:
        presentation = artifact["presentation"]
        issuer_signed = presentation.split("~")[0]
        header, payload, signature = issuer_signed.split(".")
        disclosures = [segment for segment in presentation.split("~")[1:] if segment]
        print_parts_table(
            f"SD-JWT PoR presentation, {artifact['manifest']['worker_id']}"
            f" — {len(presentation)} bytes, EdDSA",
            [
                ("issuer-signed header (base64url)", len(header)),
                ("issuer-signed payload (_sd, cnf)", len(payload)),
                ("issuer-signed signature", len(signature)),
                ("selected disclosures", sum(len(item) for item in disclosures)),
                ("'.' and '~' separators", 2 + presentation.count("~")),
            ],
        )

    print_exchange_table(EXCHANGES)
    print_speed_comparison()

    print(f"    {paint('Stage timing — HTTP round trips measured by this client', 'bold')}")
    print(f"    {'stage':<{STAGE_WIDTH}} {'ms':>8}")
    print(f"    {'-' * STAGE_WIDTH} {'-' * 8}")
    for label, milliseconds in TIMINGS.items():
        print(f"    {label:<{STAGE_WIDTH}} {milliseconds:>8.1f}")
    print(
        "\n    The PIC-X rows are PIC work; the Keycloak rows are the IdP that produces the input"
        "\n    and the same RFC 8693 exchange performed by the IdP itself. Every row includes its"
        "\n    own HTTP round trip, which is what makes them comparable."
    )

def extract_field_bytes(data: bytes, name: str) -> bytes:
    """The exact encoded bytes of one map value, so a nested map can be weighed on its own."""
    major, _, count, offset = cbor_head(data, 0)
    if major != 5:
        raise DemoError("expected a CBOR map")

    for _ in range(count):
        key, offset = cbor_value(data, offset)
        start = offset
        _, offset = cbor_value(data, offset)
        if key == name:
            return data[start:offset]

    raise DemoError(f"the CBOR map has no `{name}` member")


def print_size_table(
    access_token: str, proposal_json: dict, proposal_wire: str, pic_token: str
) -> None:
    pic_header, pic_payload = decode_jwt(pic_token)
    pic_root = pic_payload.get("pic", {}).get("root")
    if not isinstance(pic_root, str):
        raise DemoError("PIC Token JWT payload has no pic.root")

    rows = [
        (
            "Keycloak access token JWT",
            len(access_token),
            len(access_token.encode("utf-8")),
        ),
        (
            "Initial proposal JSON",
            len(compact_json(proposal_json)),
            len(compact_json(proposal_json).encode("utf-8")),
        ),
        (
            "continuity_proposal parameter",
            len(proposal_wire),
            len(proposal_wire.encode("utf-8")),
        ),
        ("PIC Token JWT 0", len(pic_token), len(pic_token.encode("utf-8"))),
        ("PIC Token JWT header JSON", 0, len(compact_json(pic_header).encode("utf-8"))),
        (
            "PIC Token JWT payload JSON",
            0,
            len(compact_json(pic_payload).encode("utf-8")),
        ),
        ("pic.root Continuity COSE b64url", len(pic_root), len(pic_root.encode("utf-8"))),
        ("pic.root Continuity COSE bytes", 0, len(b64url_decode(pic_root))),
    ]

    print("    component                              chars    bytes")
    print("    -----------------------------------  -------  -------")
    for name, chars, bytes_len in rows:
        chars_text = "-" if chars == 0 else str(chars)
        print(f"    {name:<35} {chars_text:>7} {bytes_len:>7}")


def print_size(name: str, chars: int, bytes_len: int) -> None:
    print(f"    {paint(name + ':', 'cyan')} {chars} chars, {bytes_len} bytes")


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
    print("          +---- token exchange ---------> +------------------------+")
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
    print(f"                                          | {flow_cell('SD-JWT PoR issuer', 22)} |")
    print("                                          +------------------------+")
    print()
    print(f"  {paint('next target', 'yellow')}")
    print("  PIC Token JWT 0 -> workload candidate with SD-JWT PoR")
    print("     -> PIC-X validates PoR, transition, non-expansion")
    print("     -> realm-signed PIC Token JWT N+1")


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


def interactive_panel(title: str, detail: str | None = None) -> None:
    if not INTERACTIVE:
        return
    print()
    print(f"    {paint('=' * 72, 'dim')}")
    print(f"    {paint(title, 'bold_cyan')}")
    if detail:
        print_dim(f"    {detail}")
    print(f"    {paint('-' * 72, 'dim')}")


def interactive_pause(next_action: str) -> None:
    if not INTERACTIVE:
        return
    print()
    print(f"    {paint('Next:', 'yellow')} {next_action}")
    prompt = f"    {paint('Press Enter to continue...', 'yellow')} "
    try:
        input(prompt)
    except EOFError:
        print_dim("    stdin is closed; continuing without interactive pauses")
    print()


def print_token(label: str, token: str) -> None:
    if PRINT_VALUES:
        print_kv(label, paint(token, "cyan"))
    print_dim(f"{label} length: {len(token)} characters")
    if not PRINT_VALUES:
        print_dim("    run with `print` or `--print-tokens` to dump token contents")


def print_jwt_details(label: str, token: str) -> None:
    if not PRINT_VALUES:
        return
    header, payload = decode_jwt(token)
    print_json_block(f"{label} header", header)
    print_json_block(f"{label} payload", payload)


def print_sd_jwt_presentation(label: str, presentation: str) -> None:
    if not PRINT_VALUES:
        return
    segments = presentation.split("~")
    issuer_signed = segments[0]
    disclosures = [segment for segment in segments[1:] if segment]
    header, payload = decode_jwt(issuer_signed)
    committed = set(payload.get("_sd", []))

    decoded_disclosures = []
    for disclosure in disclosures:
        computed = b64url(hashlib.sha256(disclosure.encode("utf-8")).digest())
        try:
            parts = json.loads(b64url_decode(disclosure).decode("utf-8"))
        except (json.JSONDecodeError, UnicodeDecodeError) as error:
            decoded_disclosures.append(
                {
                    "error": str(error),
                    "digest": computed,
                    "digest_committed": computed in committed,
                }
            )
            continue

        if not isinstance(parts, list) or len(parts) != 3:
            decoded_disclosures.append(
                {
                    "error": "not a [salt, name, value] disclosure",
                    "digest": computed,
                    "digest_committed": computed in committed,
                }
            )
            continue

        salt, name, value = parts
        salt_bytes = None
        if isinstance(salt, str):
            try:
                salt_bytes = len(b64url_decode(salt))
            except Exception:
                salt_bytes = None
        decoded_disclosures.append(
            {
                "claim": name,
                "value": value,
                "salt_bytes": salt_bytes,
                "digest": computed,
                "digest_committed": computed in committed,
            }
        )

    print_json_block(f"{label} issuer-signed header", header)
    print_json_block(f"{label} issuer-signed payload", payload)
    print_json_block(
        f"{label} disclosure summary",
        {
            "committed_hashes_in__sd": len(committed),
            "presented_disclosures": len(disclosures),
            "withheld_disclosures": max(len(committed) - len(disclosures), 0),
            "decoded_disclosures": decoded_disclosures,
        },
    )


def print_pic_token_details(label: str, token: str) -> None:
    if not PRINT_VALUES:
        return
    header, payload = decode_jwt(token)
    print_json_block(f"{label} header", header)
    print_json_block(f"{label} payload", payload)

    root = payload.get("pic", {}).get("root")
    if not isinstance(root, str):
        return
    continuity_bytes = b64url_decode(root)
    continuity_parts, _ = cose_sign1_parts(continuity_bytes)
    continuity_payload = continuity_parts[2][0]
    continuity_fields, _ = cbor_map_fields(continuity_payload)
    continuity = {name: jsonable(value) for name, value, _ in continuity_fields}
    print_json_block(f"{label} PIC Continuity payload", continuity)

    pca = field_value(continuity_fields, "root")
    if isinstance(pca, dict) and isinstance(pca.get("pca"), bytes):
        pca_parts, _ = cose_sign1_parts(pca["pca"])
        pca_payload = pca_parts[2][0]
        pca_fields, _ = cbor_map_fields(pca_payload)
        print_json_block(
            f"{label} PIC PCA payload",
            {name: jsonable(value) for name, value, _ in pca_fields},
        )

    transitions = field_value(continuity_fields, "transitions")
    if isinstance(transitions, list):
        for index, transition_bytes in enumerate(transitions):
            if not isinstance(transition_bytes, bytes):
                continue
            transition_parts, _ = cose_sign1_parts(transition_bytes)
            transition_payload = transition_parts[2][0]
            transition_fields, _ = cbor_map_fields(transition_payload)
            transition = {name: jsonable(value) for name, value, _ in transition_fields}
            print_json_block(
                f"{label} PIC Transition payload {index}",
                transition,
            )
            por = field_value(transition_fields, "proof_of_relationship")
            if isinstance(por, dict) and por.get("type") == "sd-jwt":
                evidence = por.get("evidence")
                if isinstance(evidence, bytes):
                    print_sd_jwt_presentation(
                        f"{label} SD-JWT PoR evidence {index}",
                        evidence.decode("utf-8"),
                    )


def jsonable(value):
    if isinstance(value, bytes):
        return {
            "bytes": len(value),
            "b64url": b64url(value),
        }
    if isinstance(value, list):
        return [jsonable(item) for item in value]
    if isinstance(value, dict):
        return {str(key): jsonable(item) for key, item in value.items()}
    return value


def print_json_block(title: str, value) -> None:
    print(f"    {paint(title + ':', 'bold')}")
    text = json.dumps(value, indent=2, sort_keys=True, ensure_ascii=False)
    for line in text.splitlines():
        print(f"    {color_json(line)}")


def color_json(line: str) -> str:
    if not color_is_enabled():
        return line
    line = re.sub(
        r'^(\s*)"([^"]+)":',
        lambda match: f"{match.group(1)}{paint(json.dumps(match.group(2)), 'cyan')}:",
        line,
    )
    line = re.sub(
        r': "([^"]*)"',
        lambda match: f': {paint(json.dumps(match.group(1)), "green")}',
        line,
    )
    return line


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
