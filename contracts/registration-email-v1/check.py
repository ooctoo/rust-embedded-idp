#!/usr/bin/env python3
"""Verify the checked-in I1 contract files without implementing JSON Schema."""

from __future__ import annotations

import hashlib
import json
import re
import sys
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parent
PROFILE = "idp-registration-email-v1"
HEADER_NAME = "X-IDP-Registration-Profile"
HEADER_VALUE = PROFILE
MIN_FIXTURES = 24
REQUIRED_STATES = {"unknown", "pending", "active", "disabled"}
ERROR_CODES = {
    "registration_profile_required",
    "invalid_request",
    "invalid_registration",
    "invalid_tenant",
    "request_expired",
    "request_conflict",
    "registration_closed",
    "source_limited",
    "temporarily_unavailable",
    "verification_unavailable",
}
ROUTES = [
    {"method": "POST", "path": "/auth/register"},
    {"method": "POST", "path": "/auth/resend-verification"},
    {"method": "POST", "path": "/auth/verify-email"},
]
UUID7_PATTERN = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$"
)
RUNTIME_BASE_KEYS = {
    "server_now_unix_secs",
    "trusted_scope",
    "operation_timestamp_unix_secs",
    "operation_max_age_secs",
}
RUNTIME_CONTEXT_KEYS = RUNTIME_BASE_KEYS | {
    "context_accepted_at_unix_secs",
    "context_lifetime_secs",
    "context_expires_at_unix_secs",
}
SEMANTIC_RESULTS = {
    "register_accepted",
    "resend_accepted",
    "verify_success",
    "error",
}
FORBIDDEN_PUBLIC_KEYS = {
    "account_id",
    "accountId",
    "account_status",
    "delivery",
    "delivery_status",
    "email",
    "leak",
    "password",
    "session",
    "session_id",
    "token",
}


def fail(message: str) -> None:
    raise SystemExit(f"check failed: {message}")


def no_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            fail(f"duplicate JSON key {key!r}")
        result[key] = value
    return result


def load_json(path: Path) -> Any:
    try:
        raw = path.read_bytes()
        if raw.startswith(b"\xef\xbb\xbf"):
            fail(f"UTF-8 BOM is not allowed in {path.name}")
        return json.loads(
            raw.decode("utf-8"), object_pairs_hook=no_duplicate_keys
        )
    except UnicodeDecodeError as exc:
        fail(f"{path.name} is not UTF-8: {exc}")
    except json.JSONDecodeError as exc:
        fail(f"invalid JSON in {path.name}: {exc}")


def canonical_bytes(value: Any) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def sha256_file(path: Path) -> str:
    return sha256_bytes(path.read_bytes())


def is_int(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def uuidv7_timestamp_unix_secs(value: str) -> int:
    if not UUID7_PATTERN.fullmatch(value):
        fail(f"invalid lower-case UUIDv7 in runtime fixture: {value!r}")
    milliseconds = int(value.split("-")[0] + value.split("-")[1], 16)
    return milliseconds // 1000


def walk_keys(value: Any):
    if isinstance(value, dict):
        for key, child in value.items():
            yield key, child
            yield from walk_keys(child)
    elif isinstance(value, list):
        for child in value:
            yield from walk_keys(child)


def require_http_shape(fixture: dict[str, Any]) -> None:
    http = fixture.get("http")
    if not isinstance(http, dict):
        fail(f"{fixture['id']}: missing http metadata")
    profile_header = http.get("profile_header")
    if fixture.get("response", {}).get("error", {}).get("code") == "registration_profile_required":
        if profile_header not in (
            None,
            {"name": HEADER_NAME, "value": "other-profile"},
        ):
            fail(f"{fixture['id']}: profile error must show missing or wrong header")
    elif profile_header != {"name": HEADER_NAME, "value": HEADER_VALUE}:
        fail(f"{fixture['id']}: profile header is not fixed")
    if http.get("cache_control") != "no-store":
        fail(f"{fixture['id']}: response must be no-store")
    if http.get("set_cookie") is not False:
        fail(f"{fixture['id']}: cookies are not allowed")
    if http.get("location") is not None:
        fail(f"{fixture['id']}: redirects are not allowed")
    status = http.get("expected_status")
    retry_after = http.get("retry_after")
    if status == 429:
        if not isinstance(retry_after, dict) or retry_after.get("scope") != "source":
            fail(f"{fixture['id']}: 429 must carry source-only Retry-After metadata")
    elif retry_after is not None:
        fail(f"{fixture['id']}: Retry-After is only allowed for 429")


def require_public_response_shape(fixture: dict[str, Any]) -> None:
    response = fixture.get("response")
    if not isinstance(response, dict):
        fail(f"{fixture['id']}: response must be an object")
    for key, _ in walk_keys(response):
        if key in FORBIDDEN_PUBLIC_KEYS:
            fail(f"{fixture['id']}: forbidden public response key {key!r}")
    if fixture.get("kind") == "error":
        if set(response) != {"error"}:
            fail(f"{fixture['id']}: error response has non-fixed fields")
        error = response.get("error")
        if not isinstance(error, dict) or set(error) != {"code"}:
            fail(f"{fixture['id']}: error shape must be {{error: {{code}}}}")
        if error.get("code") not in ERROR_CODES:
            fail(f"{fixture['id']}: unknown error code")


def check_status_mapping(fixture: dict[str, Any]) -> None:
    if fixture.get("kind") != "error":
        return
    code = fixture["response"]["error"]["code"]
    status = fixture["http"]["expected_status"]
    if code == "invalid_request":
        expected = 400 if fixture.get("subtype") == "invalid_json" else 422
    else:
        expected = {
            "registration_profile_required": 400,
            "invalid_registration": 400,
            "invalid_tenant": 400,
            "request_expired": 400,
            "request_conflict": 409,
            "registration_closed": 403,
            "source_limited": 429,
            "temporarily_unavailable": 503,
            "verification_unavailable": 503,
        }[code]
    if status != expected:
        fail(f"{fixture['id']}: {code} must use HTTP {expected}, got {status}")


def check_runtime_semantics(fixture: dict[str, Any]) -> None:
    """Check fixture timing/scope metadata without validating JSON Schema."""

    if fixture.get("valid") is False:
        if "runtime" in fixture or "semantic" in fixture or "replay" in fixture:
            fail(f"{fixture['id']}: shape-invalid fixture must not carry runtime metadata")
        return

    runtime = fixture.get("runtime")
    if not isinstance(runtime, dict):
        fail(f"{fixture['id']}: shape-valid fixture needs runtime metadata")
    path = fixture["http"].get("path")
    expected_runtime_keys = (
        RUNTIME_CONTEXT_KEYS
        if path in {"/auth/resend-verification", "/auth/verify-email"}
        else RUNTIME_BASE_KEYS
    )
    if set(runtime) != expected_runtime_keys:
        fail(f"{fixture['id']}: runtime keys do not match its route")
    for key in (
        "server_now_unix_secs",
        "operation_timestamp_unix_secs",
        "operation_max_age_secs",
    ):
        if not is_int(runtime[key]) or runtime[key] < 0:
            fail(f"{fixture['id']}: runtime.{key} must be a non-negative integer")
    if runtime["operation_max_age_secs"] <= 0:
        fail(f"{fixture['id']}: operation max age must be positive")
    scope = runtime["trusted_scope"]
    if not isinstance(scope, dict) or set(scope) != {
        "authority",
        "product",
        "tenant",
        "mode",
    }:
        fail(f"{fixture['id']}: trusted_scope has the wrong shape")
    if any(not isinstance(scope[key], str) or not scope[key] for key in scope):
        fail(f"{fixture['id']}: trusted_scope values must be non-empty strings")
    if scope["mode"] != "enabled":
        fail(f"{fixture['id']}: trusted scope mode must be enabled")

    input_obj = fixture.get("input")
    if not isinstance(input_obj, dict):
        fail(f"{fixture['id']}: shape-valid fixture needs an object input")
    operation_id = input_obj.get("client_operation_id")
    if not isinstance(operation_id, str):
        fail(f"{fixture['id']}: shape-valid fixture needs a client operation id")
    operation_timestamp = uuidv7_timestamp_unix_secs(operation_id)
    if runtime["operation_timestamp_unix_secs"] != operation_timestamp:
        fail(f"{fixture['id']}: UUIDv7 timestamp metadata mismatch")
    server_now = runtime["server_now_unix_secs"]
    age_limit = operation_timestamp + runtime["operation_max_age_secs"]
    if server_now < operation_timestamp:
        fail(f"{fixture['id']}: server clock precedes operation timestamp")

    code = fixture.get("response", {}).get("error", {}).get("code")
    if code == "request_expired":
        if server_now <= age_limit:
            fail(f"{fixture['id']}: request_expired must be outside operation max age")
    elif server_now > age_limit:
        fail(f"{fixture['id']}: non-expired fixture is outside operation max age")

    if path in {"/auth/resend-verification", "/auth/verify-email"}:
        accepted = runtime["context_accepted_at_unix_secs"]
        lifetime = runtime["context_lifetime_secs"]
        expires = runtime["context_expires_at_unix_secs"]
        if not all(is_int(runtime[key]) for key in RUNTIME_CONTEXT_KEYS - RUNTIME_BASE_KEYS):
            fail(f"{fixture['id']}: context runtime values must be integers")
        if lifetime <= 0 or expires != accepted + lifetime:
            fail(f"{fixture['id']}: context expiry metadata is inconsistent")
        if code == "request_expired":
            if server_now <= expires:
                fail(f"{fixture['id']}: request_expired context is not expired")
        elif server_now > expires:
            fail(f"{fixture['id']}: non-expired context is already expired")

    semantic = fixture.get("semantic")
    if not isinstance(semantic, dict) or set(semantic) != {
        "result",
        "expected_error_code",
    }:
        fail(f"{fixture['id']}: shape-valid fixture needs semantic metadata")
    result = semantic["result"]
    if result not in SEMANTIC_RESULTS:
        fail(f"{fixture['id']}: unknown semantic result")
    if code is None:
        if semantic["expected_error_code"] is not None:
            fail(f"{fixture['id']}: successful fixture has an expected error")
        expected_result = {
            "RegisterAccepted": "register_accepted",
            "ResendAccepted": "resend_accepted",
            "VerifySuccess": "verify_success",
        }.get(fixture.get("response_schema"))
        if result != expected_result:
            fail(f"{fixture['id']}: semantic result does not match response schema")
    elif result != "error" or semantic["expected_error_code"] != code:
        fail(f"{fixture['id']}: semantic error metadata does not match response")

    response = fixture.get("response", {})
    if fixture.get("response_schema") == "RegisterAccepted":
        accepted = response.get("accepted_at_unix_secs")
        if not is_int(accepted) or accepted != server_now:
            fail(f"{fixture['id']}: accepted_at must equal the trusted server clock")
        if accepted < operation_timestamp or accepted > age_limit:
            fail(f"{fixture['id']}: accepted_at is inconsistent with UUIDv7 max age")

    replay = fixture.get("replay")
    if replay is not None:
        if path != "/auth/register" or not isinstance(replay, dict) or set(replay) != {
            "group",
            "role",
            "peer_fixture_id",
            "deadline_unix_secs",
            "deadline_extended",
        }:
            fail(f"{fixture['id']}: invalid original-key replay metadata")
        if replay["group"] != "register-original-key" or replay["role"] not in {
            "original",
            "replay",
        }:
            fail(f"{fixture['id']}: invalid original-key replay role")
        if not is_int(replay["deadline_unix_secs"]) or replay["deadline_extended"] is not False:
            fail(f"{fixture['id']}: replay deadline must be a fixed integer")
        if replay["deadline_unix_secs"] != response["accepted_at_unix_secs"] + response["context_lifetime_secs"]:
            fail(f"{fixture['id']}: replay deadline must derive from the original acceptance")


def check_fixture_hashes(fixtures: dict[str, Any], manifest: dict[str, Any]) -> None:
    entries = fixtures.get("fixtures")
    if not isinstance(entries, list):
        fail("fixtures must contain an array")
    if len(entries) < MIN_FIXTURES:
        fail(f"need at least {MIN_FIXTURES} fixtures")
    ids = [item.get("id") for item in entries if isinstance(item, dict)]
    if len(ids) != len(entries) or any(not isinstance(item, str) for item in ids):
        fail("every fixture needs a string id")
    if len(set(ids)) != len(ids):
        fail("fixture ids must be unique")
    if ids != sorted(ids):
        fail("fixtures must be sorted by id")

    manifest_entries = manifest.get("fixture_hashes")
    if not isinstance(manifest_entries, list):
        fail("manifest fixture_hashes must be an array")
    if manifest_entries != [
        {"id": item["id"], "canonical_sha256": sha256_bytes(canonical_bytes(item))}
        for item in entries
    ]:
        fail("manifest fixture hashes do not match canonical fixture objects")

    states: set[str] = set()
    paths: set[str] = set()
    error_codes: set[str] = set()
    valid = invalid = 0
    for fixture in entries:
        if not isinstance(fixture, dict):
            fail("fixture entries must be objects")
        if fixture.get("profile") != PROFILE:
            fail(f"{fixture['id']}: wrong profile")
        if fixture.get("valid") is True:
            valid += 1
        elif fixture.get("valid") is False:
            invalid += 1
        else:
            fail(f"{fixture['id']}: valid must be boolean")
        state = fixture.get("state")
        if state is not None:
            states.add(state)
        paths.add(fixture["http"].get("path"))
        if fixture.get("kind") == "error":
            error_codes.add(fixture["response"]["error"]["code"])
        require_http_shape(fixture)
        require_public_response_shape(fixture)
        check_status_mapping(fixture)
        check_runtime_semantics(fixture)
    if valid == 0 or invalid == 0:
        fail("need both valid and invalid fixtures")
    if not REQUIRED_STATES.issubset(states):
        fail(f"missing state fixtures: {sorted(REQUIRED_STATES - states)}")
    expected_paths = {route["path"] for route in ROUTES}
    if paths != expected_paths:
        fail(f"fixture routes must cover exactly {sorted(expected_paths)}")
    if error_codes != ERROR_CODES:
        fail(f"fixture error-code coverage mismatch: {sorted(ERROR_CODES - error_codes)}")

    state_responses = [
        item["response"] for item in entries if item.get("state") in REQUIRED_STATES
    ]
    if len(state_responses) != len(REQUIRED_STATES) or any(
        response != state_responses[0] for response in state_responses[1:]
    ):
        fail("unknown/pending/active/disabled must share one RegisterAccepted object")
    if state_responses[0] != {
        "accepted_at_unix_secs": 1713894200,
        "context_lifetime_secs": 900,
        "resend_after_secs": 60,
        "status": "verification_requested",
        "verification_context": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
    }:
        fail("state fixtures do not use the frozen RegisterAccepted object")

    replay_entries = [item for item in entries if item.get("replay") is not None]
    if {item["id"] for item in replay_entries} != {
        "register-valid-minimal",
        "register-replay-same-key",
    }:
        fail("original-key replay coverage must contain exactly two fixtures")
    original, replay = sorted(replay_entries, key=lambda item: item["replay"]["role"])
    if original["replay"]["role"] != "original" or replay["replay"]["role"] != "replay":
        fail("original-key replay roles are not paired")
    if original["replay"]["peer_fixture_id"] != replay["id"] or replay["replay"]["peer_fixture_id"] != original["id"]:
        fail("original-key replay peers do not point at each other")
    if original["input"] != replay["input"]:
        fail("original-key replay requests must use the same operation key and payload")
    if original["runtime"] != replay["runtime"] or original["response"] != replay["response"]:
        fail("original-key replay must preserve runtime and accepted response")
    if original["replay"]["deadline_unix_secs"] != replay["replay"]["deadline_unix_secs"]:
        fail("original-key replay must preserve the deadline")


def main() -> None:
    schema_path = ROOT / "schema.json"
    fixtures_path = ROOT / "fixtures.json"
    manifest_path = ROOT / "manifest.json"
    schema = load_json(schema_path)
    fixtures = load_json(fixtures_path)
    manifest = load_json(manifest_path)
    if not isinstance(schema, dict) or schema.get("$schema") != (
        "https://json-schema.org/draft/2020-12/schema"
    ):
        fail("schema must declare JSON Schema draft 2020-12")
    if not isinstance(fixtures, dict) or fixtures.get("profile") != PROFILE:
        fail("fixtures profile mismatch")
    if not isinstance(manifest, dict) or manifest.get("profile") != PROFILE:
        fail("manifest profile mismatch")
    if manifest.get("schema_file") != "schema.json" or manifest.get("fixtures_file") != "fixtures.json":
        fail("manifest file names are not fixed")
    if manifest.get("canonicalization") != {
        "encoding": "UTF-8",
        "ensure_ascii": False,
        "separators": [",", ":"],
        "sort_keys": True,
    }:
        fail("manifest canonicalization rules are not fixed")
    if manifest.get("header") != {"name": HEADER_NAME, "value": HEADER_VALUE}:
        fail("manifest profile header mismatch")
    if manifest.get("routes") != ROUTES:
        fail("manifest routes do not match the checked old module-local routes")
    if manifest.get("schema_sha256") != sha256_file(schema_path):
        fail("schema_sha256 mismatch")
    if manifest.get("fixtures_sha256") != sha256_file(fixtures_path):
        fail("fixtures_sha256 mismatch")
    check_fixture_hashes(fixtures, manifest)
    manifest_without_hash = dict(manifest)
    manifest_without_hash.pop("canonical_sha256", None)
    expected_manifest_hash = sha256_bytes(canonical_bytes(manifest_without_hash))
    if manifest.get("canonical_sha256") != expected_manifest_hash:
        fail("manifest canonical_sha256 mismatch")
    print(
        f"ok: profile={PROFILE} fixtures={len(fixtures['fixtures'])} "
        f"schema_sha256={manifest['schema_sha256']} "
        f"fixtures_sha256={manifest['fixtures_sha256']} "
        f"canonical_sha256={manifest['canonical_sha256']}"
    )


if __name__ == "__main__":
    main()
