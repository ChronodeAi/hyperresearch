"""Checksummed local evidence artifacts, credential refusal and atomic publication."""

from __future__ import annotations

import hashlib
import json
import os
import re
import tempfile
from pathlib import Path

from hyperresearch.models.x_evidence import (
    canonical_bytes,
    validate_artifact_path,
    validate_artifact_ref,
    validate_record,
)

CREDENTIAL_KEYS = frozenset({
    "authorization", "cookie", "cookies", "setcookie", "headers", "requestheaders",
    "authtoken", "accesstoken", "refreshtoken", "bearertoken", "csrftoken",
    "ct0", "password", "secret", "apikey", "privatekey",
})
_CREDENTIAL_TEXT = re.compile(r"(?i)(?:bearer\s+[a-z0-9._~+/=-]{16,}|-----BEGIN (?:[A-Z ]+ )?PRIVATE KEY-----|https?://[^\s/@:]+:[^\s/@]+@)")


def reject_credentials(value, _active=None) -> None:
    active = set() if _active is None else _active
    if isinstance(value, (dict, list)):
        identity = id(value)
        if identity in active:
            raise ValueError("Cyclic evidence is not JSON data")
        active.add(identity)
        try:
            if isinstance(value, dict):
                for key, child in value.items():
                    if not isinstance(key, str):
                        raise ValueError("Evidence JSON keys must be strings")
                    if re.sub(r"[^a-z0-9]", "", key.lower()) in CREDENTIAL_KEYS:
                        raise ValueError("Credentials or private request metadata cannot be retained")
                    reject_credentials(child, active)
            else:
                for child in value:
                    reject_credentials(child, active)
        finally:
            active.remove(identity)
    elif isinstance(value, str) and _CREDENTIAL_TEXT.search(value):
        raise ValueError("Credential-bearing text cannot be retained")


def decode_json(data: bytes | str):
    """Reject shadowed fields and non-JSON numbers before schema/credential validation."""
    def object_pairs(pairs):
        value = {}
        for key, child in pairs:
            if key in value:
                raise ValueError(f"Duplicate evidence JSON field: {key}")
            value[key] = child
        return value

    def invalid_constant(value):
        raise ValueError(f"Non-JSON number in evidence: {value}")

    return json.loads(data, object_pairs_hook=object_pairs, parse_constant=invalid_constant)


def artifact_path(root: Path, relative: str) -> Path:
    """Validate containment and refuse symlink traversal, including in parent dirs."""
    relative_path = validate_artifact_path(relative)
    root = root.resolve()
    candidate = root / relative_path
    for part in (candidate, *candidate.parents):
        if part == root:
            break
        if part.is_symlink():
            raise ValueError(f"Symlink evidence path refused: {relative}")
    return validate_artifact_path(relative, root=root)


def artifact_ref(root: Path, path: Path) -> dict:
    relative = path.relative_to(root).as_posix()
    artifact_path(root, relative)
    return {"path": relative, "sha256": hashlib.sha256(path.read_bytes()).hexdigest()}


def read_artifact(root: Path, ref: dict) -> bytes:
    validated = validate_artifact_ref(ref)
    path = artifact_path(root, validated["path"])
    if not path.is_file():
        raise ValueError(f"Missing evidence artifact: {validated['path']}")
    data = path.read_bytes()
    if hashlib.sha256(data).hexdigest() != validated["sha256"]:
        raise ValueError(f"Evidence checksum mismatch: {validated['path']}")
    return data


def read_json(root: Path, ref: dict) -> dict:
    try:
        value = decode_json(read_artifact(root, ref))
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise ValueError(f"Invalid evidence JSON: {ref['path']}") from exc
    reject_credentials(value)
    return value


def atomic_write(path: Path, data: bytes, *, immutable: bool = False) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if immutable and path.exists():
        if path.read_bytes() != data:
            raise ValueError(f"Immutable evidence collision: {path.name}")
        return
    descriptor, temporary = tempfile.mkstemp(prefix=".commit-", dir=path.parent)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        if immutable:
            try:
                os.link(temporary, path)
            except FileExistsError:
                if path.read_bytes() != data:
                    raise ValueError(f"Immutable evidence collision: {path.name}") from None
        else:
            os.replace(temporary, path)
        directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def nested_refs(value):
    if isinstance(value, dict):
        if "path" in value and "sha256" in value:
            yield validate_artifact_ref(value)
        else:
            for child in value.values():
                yield from nested_refs(child)
    elif isinstance(value, list):
        for child in value:
            yield from nested_refs(child)


def validate_closure(root: Path, payload: dict, *, seen=None) -> None:
    """Require every declared descendant to be recoverable, never fetch it."""
    seen = seen if seen is not None else set()
    for ref in nested_refs(payload):
        identity = (str(root), ref["path"], ref["sha256"])
        if identity in seen:
            continue
        seen.add(identity)
        data = read_artifact(root, ref)
        if ref["path"].endswith(".json"):
            try:
                child = decode_json(data)
            except (UnicodeError, json.JSONDecodeError) as exc:
                raise ValueError(f"Invalid evidence JSON: {ref['path']}") from exc
            reject_credentials(child)
            validate_closure(root, child, seen=seen)
        else:
            reject_credentials(data.decode("utf-8"))


def publish_manifest(root: Path, manifest: dict) -> dict:
    value = validate_record("evidence-manifest", manifest)
    data = canonical_bytes(value)
    digest = hashlib.sha256(data).hexdigest()
    path = artifact_path(root, f"manifests/{digest}.json")
    atomic_write(path, data, immutable=True)
    return {"path": path.relative_to(root).as_posix(), "sha256": digest}
