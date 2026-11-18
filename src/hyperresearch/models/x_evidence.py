"""Offline JSON Schema authority for continuous X research records.

The JSON assets, not these Python helpers, define record fields. Validation never
coerces, ignores unknown fields, resolves approval grants, or retrieves schemas
from the network. A structurally valid record is not execution or factual proof.
"""

from __future__ import annotations

import copy
import hashlib
import json
import math
import os
import re
import stat
from functools import lru_cache
from importlib.resources import files
from pathlib import Path
from typing import Any

import rfc8785
from jsonschema import Draft202012Validator, FormatChecker
from jsonschema.exceptions import ValidationError
from referencing import Registry, Resource
from referencing.exceptions import NoSuchResource
from referencing.jsonschema import DRAFT202012

DIALECT = "https://json-schema.org/draft/2020-12/schema"
RECORD_KINDS = (
    "source-capture", "source-receipt", "source-capabilities", "monitor-plan",
    "monitor-session", "analysis-annotation", "verified-observation", "analytics-event",
)
SOURCE_KINDS = ("source-capture", "source-receipt", "source-capabilities")
SCHEMA_IDS = {
    kind: f"https://aiwg.io/schemas/{'opencli' if kind in SOURCE_KINDS else 'hyperresearch'}-x-{kind}.v1.json"
    for kind in RECORD_KINDS
}
_DEFINITIONS = {
    "artifact-path": ("source-receipt", "artifact_path"),
    "artifact-ref": ("source-receipt", "artifact_ref"),
    "producer": ("source-receipt", "producer"),
    "source-scope": ("source-receipt", "source_scope"),
    "page-descriptor": ("source-receipt", "page_descriptor"),
    "operation-manifest": ("source-receipt", "operation_manifest"),
    "native-owner-journal": ("source-receipt", "native_owner_journal"),
    "approval-envelope": ("monitor-plan", "approval_envelope"),
    "approval-payload": ("monitor-plan", "approval_payload"),
    "trust-store": ("monitor-plan", "trust_store"),
    "grant-ledger": ("monitor-plan", "grant_ledger"),
    "export-policy": ("monitor-plan", "export_policy"),
    "analysis-policy": ("monitor-plan", "analysis_policy"),
    "provider-billing-bounds": ("monitor-plan", "provider_billing_bounds"),
    "observation-binding": ("monitor-plan", "observation_binding"),
    "x-config": ("monitor-plan", "x_config"),
    "note-evidence-refs": ("monitor-session", "note_evidence_refs"),
    "evidence-manifest": ("monitor-session", "evidence_manifest"),
    "evidence-transport": ("monitor-session", "evidence_transport"),
    "note-transport": ("monitor-session", "note_transport"),
    "authority-snapshot": ("monitor-session", "authority_snapshot"),
    "monitor-pointer": ("monitor-session", "monitor_pointer"),
    "monitor-control": ("monitor-session", "monitor_control"),
    "analysis-request": ("analysis-annotation", "analysis_request"),
    "source-span": ("analysis-annotation", "source_span"),
    "observation-evidence": ("verified-observation", "observation_evidence"),
    "observation-entity": ("verified-observation", "entity"),
}


class ContractValidationError(ValueError):
    """A value fails its canonical authority, or is not JSON-safe."""


class ArtifactReferenceError(ContractValidationError):
    """An artifact path, file type, containment or checksum is unsafe."""


class SchemaProjectionError(ContractValidationError):
    """An authority pin or consumer projection has drifted."""

_SURROGATE_CODE_POINT = re.compile(r"[\ud800-\udfff]")



def _require_json(value: Any, active: set[int] | None = None) -> None:
    """Enforce JSON/UTF-8 transport syntax, not a second family field contract."""
    if type(value) is str:
        if _SURROGATE_CODE_POINT.search(value) is not None:
            raise ContractValidationError("Surrogate code points are not UTF-8 JSON strings")
        return
    if value is None or type(value) in (int, bool):
        return
    if type(value) is float:
        if not math.isfinite(value):
            raise ContractValidationError("Non-finite numbers are not JSON values")
        return
    if type(value) not in (dict, list):
        raise ContractValidationError(f"Non-JSON value type: {type(value).__name__}")
    if active is None:
        active = set()
    identity = id(value)
    if identity in active:
        raise ContractValidationError("Cyclic values are not JSON values")
    active.add(identity)
    try:
        if type(value) is dict:
            for key, item in value.items():
                if type(key) is not str:
                    raise ContractValidationError("JSON object keys must be strings")
                _require_json(key, active)
                _require_json(item, active)
        else:
            for item in value:
                _require_json(item, active)
    finally:
        active.remove(identity)


def canonical_bytes(value: Any) -> bytes:
    """RFC 8785 JCS UTF-8 bytes through the maintained rfc8785 implementation.

    Integral-float spelling, ECMAScript finite-number formatting and UTF-16 key
    order agree with the native JCS producer. Unsafe integers, lone surrogates
    and non-finite numbers fail explicitly. SDK wire bytes and raw artifact
    checksums remain independent of canonical record digests.
    """
    _require_json(value)
    try:
        return rfc8785.dumps(value)
    except (rfc8785.CanonicalizationError, UnicodeError, RecursionError) as exc:
        raise ContractValidationError("Value cannot be encoded as RFC 8785 UTF-8 JSON") from exc


def record_digest(value: Any) -> str:
    """Return bare lowercase SHA256 hex of canonical_bytes(value)."""
    return hashlib.sha256(canonical_bytes(value)).hexdigest()


def _assets() -> Any:
    return files("hyperresearch").joinpath("schemas", "x")


@lru_cache(maxsize=1)
def _catalog_entries() -> dict[str, dict[str, Any]]:
    catalog = json.loads(_assets().joinpath("catalog.json").read_text(encoding="utf-8"))
    if catalog.get("schemaVersion") != "1":
        raise SchemaProjectionError("Unsupported packaged schema catalog version")
    entries = {}
    for domain in catalog["domains"]:
        if not isinstance(domain, dict):
            raise SchemaProjectionError("Packaged catalog requires inline domain manifests")
        for artifact in domain["artifacts"]:
            if artifact["id"] in entries:
                raise SchemaProjectionError("Duplicate packaged schema identity")
            entries[artifact["id"]] = artifact
    return entries


@lru_cache(maxsize=len(RECORD_KINDS))
def _authority(kind: str) -> dict[str, Any]:
    if kind not in SCHEMA_IDS:
        raise ContractValidationError(f"Unknown record family: {kind}")
    raw = _assets().joinpath(f"{kind}.schema.json").read_bytes()
    entry = _catalog_entries().get(SCHEMA_IDS[kind])
    actual = f"sha256:{hashlib.sha256(raw).hexdigest()}"
    if entry is None or entry.get("digest") != actual:
        raise SchemaProjectionError(f"Schema digest pin mismatch: {kind}")
    schema = json.loads(raw)
    if schema.get("$id") != SCHEMA_IDS[kind] or schema.get("$schema") != DIALECT:
        raise SchemaProjectionError(f"Schema identity/dialect mismatch: {kind}")
    return schema


def schema_uri(kind: str) -> str:
    """Return a governed family ID or definition URI; never a fetch URL."""
    if kind in SCHEMA_IDS:
        return SCHEMA_IDS[kind]
    if kind in _DEFINITIONS:
        family, definition = _DEFINITIONS[kind]
        return f"{SCHEMA_IDS[family]}#/$defs/{definition}"
    raise ContractValidationError(f"Unknown contract: {kind}")


def load_schema(kind: str) -> dict[str, Any]:
    """Return a detached authority, or a local-registry definition reference.

    Definition names are the hyphenated public API keys above. The returned
    definition wrapper resolves with this module's offline registry; callers
    must not substitute a network resolver.
    """
    if kind in SCHEMA_IDS:
        return copy.deepcopy(_authority(kind))
    if kind in _DEFINITIONS:
        family, definition = _DEFINITIONS[kind]
        if definition not in _authority(family)["$defs"]:
            raise SchemaProjectionError(f"Missing governed definition: {kind}")
        return {"$schema": DIALECT, "$ref": schema_uri(kind)}
    raise ContractValidationError(f"Unknown contract: {kind}")


def _deny_retrieval(uri: str) -> Resource[Any]:
    raise NoSuchResource(ref=uri)


@lru_cache(maxsize=1)
def _registry() -> Registry[Any]:
    resources = (
        (SCHEMA_IDS[kind], Resource.from_contents(_authority(kind), default_specification=DRAFT202012))
        for kind in RECORD_KINDS
    )
    return Registry(retrieve=_deny_retrieval).with_resources(resources)


@lru_cache(maxsize=len(RECORD_KINDS) + len(_DEFINITIONS))
def _validator(kind: str) -> Draft202012Validator:
    return Draft202012Validator(load_schema(kind), registry=_registry(), format_checker=FormatChecker())


def _validate(kind: str, payload: Any) -> None:
    _require_json(payload)
    try:
        _validator(kind).validate(payload)
    except ValidationError as exc:
        location = "/" + "/".join(str(part).replace("~", "~0").replace("/", "~1") for part in exc.absolute_path)
        # Do not echo retained source text, provider payloads or operator data.
        raise ContractValidationError(f"{kind} at {location}: violates {exc.validator}") from exc


def validate_record(kind: str, payload: Any) -> dict[str, Any]:
    """Validate a family or object definition and return detached JSON-safe data.

    No fields are dropped, no defaults are inserted and no authority is granted.
    Use validate_artifact_path for the scalar artifact-path definition.
    """
    _validate(kind, payload)
    if type(payload) is not dict:
        raise ContractValidationError(f"{kind} requires a JSON object result")
    return copy.deepcopy(payload)


def validate_definition(kind: str, payload: Any) -> dict[str, Any]:
    """Validate an explicitly governed definition, not a ninth record family."""
    if kind not in _DEFINITIONS:
        raise ContractValidationError(f"Unknown governed definition: {kind}")
    return validate_record(kind, payload)


def plan_digest(plan: Any) -> str:
    """Validate the required digest against the full plan excluding only digest.

    Grant bindings use this checked digest. The raw stored artifact SHA256 is
    independent. Criteria and analysis envelope digests hash the entire profile
    and analysis objects respectively, including source/guard/export settings.
    """
    record = validate_record("monitor-plan", plan)
    expected = record_digest({key: value for key, value in record.items() if key != "digest"})
    if record["digest"] != expected:
        raise ContractValidationError("monitor-plan digest does not match canonical plan content")
    return expected


def _safe_root(root: str | Path) -> Path:
    path = Path(root).absolute()
    for ancestor in (*reversed(path.parents), path):
        if ancestor.is_symlink():
            raise ArtifactReferenceError("Artifact root has a symlink ancestor")
    if not path.is_dir():
        raise ArtifactReferenceError("Artifact root must be an existing directory")
    return path.resolve(strict=True)


def validate_artifact_path(path: Any, root: str | Path | None = None) -> Path:
    """Validate a relative POSIX path, optionally proving filesystem containment.

    Without root, return the safe relative Path. With root, return the contained
    absolute path, refusing symlink components and non-regular existing files.
    Missing leaf/directories are allowed for prospective atomic writes; this
    helper does not create them or grant write authority.
    """
    try:
        _validate("artifact-path", path)
    except ContractValidationError as exc:
        raise ArtifactReferenceError("Unsafe relative artifact path") from exc
    relative = Path(path)
    if root is None:
        return relative
    base = _safe_root(root)
    target = base
    for index, component in enumerate(relative.parts):
        target /= component
        if target.is_symlink():
            raise ArtifactReferenceError("Artifact path has a symlink component")
        if target.exists():
            if index < len(relative.parts) - 1 and not target.is_dir():
                raise ArtifactReferenceError("Artifact parent is not a directory")
            if index == len(relative.parts) - 1 and not (target.is_file() or target.is_dir()):
                raise ArtifactReferenceError("Artifact target is not a regular file/directory")
    if not target.resolve(strict=False).is_relative_to(base):
        raise ArtifactReferenceError("Artifact path escapes its configured root")
    return target


def _contained_file_digest(root: str | Path, relative: str) -> str:
    """Open the root and each relative component with dir_fd/O_NOFOLLOW."""
    base = _safe_root(root)
    directory: int | None = None
    file_descriptor: int | None = None
    try:
        directory = os.open(base.anchor, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        for component in (*base.parts[1:], *Path(relative).parts[:-1]):
            next_directory = os.open(component, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=directory)
            os.close(directory)
            directory = next_directory
        file_descriptor = os.open(Path(relative).name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory)
        if not stat.S_ISREG(os.fstat(file_descriptor).st_mode):
            raise ArtifactReferenceError("Artifact reference must identify a regular file")
        with os.fdopen(file_descriptor, "rb") as stream:
            file_descriptor = None
            return hashlib.file_digest(stream, "sha256").hexdigest()
    except OSError as exc:
        raise ArtifactReferenceError("Cannot safely open contained artifact") from exc
    finally:
        if file_descriptor is not None:
            os.close(file_descriptor)
        if directory is not None:
            os.close(directory)


def validate_artifact_ref(
    ref: Any,
    root: str | Path | None = None,
    verify_checksum: bool = False,
) -> dict[str, Any]:
    """Validate all declared reference fields, path containment and optional bytes.

    sha256 is bare 64-hex and always structurally checked. Checksum verification
    requires a root and a regular file; it never fetches a URI or follows links.
    """
    try:
        record = validate_record("artifact-ref", ref)
        target = validate_artifact_path(record["path"], root)
        if root is not None and target.exists() and not target.is_file():
            raise ArtifactReferenceError("Artifact reference must identify a regular file")
    except ContractValidationError as exc:
        raise ArtifactReferenceError("Invalid artifact reference") from exc
    if verify_checksum:
        if root is None:
            raise ArtifactReferenceError("Checksum verification requires an artifact root")
        if _contained_file_digest(root, record["path"]) != record["sha256"]:
            raise ArtifactReferenceError("Artifact checksum mismatch")
    return record


def verify_record_projection(kind: str, canonical: Any, projected: Any) -> None:
    """Prove a JSON projection preserves every field and reference exactly."""
    original = validate_record(kind, canonical)
    restored = validate_record(kind, projected)
    if canonical_bytes(original) != canonical_bytes(restored):
        raise SchemaProjectionError(f"Lossy or changed {kind} projection")


def verify_reference_projection(canonical: Any, projected: Any) -> None:
    """Prove NoteMeta/frontmatter/cache/export preserve refs AND actual producer."""
    verify_record_projection("note-evidence-refs", canonical, projected)


def verify_schema_projections(opencli_root: str | Path | None = None) -> dict[str, str]:
    """Verify packaged pins and, when supplied, exact cross-product byte parity.

    The integration owner runs this after all edits land. Without a peer checkout
    it checks the declared pinned packaged authorities, not remote publication.
    """
    catalog = json.loads(_assets().joinpath("catalog.json").read_text(encoding="utf-8"))
    entries = {entry["id"]: entry for domain in catalog["domains"] for entry in domain["artifacts"]}
    result = {}
    for kind in RECORD_KINDS:
        raw = _assets().joinpath(f"{kind}.schema.json").read_bytes()
        actual = f"sha256:{hashlib.sha256(raw).hexdigest()}"
        schema = json.loads(raw)
        if schema.get("$id") != SCHEMA_IDS[kind] or schema.get("$schema") != DIALECT:
            raise SchemaProjectionError(f"Schema identity/dialect mismatch: {kind}")
        if entries.get(SCHEMA_IDS[kind], {}).get("digest") != actual:
            raise SchemaProjectionError(f"Schema digest pin mismatch: {kind}")
        result[SCHEMA_IDS[kind]] = actual
    if opencli_root is not None:
        peer = Path(opencli_root)
        for kind in SOURCE_KINDS:
            local = _assets().joinpath(f"{kind}.schema.json").read_bytes()
            if (peer / "schemas" / "x" / f"{kind}.schema.json").read_bytes() != local:
                raise SchemaProjectionError(f"OpenCLI source authority mirror differs: {kind}")
        plan = _assets().joinpath("monitor-plan.schema.json").read_bytes()
        if (peer / "schemas" / "x" / "monitor-plan.schema.json").read_bytes() != plan:
            raise SchemaProjectionError("OpenCLI approval authority mirror differs: monitor-plan")
    return result
