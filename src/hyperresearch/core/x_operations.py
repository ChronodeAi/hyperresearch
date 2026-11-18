"""Incremental, scope-bound import of OpenCLI's atomically committed source pages."""

from __future__ import annotations

import hashlib
import re
from pathlib import Path

from hyperresearch.core.x_artifacts import (
    artifact_path,
    artifact_ref,
    atomic_write,
    decode_json,
    read_json,
    reject_credentials,
    validate_closure,
)
from hyperresearch.models.x_evidence import canonical_bytes, record_digest, validate_record

_PAGE_DIRECTORY = re.compile(r"^[0-9]+$")


def _read_scope(operation: Path) -> dict:
    path = artifact_path(operation, "scope.json")
    if not path.is_file():
        raise ValueError("Native operation is missing its admitted scope.json")
    value = decode_json(path.read_bytes())
    reject_credentials(value)
    return validate_record("source-scope", value)


def _bind_receipt(payload: dict, scope: dict, ordinal: int | None) -> dict:
    receipt = validate_record("source-receipt", payload)
    if canonical_bytes(receipt["scope"]) != canonical_bytes(scope):
        raise ValueError("Source receipt scope differs from admitted operation")
    if receipt["operation_id"] != scope["operation_id"]:
        raise ValueError("Source receipt operation identity mismatch")
    if receipt["producer"]["owner"] != scope["owner"] or receipt["producer"]["profile"] != scope["profile"]:
        raise ValueError("Source receipt producer scope mismatch")
    continuation = receipt["continuation"]
    if continuation["scope_digest"] != record_digest(scope) or continuation["producer_digest"] != record_digest(receipt["producer"]):
        raise ValueError("Source continuation is not bound to this scope and producer")
    kind = "final-outcome" if ordinal is None else "page-commit"
    if receipt["kind"] != kind:
        raise ValueError("Source page descriptor is not a committed page")
    if ordinal is not None and receipt["page"]["ordinal"] != ordinal:
        raise ValueError("Source page ordinal mismatch")
    return receipt


def _bind_capture(payload: dict, scope: dict, ordinal: int, producer=None, raw_ref=None) -> dict:
    capture = validate_record("source-capture", payload)
    if producer is not None and capture["producer"] != producer:
        raise ValueError("Capture producer differs from committed receipt")
    if capture["producer"]["owner"] != scope["owner"] or capture["producer"]["profile"] != scope["profile"]:
        raise ValueError("Capture producer differs from admitted source identity")
    if raw_ref is not None and (capture["artifact"]["path"], capture["artifact"]["sha256"]) != (raw_ref["path"], raw_ref["sha256"]):
        raise ValueError("Capture raw artifact differs from committed descriptor")
    occurrence, query_ref = capture["occurrence"], scope["query_ref"] or {}
    if (
        occurrence["operation_id"] != scope["operation_id"]
        or occurrence["scope_id"] != scope["scope_id"]
        or occurrence["query_id"] != query_ref.get("query_id")
        or occurrence["query_revision"] != query_ref.get("revision")
        or occurrence["page_ordinal"] != ordinal
    ):
        raise ValueError("Capture occurrence differs from admitted scope/page lineage")
    return capture


def _retain_record(store, operation: Path, kind: str, data: bytes) -> dict:
    digest = hashlib.sha256(data).hexdigest()
    relative = f"records/{kind}/{digest}.json"
    atomic_write(artifact_path(store.root, relative), data, immutable=True)
    return {
        "kind": kind, "ref": {"path": relative, "sha256": digest},
        "artifact_root": operation.relative_to(store.root).as_posix(),
    }


def import_operation(store, operation_dir: Path | str) -> dict:
    """Publish committed pages immediately; final settlement is a separate receipt."""
    operation = Path(operation_dir).absolute()
    relative = operation.relative_to(store.root).as_posix()
    operation = artifact_path(store.root, relative)
    if operation.parent != store.root / "operations" or not operation.is_dir():
        raise ValueError("Source operation must live directly in this evidence store's operations directory")
    scope = _read_scope(operation)
    pages = operation / "pages"
    descriptors = sorted(
        (p / "receipt.json" for p in pages.iterdir()
         if p.is_dir() and _PAGE_DIRECTORY.fullmatch(p.name) and (p / "receipt.json").is_file()),
        key=lambda p: int(p.parent.name),
    ) if pages.exists() else []
    committed = {"page_refs": [], "capture_refs": [], "receipt_refs": [], "final_receipt_ref": None}
    entries = []
    previous_native = None
    for descriptor in descriptors:
        ordinal = int(descriptor.parent.name)
        native_ref = artifact_ref(operation, descriptor)
        data = descriptor.read_bytes()
        receipt = _bind_receipt(read_json(operation, native_ref), scope, ordinal)
        previous = receipt["page"]["previous_receipt_ref"]
        if (None if previous is None else (previous["path"], previous["sha256"])) != (
            None if previous_native is None else (previous_native["path"], previous_native["sha256"])
        ):
            raise ValueError("Committed source page chain is missing or incompatible")
        if ordinal != len(committed["page_refs"]):
            raise ValueError("Committed source page ordinal gap")
        validate_closure(operation, receipt)
        page_entries = []
        for capture_ref in receipt["page"]["capture_refs"]:
            payload = _bind_capture(read_json(operation, capture_ref), scope, ordinal,
                                    receipt["producer"], receipt["page"]["raw_ref"])
            validate_closure(operation, payload)
            retained = _retain_record(store, operation, "source-capture",
                                      artifact_path(operation, capture_ref["path"]).read_bytes())
            page_entries.append(retained)
            committed["capture_refs"].append(retained["ref"])
        retained_receipt = _retain_record(store, operation, "source-receipt", data)
        page_entries.append(retained_receipt)
        committed["page_refs"].append(retained_receipt["ref"])
        committed["receipt_refs"].append(retained_receipt["ref"])
        entries.extend(page_entries)
        store._publish_records(page_entries, operation_id=scope["operation_id"], scope_digest=record_digest(scope))
        previous_native = native_ref
    final_path = artifact_path(operation, "receipt.json")
    if final_path.is_file():
        native_ref = artifact_ref(operation, final_path)
        receipt = _bind_receipt(read_json(operation, native_ref), scope, None)
        validate_closure(operation, receipt)
        if receipt["durability"]["committed_pages"] != len(committed["page_refs"]) or receipt["durability"]["capture_count"] != len(committed["capture_refs"]):
            raise ValueError("Final source durability differs from committed descriptor prefix")
        retained = _retain_record(store, operation, "source-receipt", final_path.read_bytes())
        entries.append(retained)
        committed["receipt_refs"].append(retained["ref"])
        committed["final_receipt_ref"] = retained["ref"]
    committed["capture_refs"] = list({ref["sha256"]: ref for ref in committed["capture_refs"]}.values())
    manifest = {"schema_version": 1, "revision": 1, "records": entries,
                "operation_id": scope["operation_id"], "scope_digest": record_digest(scope),
                **{key: committed[key] for key in ("page_refs", "capture_refs", "receipt_refs")}}
    committed["manifest_ref"] = store._publish_manifest(manifest)
    return {"operation_id": scope["operation_id"], "scope": scope, **committed,
            "durability": {"evidence": "committed", "notes": "not-materialized", "index": "not-projected"}}
