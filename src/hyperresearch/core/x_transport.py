"""Offline JSON and Markdown-sidecar transport of complete evidence artifact closure."""

from __future__ import annotations

import base64
import hashlib
import tempfile
from pathlib import Path

from hyperresearch.core.x_artifacts import (
    artifact_path,
    atomic_write,
    decode_json,
    nested_refs,
    read_artifact,
    reject_credentials,
)
from hyperresearch.models.x_evidence import validate_record


def export_closure(store, refs: list[dict] | None) -> dict:
    entries = store._entries()
    selected, artifacts = {}, {}
    seen = set()

    def visit(ref, root):
        path = artifact_path(root, ref["path"])
        relative = path.relative_to(store.root).as_posix()
        data = read_artifact(root, ref)
        key = (relative, ref["sha256"])
        if key in seen:
            return
        seen.add(key)
        artifacts[relative] = {"ref": {"path": relative, "sha256": ref["sha256"]},
                               "content_base64": base64.b64encode(data).decode("ascii")}
        entry = entries.get(key)
        if entry is None:
            entry = next((item for item in entries.values()
                          if item["ref"]["sha256"] == ref["sha256"]), None)
        if entry:
            selected[(entry["ref"]["path"], entry["ref"]["sha256"])] = entry
            if entry["ref"]["path"] != relative:
                visit(entry["ref"], store.root)
        if relative.endswith(".json"):
            value = decode_json(data)
            reject_credentials(value)
            context = store._record_context(entry) if entry else root
            for child in nested_refs(value):
                visit(child, context)

    requested = refs if refs is not None else [entry["ref"] for entry in entries.values()]
    for ref in requested:
        store.get_record(ref)
        visit(ref, store.root)
    for entry in list(selected.values()):
        if entry.get("artifact_root"):
            context = store._record_context(entry)
            scope_path = artifact_path(context, "scope.json")
            if scope_path.exists():
                data = scope_path.read_bytes()
                validate_record("source-scope", decode_json(data))
                visit({"path": "scope.json", "sha256": hashlib.sha256(data).hexdigest()}, context)
    originals = list(store._manifests())
    manifest_refs = {}
    covered = set()
    chosen = list(originals) if refs is None else []
    while chosen or any(identity not in covered for identity in selected):
        if chosen:
            manifest_ref, manifest = chosen.pop(0)
        else:
            identity = next(identity for identity in selected if identity not in covered)
            candidates = [(ref, manifest) for ref, manifest in originals
                          if any((item["ref"]["path"], item["ref"]["sha256"]) == identity
                                 for item in manifest["records"])]
            if not candidates:
                raise ValueError("Evidence record has no canonical manifest to transport")
            manifest_ref, manifest = min(candidates, key=lambda candidate: (len(candidate[1]["records"]), candidate[0]["path"]))
        if manifest_ref["path"] in manifest_refs:
            continue
        manifest_refs[manifest_ref["path"]] = manifest_ref
        covered.update((item["ref"]["path"], item["ref"]["sha256"]) for item in manifest["records"])
        visit(manifest_ref, store.root)
        roots = {entry["artifact_root"] for entry in manifest["records"] if entry.get("artifact_root")}
        if manifest.get("scope_digest") and manifest.get("operation_id") and not roots:
            roots.add(f"operations/{hashlib.sha256(manifest['operation_id'].encode()).hexdigest()}")
        for relative_root in roots:
            context = artifact_path(store.root, relative_root)
            scope_path = artifact_path(context, "scope.json")
            if not scope_path.is_file():
                raise ValueError("Missing native operation scope in transport closure")
            scope_bytes = scope_path.read_bytes()
            visit({"path": "scope.json", "sha256": hashlib.sha256(scope_bytes).hexdigest()}, context)
    return validate_record("evidence-transport", {
        "schema_version": 1, "artifacts": list(artifacts.values()), "manifests": list(manifest_refs.values()),
    })


def import_closure(store, bundle: dict) -> list[dict]:
    """Validate the entire closure before making any new manifest visible."""
    value = validate_record("evidence-transport", bundle)
    decoded = {}
    for artifact in value["artifacts"]:
        ref = artifact["ref"]
        artifact_path(store.root, ref["path"])
        try:
            data = base64.b64decode(artifact["content_base64"], validate=True)
        except ValueError as exc:
            raise ValueError("Invalid transport artifact encoding") from exc
        if hashlib.sha256(data).hexdigest() != ref["sha256"]:
            raise ValueError(f"Transport checksum mismatch: {ref['path']}")
        if ref["path"] in decoded and decoded[ref["path"]] != data:
            raise ValueError("Conflicting transport artifacts")
        reject_credentials(decode_json(data) if ref["path"].endswith(".json") else data.decode("utf-8"))
        decoded[ref["path"]] = data
    with tempfile.TemporaryDirectory(prefix=".incoming-", dir=store.root) as temporary:
        staging = Path(temporary)
        for relative, data in decoded.items():
            atomic_write(artifact_path(staging, relative), data, immutable=True)
        proxy = object.__new__(type(store))
        proxy.vault, proxy.root = store.vault, staging
        entries = proxy._entries()
        for ref in value["manifests"]:
            manifest = validate_record("evidence-manifest", decode_json(read_artifact(staging, ref)))
            if artifact_path(staging, ref["path"]).parent != staging / "manifests":
                raise ValueError("Transport manifest outside canonical manifest directory")
            for entry in manifest["records"]:
                proxy.get_record(entry["ref"], entry["kind"])
            proxy._walk_closure(manifest, staging, entries, set())
        # Collision checks happen before publication, including native raw paths.
        for relative, data in decoded.items():
            target = artifact_path(store.root, relative)
            if target.exists() and target.read_bytes() != data:
                raise ValueError(f"Evidence transport collides with retained artifact: {relative}")
        manifest_paths = {ref["path"] for ref in value["manifests"]}
        if any(relative.startswith("manifests/") and relative not in manifest_paths for relative in decoded):
            raise ValueError("Transport contains an undeclared manifest")
        for relative, data in decoded.items():
            if relative not in manifest_paths:
                atomic_write(artifact_path(store.root, relative), data, immutable=True)
        for ref in value["manifests"]:
            atomic_write(artifact_path(store.root, ref["path"]), decoded[ref["path"]], immutable=True)
    return [entry["ref"] for entry in entries.values()]
