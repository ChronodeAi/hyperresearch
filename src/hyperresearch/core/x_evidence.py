"""One canonical X evidence store; SQLite and notes are rebuildable projections."""

from __future__ import annotations

import hashlib
from pathlib import Path

from hyperresearch.core.x_artifacts import (
    artifact_path,
    atomic_write,
    decode_json,
    nested_refs,
    publish_manifest,
    read_artifact,
    read_json,
    reject_credentials,
)
from hyperresearch.models.x_evidence import RECORD_KINDS, canonical_bytes, validate_record


class EvidenceStore:
    """Persist immutable, validated records under configured research/evidence/x."""

    def __init__(self, vault_root: Path | str):
        from hyperresearch.core.vault import Vault

        self.vault = Vault(Path(vault_root))
        self.root = self.vault.research_dir / "evidence" / "x"
        self.root.relative_to(self.vault.root)
        for parent in (self.root, *self.root.parents):
            if parent == self.vault.root:
                break
            if parent.is_symlink():
                raise ValueError("Evidence root must not traverse a symlink")
        self.root.resolve().relative_to(self.vault.root)
        self.root = self.root.resolve()
        self.root.mkdir(parents=True, exist_ok=True)

    def put_blob(self, data: bytes, *, suffix: str = ".json", category: str = "support") -> dict:
        """Retain safe public response bytes; never acquire or transform them."""
        if suffix not in {".json", ".txt"}:
            raise ValueError("Only safe public JSON/text evidence artifacts are supported")
        if category not in {"support", "source"}:
            raise ValueError("Unsupported evidence blob category")
        text = data.decode("utf-8")
        reject_credentials(decode_json(text) if suffix == ".json" else text)
        digest = hashlib.sha256(data).hexdigest()
        relative = f"artifacts/{category}/{digest}{suffix}"
        atomic_write(artifact_path(self.root, relative), data, immutable=True)
        return {"path": relative, "sha256": digest}

    def read_blob(self, ref: dict) -> bytes:
        data = read_artifact(self.root, ref)
        reject_credentials(decode_json(data) if ref["path"].endswith(".json") else data.decode("utf-8"))
        return data

    def ref_from_path(self, path: str | Path) -> dict:
        """Checksum an existing safe canonical store path, independent of caller CWD."""
        candidate = Path(path)
        if candidate.is_absolute():
            relative = candidate.relative_to(self.root).as_posix()
        else:
            prefix = self.root.relative_to(self.vault.root)
            relative = candidate.relative_to(prefix).as_posix() if candidate.is_relative_to(prefix) else candidate.as_posix()
        target = artifact_path(self.root, relative)
        if not target.is_file():
            raise ValueError("Canonical evidence artifact is missing")
        return {"path": relative, "sha256": hashlib.sha256(target.read_bytes()).hexdigest()}

    def put_record(self, kind: str, payload: dict) -> dict:
        if kind not in RECORD_KINDS:
            raise ValueError(f"Not a canonical evidence record kind: {kind}")
        reject_credentials(payload)
        value = self._validated_payload({"kind": kind}, payload)
        self._walk_closure(value, self.root, self._entries(), set())
        data = canonical_bytes(value)
        digest = hashlib.sha256(data).hexdigest()
        ref = {"path": f"records/{kind}/{digest}.json", "sha256": digest}
        atomic_write(artifact_path(self.root, ref["path"]), data, immutable=True)
        self._publish_records([{"kind": kind, "ref": ref}])
        return ref

    def _publish_manifest(self, manifest: dict) -> dict:
        return publish_manifest(self.root, manifest)

    def _publish_records(self, entries: list[dict], **fields) -> dict:
        return self._publish_manifest({"schema_version": 1, "revision": 1, "records": entries, **fields})

    def _manifests(self, *, errors: list | None = None):
        directory = self.root / "manifests"
        for path in sorted(directory.glob("*.json")) if directory.exists() else []:
            relative = path.relative_to(self.root).as_posix()
            ref = {"path": relative, "sha256": path.stem}
            try:
                payload = validate_record("evidence-manifest", read_json(self.root, ref))
            except (ValueError, OSError) as exc:
                if errors is None:
                    raise ValueError(f"Invalid evidence manifest {relative}: {exc}") from exc
                errors.append({"path": relative, "error": str(exc)})
                continue
            yield ref, payload

    def _entries(self, *, errors: list | None = None) -> dict:
        entries = {}
        for manifest_ref, manifest in self._manifests(errors=errors):
            try:
                if manifest.get("scope_digest") and manifest.get("operation_id"):
                    from hyperresearch.core.x_operations import _read_scope

                    roots = {entry["artifact_root"] for entry in manifest["records"] if entry.get("artifact_root")}
                    if not roots:
                        roots.add(f"operations/{hashlib.sha256(manifest['operation_id'].encode()).hexdigest()}")
                    for relative in roots:
                        scope = _read_scope(artifact_path(self.root, relative))
                        if scope["operation_id"] != manifest["operation_id"] or hashlib.sha256(canonical_bytes(scope)).hexdigest() != manifest["scope_digest"]:
                            raise ValueError("Canonical manifest operation scope digest mismatch")
            except (ValueError, OSError) as exc:
                if errors is None:
                    raise ValueError(f"Invalid scoped manifest {manifest_ref['path']}: {exc}") from exc
                errors.append({"path": manifest_ref["path"], "error": str(exc)})
                continue
            for entry in manifest["records"]:
                key = (entry["ref"]["path"], entry["ref"]["sha256"])
                if key in entries and entries[key] != entry:
                    if errors is None:
                        raise ValueError("Conflicting evidence artifact roots or kinds")
                    errors.append({"path": manifest_ref["path"], "error": "Conflicting evidence artifact roots or kinds"})
                    continue
                entries[key] = entry
        return entries

    def _record_context(self, entry: dict) -> Path:
        return artifact_path(self.root, entry["artifact_root"]) if entry.get("artifact_root") else self.root

    def _validated_payload(self, entry: dict, payload: dict) -> dict:
        value = validate_record(entry["kind"], payload)
        context = self._record_context(entry)
        if entry["kind"] in {"source-capture", "source-receipt"}:
            from hyperresearch.core.x_operations import _bind_capture, _bind_receipt, _read_scope

            scope = _read_scope(context) if entry.get("artifact_root") else value.get("scope")
            if entry["kind"] == "source-capture" and scope is not None:
                _bind_capture(value, scope, value["occurrence"]["page_ordinal"])
            elif entry["kind"] == "source-receipt":
                page = value["page"]
                _bind_receipt(value, scope, page["ordinal"] if page is not None else None)
                if page is not None:
                    for ref in page["capture_refs"]:
                        _bind_capture(read_json(context, ref), scope, page["ordinal"], value["producer"], page["raw_ref"])
        return value

    def resolve_ref(self, ref: dict, *, origin_ref: dict | None = None) -> dict:
        """Resolve a source-owned nested ref without modifying the canonical payload."""
        entries = self._entries()
        root = self.root
        if origin_ref is not None:
            self.get_record(origin_ref)
            root = self._record_context(entries[(origin_ref["path"], origin_ref["sha256"])])
        read_artifact(root, ref)
        relative = artifact_path(root, ref["path"]).relative_to(self.root).as_posix()
        identity = (relative, ref["sha256"])
        entry = entries.get(identity) or next(
            (item for item in entries.values() if item["ref"]["sha256"] == ref["sha256"]), None,
        )
        return {**ref, **entry["ref"]} if entry else {**ref, "path": relative}

    def _walk_closure(self, value, root: Path, entries: dict, seen: set) -> None:
        for ref in nested_refs(value):
            data = read_artifact(root, ref)
            relative = artifact_path(root, ref["path"]).relative_to(self.root).as_posix()
            identity = (relative, ref["sha256"])
            if identity in seen:
                continue
            seen.add(identity)
            if not relative.endswith(".json"):
                reject_credentials(data.decode("utf-8"))
                continue
            child = decode_json(data)
            reject_credentials(child)
            entry = entries.get(identity) or next(
                (item for item in entries.values() if item["ref"]["sha256"] == ref["sha256"]), None,
            )
            if entry:
                child = self._validated_payload(entry, child)
            self._walk_closure(child, self._record_context(entry) if entry else root, entries, seen)

    def get_record(self, ref: dict, expected_kind: str | None = None) -> dict:
        entries = self._entries()
        entry = entries.get((ref.get("path"), ref.get("sha256")))
        if entry is None:
            raise ValueError("Evidence record has no atomically published manifest")
        if expected_kind is not None and entry["kind"] != expected_kind:
            raise ValueError(f"Evidence kind mismatch: expected {expected_kind}, got {entry['kind']}")
        value = self._validated_payload(entry, read_json(self.root, ref))
        self._walk_closure(value, self._record_context(entry), entries, set())
        return value

    def list_records(self, kind: str) -> list[dict]:
        if kind not in RECORD_KINDS:
            raise ValueError(f"Not a canonical evidence record kind: {kind}")
        refs = [entry["ref"] for entry in self._entries().values() if entry["kind"] == kind]
        for ref in refs:
            self.get_record(ref, kind)
        return sorted(refs, key=lambda ref: ref["path"])

    def resolve_closure(self, refs: list[dict]) -> list[dict]:
        """Return only explicitly frozen records and declared record descendants."""
        entries, result, seen = self._entries(), {}, set()

        def visit(ref, root):
            relative = artifact_path(root, ref["path"]).relative_to(self.root).as_posix()
            identity = (relative, ref["sha256"])
            if identity in seen:
                return
            seen.add(identity)
            read_artifact(root, ref)
            entry = entries.get(identity) or next(
                (item for item in entries.values() if item["ref"]["sha256"] == ref["sha256"]), None,
            )
            if entry is None:
                return
            canonical_identity = (entry["ref"]["path"], entry["ref"]["sha256"])
            if canonical_identity in result:
                return
            value = self.get_record(entry["ref"], entry["kind"])
            result[canonical_identity] = {"kind": entry["kind"], "ref": {**ref, **entry["ref"]}, "payload": value}
            for child in nested_refs(value):
                visit(child, self._record_context(entry))

        for ref in refs:
            self.get_record(ref)
            visit(ref, self.root)
        return list(result.values())

    def create_operation(self, scope: dict) -> Path:
        value = validate_record("source-scope", scope)
        reject_credentials(value)
        operation = artifact_path(self.root, f"operations/{hashlib.sha256(value['operation_id'].encode()).hexdigest()}")
        atomic_write(operation / "scope.json", canonical_bytes(value), immutable=True)
        return operation

    def import_operation(self, operation_dir: Path | str) -> dict:
        from hyperresearch.core.x_operations import import_operation

        return import_operation(self, operation_dir)

    def materialize_capture(self, capture_ref: dict, receipt_ref: dict | None = None) -> dict:
        from hyperresearch.core.x_materialization import materialize_capture

        return materialize_capture(self, capture_ref, receipt_ref)

    def validate_note_refs(self, value: dict | None) -> None:
        from hyperresearch.core.x_projection import REFERENCE_FIELDS

        if value is None:
            return
        value = validate_record("note-evidence-refs", value)
        kinds = ("source-capture", "source-receipt", "analysis-annotation", "verified-observation", "analytics-event")
        first_source = None
        for field, kind in zip(REFERENCE_FIELDS, kinds, strict=True):
            for ref in value[field]:
                payload = self.get_record(ref, kind)
                if first_source is None and kind in {"source-capture", "source-receipt"}:
                    first_source = payload
        if first_source is not None and value["producer"] != first_source["producer"]:
            raise ValueError("Note producer is not the actual referenced source producer")
        if value["receipt_refs"] and value["capture_refs"]:
            bound = {item["ref"]["sha256"] for item in self.resolve_closure(value["receipt_refs"])
                     if item["kind"] == "source-capture"}
            if any(ref["sha256"] not in bound for ref in value["capture_refs"]):
                raise ValueError("Note capture is not bound to the referenced source receipts")

    def rebuild_projection(self, conn) -> dict:
        """Reconstruct cache history from committed manifests, including zero-note operations."""
        rows, errors = [], []
        entries = self._entries(errors=errors)
        if errors:
            return {"records": 0, "errors": errors}
        for manifest_ref, manifest in self._manifests():
            try:
                self._walk_closure(manifest, self.root, entries, set())
            except (ValueError, OSError) as exc:
                errors.append({"path": manifest_ref["path"], "error": str(exc)})
        for entry in entries.values():
            try:
                payload = self.get_record(entry["ref"], entry["kind"])
                rows.append((entry["ref"]["path"], entry["ref"]["sha256"], entry["kind"],
                             entry.get("artifact_root"), canonical_bytes(payload).decode()))
            except (ValueError, OSError) as exc:
                errors.append({"path": entry["ref"]["path"], "error": str(exc)})
        if errors:
            return {"records": 0, "errors": errors}
        conn.execute("DELETE FROM x_records")
        conn.executemany("INSERT INTO x_records(path,sha256,kind,artifact_root,payload) VALUES (?,?,?,?,?)", rows)
        return {"records": len(rows), "errors": []}

    def export_closure(self, refs: list[dict] | None = None) -> dict:
        from hyperresearch.core.x_transport import export_closure

        return export_closure(self, refs)

    def import_closure(self, bundle: dict) -> list[dict]:
        from hyperresearch.core.x_transport import import_closure

        return import_closure(self, bundle)

    def export_artifacts(self, path: Path, refs: list[dict] | None = None) -> None:
        atomic_write(Path(path), canonical_bytes(self.export_closure(refs)))

    def import_artifacts(self, path: Path) -> list[dict]:
        return self.import_closure(decode_json(Path(path).read_bytes()))
