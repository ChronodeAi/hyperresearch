"""Recoverable X note publication with note and index durability kept independent."""

from __future__ import annotations

from urllib.parse import urlsplit

from yaml import YAMLError

from hyperresearch.core.frontmatter import render_note
from hyperresearch.core.note import read_note
from hyperresearch.core.x_artifacts import atomic_write
from hyperresearch.core.x_projection import inert_markdown, unknown_evidence
from hyperresearch.models.note import NoteMeta


def _find_capture_note(store, capture_ref):
    for directory in (store.vault.notes_dir, store.vault.temp_dir):
        for path in directory.rglob("*.md") if directory.exists() else []:
            if path.is_symlink():
                continue
            try:
                note = read_note(path, store.vault.root)
            except (ValueError, OSError, YAMLError):
                # Sync reports these per-file errors; an unrelated note cannot hide a capture.
                continue
            identity = (capture_ref["path"], capture_ref["sha256"])
            if any((ref["path"], ref["sha256"]) == identity for ref in (note.meta.x_evidence or {}).get("capture_refs", [])):
                return path, note
    return None, None


def materialize_capture(store, capture_ref, receipt_ref=None) -> dict:
    capture = store.get_record(capture_ref, "source-capture")
    if receipt_ref is not None:
        receipt = store.get_record(receipt_ref, "source-receipt")
        if receipt["producer"] != capture["producer"]:
            raise ValueError("Note receipt producer differs from capture producer")
        closure = store.resolve_closure([receipt_ref])
        bound = any(item["kind"] == "source-capture" and item["ref"]["sha256"] == capture_ref["sha256"] for item in closure)
        if not bound:
            raise ValueError("Note receipt does not cover this capture")
    path, note = _find_capture_note(store, capture_ref)
    if note is None:
        identifier = f"x-{capture['post_id']}-{capture_ref['sha256'][:16]}"
        path = store.vault.notes_dir / f"{identifier}.md"
        if path.exists():
            raise ValueError("Deterministic X note path is owned by another note")
        refs = unknown_evidence()
        refs["capture_refs"] = [capture_ref]
        refs["producer"] = capture["producer"]
        meta = NoteMeta(
            title=f"X post {capture['post_id']}", id=identifier, source=capture["url"],
            source_domain=urlsplit(capture["url"]).hostname, fetched_at=capture["captured_at"],
            fetch_provider=capture["producer"]["product"], fetch_route="opencli",
            x_evidence=refs, tags=["x-source"], content_type="forum", tier="unknown",
        )
        body = inert_markdown(capture["text"])
    else:
        meta, body = note.meta, note.body
    if receipt_ref is not None and receipt_ref not in meta.x_evidence["receipt_refs"]:
        meta.x_evidence["receipt_refs"].append(receipt_ref)
        meta.x_evidence["receipt_state"] = "recorded"
    for ref in store.list_records("analysis-annotation"):
        annotation = store.get_record(ref, "analysis-annotation")
        if annotation["capture_ref"] == capture_ref and ref not in meta.x_evidence["annotation_refs"]:
            meta.x_evidence["annotation_refs"].append(ref)
    for ref in store.list_records("analytics-event"):
        event = store.get_record(ref, "analytics-event")
        if capture_ref not in event["input_refs"]["capture_refs"]:
            continue
        if ref not in meta.x_evidence["analytics_refs"]:
            meta.x_evidence["analytics_refs"].append(ref)
        for observation_ref in event["input_refs"]["observation_refs"]:
            if observation_ref not in meta.x_evidence["observation_refs"]:
                meta.x_evidence["observation_refs"].append(observation_ref)
    store.validate_note_refs(meta.x_evidence)
    data = render_note(meta, body).encode("utf-8")
    note_ref = store.put_blob(data, suffix=".txt")
    atomic_write(path, data)
    relative = path.relative_to(store.vault.root).as_posix()
    projection = {"capture_ref": capture_ref, "receipt_ref": receipt_ref, "note_ref": note_ref,
                  "state": "materialized", "index_state": "pending"}
    store._publish_manifest({"schema_version": 1, "revision": 1, "records": [], "materializations": [projection]})
    from hyperresearch.core.sync import compute_sync_plan, execute_sync

    try:
        result = execute_sync(store.vault, compute_sync_plan(store.vault))
        errors = result.errors
        row = store.vault.db.execute("SELECT path,content_hash FROM notes WHERE id=?", (meta.id,)).fetchone()
        indexed = row is not None and row["path"] == relative and row["content_hash"] == note_ref["sha256"]
        projection["index_state"] = "indexed" if indexed else "failed"
        if not indexed and not any(error.get("path") == relative for error in errors):
            errors.append({"path": relative, "error": "Durable note was not projected into the index"})
    except Exception as exc:
        errors = [{"path": relative, "error": str(exc)}]
        projection["index_state"] = "failed"
    store._publish_manifest({"schema_version": 1, "revision": 1, "records": [], "materializations": [projection]})
    return {"note_id": meta.id, "path": relative, "sha256": note_ref["sha256"], "note_ref": note_ref,
            "x_evidence": meta.x_evidence, "durability": {"evidence": "committed", "note": "materialized", "index": projection["index_state"]},
            "errors": errors}
