"""Offline source page/final settlement, recovery and artifact-closure regressions."""

from __future__ import annotations

import json

import pytest

from hyperresearch.core.frontmatter import parse_frontmatter, render_note
from hyperresearch.core.x_evidence import EvidenceStore
from hyperresearch.models.x_evidence import canonical_bytes, record_digest

PRODUCER = {"product": "opencli", "version": "fixture", "runtime": "fixture", "extension_version": None,
            "owner": "fixture", "profile": "fixture"}
TIMESTAMP = "2026-10-10T00:00:00Z"


def scope():
    return {"schema_version": 1, "operation_id": "operation-fixture", "scope_id": "scope-fixture", "operation": "search",
            "plan_ref": None, "query_ref": {"query_id": "query-fixture", "revision": 1}, "owner": "fixture", "profile": "fixture",
            "allowed_hosts": ["x.com"], "product": "Latest", "expression": "fixture", "target": None,
            "started_at": TIMESTAMP, "deadline": "2026-10-10T00:03:00Z",
            "limits": {"max_pages": 2, "max_captures": 4, "max_requests": 4, "max_elapsed_s": 180, "max_context": 2}}


def write_json(path, value):
    import hashlib

    data = canonical_bytes(value)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)
    return {"path": path.name, "sha256": hashlib.sha256(data).hexdigest()}


def receipt(request, *, final=False, refs=None):
    frontier = {"page_ordinal": None if not refs else 0, "cursor": None, "last_post_id": None, "captured_at": None}
    return {"schema_version": 1, "kind": "final-outcome" if final else "page-commit", "receipt_id": "final" if final else "page-0",
            "operation_id": request["operation_id"], "scope": request, "producer": PRODUCER,
            "execution": {"state": "settled" if final else "running", "started_at": TIMESTAMP,
                          "settled_at": TIMESTAMP if final else None, "reason": None},
            "coverage": {"state": "partial", "interval_start": None, "interval_end": None, "boundary_proven": False, "reasons": ["fixture"]},
            "durability": {"state": "committed", "committed_pages": 1 if refs else 0, "capture_count": 1 if refs else 0},
            "counters": {"page_count": 1 if refs else 0, "capture_count": 1 if refs else 0, "request_count": 1,
                         "context_count": 0, "duplicate_count": 0}, "artifacts": refs or [], "frontier": frontier,
            "page": None, "stop_reason": "executor-error" if final else "page-committed", "errors": [],
            "continuation": {"state": "unavailable", "cursor": None, "scope_digest": record_digest(request),
                             "producer_digest": record_digest(PRODUCER), "frontier": frontier, "reason": None}}


def operation_fixture(store, *, final=False, zero=False):
    request = scope()
    operation = store.create_operation(request)
    capture_ref = None
    if not zero:
        raw = write_json(operation / "pages/000000/page.json", {"public": "safe returned data"})
        raw["path"] = "pages/000000/page.json"
        capture = {"schema_version": 1, "capture_id": "capture-fixture", "post_id": "123", "revision": 1,
                   "author": {"id": None, "handle": "fixture", "name": "fixture"},
                   "text": '<script>unsafe()</script> ![fetch](https://evil.test/image) {{ tool() }}',
                   "url": "https://x.com/fixture/status/123", "posted_at": None, "captured_at": TIMESTAMP,
                   "event_time": None, "role": "primary", "event_type": "original", "relationships": [],
                   "occurrence": {"operation_id": request["operation_id"], "scope_id": request["scope_id"],
                                  "query_id": "query-fixture", "query_revision": 1, "page_ordinal": 0,
                                  "timeline_event_id": None, "observed_at": TIMESTAMP}, "artifact": raw, "producer": PRODUCER}
        capture_ref = write_json(operation / "pages/000000/captures/capture-fixture.json", capture)
        capture_ref["path"] = "pages/000000/captures/capture-fixture.json"
        page = receipt(request, refs=[raw, capture_ref])
        page["page"] = {"ordinal": 0, "raw_ref": raw, "capture_refs": [capture_ref], "previous_receipt_ref": None}
        page_ref = write_json(operation / "pages/000000/receipt.json", page)
        page_ref["path"] = "pages/000000/receipt.json"
    if final:
        write_json(operation / "receipt.json", receipt(request, final=True, refs=[] if zero else [page_ref, capture_ref]))
    return operation, capture_ref


def test_incremental_commit_then_final_reconciles_without_duplicate_history(tmp_vault):
    store = EvidenceStore(tmp_vault.root)
    operation, _ = operation_fixture(store)
    first = store.import_operation(operation)
    assert len(first["capture_refs"]) == 1
    assert first["final_receipt_ref"] is None
    assert store.get_record(first["page_refs"][0])["execution"]["state"] == "running"
    operation_fixture(store, final=True)
    final = store.import_operation(operation)
    assert final["capture_refs"] == first["capture_refs"]
    assert final["final_receipt_ref"] is not None
    assert store.import_operation(operation)["capture_refs"] == first["capture_refs"]
    assert len(store.list_records("source-capture")) == 1
    assert len(store.list_records("source-receipt")) == 2


def test_zero_error_operation_is_durable_without_note_row(tmp_vault):
    store = EvidenceStore(tmp_vault.root)
    operation, _ = operation_fixture(store, final=True, zero=True)
    outcome = store.import_operation(operation)
    assert outcome["capture_refs"] == []
    assert store.get_record(outcome["final_receipt_ref"])["stop_reason"] == "executor-error"
    tmp_vault.auto_sync()
    assert tmp_vault.db.execute("SELECT COUNT(*) FROM x_receipts").fetchone()[0] == 1
    assert tmp_vault.db.execute("SELECT COUNT(*) FROM notes").fetchone()[0] == 0


def test_uncommitted_staging_and_scope_mismatch_are_not_ingested(tmp_vault):
    store = EvidenceStore(tmp_vault.root)
    operation, _ = operation_fixture(store)
    staged = operation / "pages/staging/receipt.json"
    write_json(staged, {"uncommitted": True})
    assert len(store.import_operation(operation)["page_refs"]) == 1
    page_path = operation / "pages/000000/receipt.json"
    value = json.loads(page_path.read_bytes())
    value["scope"]["expression"] = "different"
    write_json(page_path, value)
    with pytest.raises(ValueError, match="scope"):
        store.import_operation(operation)


def test_materialization_retry_preserves_human_note_and_distinct_index_durability(tmp_vault, monkeypatch):
    store = EvidenceStore(tmp_vault.root)
    operation, _ = operation_fixture(store)
    imported = store.import_operation(operation)
    capture_ref, receipt_ref = imported["capture_refs"][0], imported["page_refs"][0]
    from hyperresearch.core import sync

    original_sync = sync.execute_sync
    monkeypatch.setattr(sync, "execute_sync", lambda *args: (_ for _ in ()).throw(RuntimeError("index interrupted")))
    first = store.materialize_capture(capture_ref, receipt_ref)
    assert first["durability"]["note"] == "materialized"
    assert first["durability"]["index"] == "failed"
    note_path = tmp_vault.root / first["path"]
    meta, body = parse_frontmatter(note_path.read_text())
    meta.summary = "human summary"
    note_path.write_text(render_note(meta, body))
    monkeypatch.setattr(sync, "execute_sync", original_sync)
    second = store.materialize_capture(capture_ref, receipt_ref)
    assert second["note_id"] == first["note_id"]
    assert second["durability"]["index"] == "indexed"
    assert parse_frontmatter(note_path.read_text())[0].summary == "human summary"
    assert len(list(tmp_vault.notes_dir.glob("*.md"))) == 1
    assert "<script>" not in body and "![fetch]" not in body and "{{ tool() }}" not in body


def test_native_transport_keeps_exact_source_bytes_and_every_raw_descendant(tmp_vault, tmp_path):
    from hyperresearch.core.vault import Vault

    store = EvidenceStore(tmp_vault.root)
    operation, original = operation_fixture(store, final=True)
    imported = store.import_operation(operation)
    bundle = store.export_closure(imported["receipt_refs"])
    fresh = Vault.init(tmp_path / "fresh-native")
    restored = EvidenceStore(fresh.root)
    restored.import_closure(bundle)
    ref = imported["capture_refs"][0]
    assert restored.get_record(ref) == store.get_record(ref)
    native_path = operation.relative_to(store.root) / original["path"]
    assert (restored.root / native_path).read_bytes() == (store.root / native_path).read_bytes()
    fresh.auto_sync()
    assert fresh.db.execute("SELECT COUNT(*) FROM x_captures").fetchone()[0] == 1


def test_corrupt_native_capture_never_publishes_manifest(tmp_vault):
    store = EvidenceStore(tmp_vault.root)
    operation, ref = operation_fixture(store)
    (operation / ref["path"]).write_text("{}")
    with pytest.raises(ValueError, match="checksum"):
        store.import_operation(operation)
    assert store.list_records("source-capture") == []


def test_capture_occurrence_cannot_escape_admitted_scope(tmp_vault):
    store = EvidenceStore(tmp_vault.root)
    operation, capture_ref = operation_fixture(store)
    capture_path = operation / capture_ref["path"]
    capture = json.loads(capture_path.read_bytes())
    capture["occurrence"]["scope_id"] = "unrelated"
    replacement = write_json(capture_path, capture)
    replacement["path"] = capture_ref["path"]
    page_path = operation / "pages/000000/receipt.json"
    page = json.loads(page_path.read_bytes())
    page["page"]["capture_refs"] = [replacement]
    page["artifacts"] = [page["page"]["raw_ref"], replacement]
    write_json(page_path, page)
    with pytest.raises(ValueError, match="occurrence"):
        store.import_operation(operation)


def test_receipt_continuation_digest_cannot_invent_compatible_history(tmp_vault):
    store = EvidenceStore(tmp_vault.root)
    operation, _ = operation_fixture(store)
    page_path = operation / "pages/000000/receipt.json"
    page = json.loads(page_path.read_bytes())
    page["continuation"]["scope_digest"] = "a" * 64
    write_json(page_path, page)
    with pytest.raises(ValueError, match="continuation"):
        store.import_operation(operation)


def test_materialization_snapshot_remains_closed_after_live_note_deletion(tmp_vault):
    store = EvidenceStore(tmp_vault.root)
    operation, _ = operation_fixture(store, final=True)
    outcome = store.import_operation(operation)
    note = store.materialize_capture(outcome["capture_refs"][0], outcome["final_receipt_ref"])
    rendered = (tmp_vault.root / note["path"]).read_bytes()
    assert store.read_blob(note["note_ref"]) == rendered
    (tmp_vault.root / note["path"]).unlink()
    bundle = store.export_closure()
    manifests = [json.loads(__import__("base64").b64decode(artifact["content_base64"]))
                 for artifact in bundle["artifacts"] if artifact["ref"]["path"].startswith("manifests/")]
    assert any(manifest.get("materializations") for manifest in manifests)


def test_corrupt_note_snapshot_refuses_fresh_derived_projection(tmp_vault):
    store = EvidenceStore(tmp_vault.root)
    operation, _ = operation_fixture(store, final=True)
    outcome = store.import_operation(operation)
    note = store.materialize_capture(outcome["capture_refs"][0], outcome["final_receipt_ref"])
    connection = tmp_vault.db
    (store.root / note["note_ref"]["path"]).write_text("corrupt immutable snapshot", encoding="utf-8")
    projection = store.rebuild_projection(connection)
    assert projection["errors"]
    assert any("checksum" in item["error"].lower() for item in projection["errors"])
