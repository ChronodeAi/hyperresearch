"""X references traverse existing CLI/search/HTML/transport surfaces without live calls."""

from __future__ import annotations

import json

import pytest
from typer.testing import CliRunner

from hyperresearch.cli import app
from hyperresearch.core.frontmatter import parse_frontmatter
from hyperresearch.core.vault import Vault
from hyperresearch.core.x_evidence import EvidenceStore
from hyperresearch.core.x_artifacts import atomic_write, nested_refs
from hyperresearch.models.x_evidence import RECORD_KINDS, canonical_bytes
from tests.test_core.test_x_operations import operation_fixture
from tests.x_fixtures import SCHEMA_ROOT, governed_fixture_path

runner = CliRunner()


def downstream_fixture_closure(store):
    """Import real offline governed records and their exact, checksummed original bytes."""
    import base64
    import hashlib

    root = SCHEMA_ROOT / "fixtures"
    targets = {
        "annotation_refs": governed_fixture_path("analysis-annotation", "deferred-missing-context").relative_to(root).as_posix(),
        "observation_refs": governed_fixture_path("verified-observation", "unverified-provider-fdv").relative_to(root).as_posix(),
        "analytics_refs": governed_fixture_path("analytics-event", "crypto-lead-needs-verification").relative_to(root).as_posix(),
    }
    artifacts, records = {}, []

    def visit(relative):
        if relative in artifacts:
            return artifacts[relative]["ref"]
        raw = (root / relative).read_bytes()
        ref = {"path": relative, "sha256": hashlib.sha256(raw).hexdigest()}
        artifacts[relative] = {"ref": ref, "content_base64": base64.b64encode(raw).decode("ascii")}
        payload = json.loads(raw)
        kind = relative.split("/", 1)[0]
        if kind in RECORD_KINDS:
            records.append({"kind": kind, "ref": ref})
        for child in nested_refs(payload):
            delivered = visit(child["path"])
            assert delivered["sha256"] == child["sha256"]
        return ref

    selected = {field: [visit(relative)] for field, relative in targets.items()}
    manifest = canonical_bytes({"schema_version": 1, "revision": 1, "records": records})
    digest = hashlib.sha256(manifest).hexdigest()
    ref = {"path": f"manifests/{digest}.json", "sha256": digest}
    store.import_closure({
        "schema_version": 1,
        "artifacts": [*artifacts.values(), {"ref": ref, "content_base64": base64.b64encode(manifest).decode("ascii")}],
        "manifests": [ref],
    })
    return selected


def seeded_x(vault):
    store = EvidenceStore(vault.root)
    operation, _ = operation_fixture(store, final=True)
    imported = store.import_operation(operation)
    note = store.materialize_capture(imported["capture_refs"][0], imported["final_receipt_ref"])
    assert not note["errors"]
    from hyperresearch.core.note import read_note
    from hyperresearch.core.frontmatter import render_note
    from hyperresearch.core.sync import compute_sync_plan, execute_sync

    path = vault.root / note["path"]
    persisted = read_note(path, vault.root)
    persisted.meta.x_evidence.update(downstream_fixture_closure(store))
    atomic_write(path, render_note(persisted.meta, persisted.body).encode("utf-8"))
    assert execute_sync(vault, compute_sync_plan(vault)).errors == []
    note["x_evidence"] = persisted.meta.x_evidence
    return store, note


def envelope(result):
    assert result.exit_code == 0, result.output
    return json.loads(result.output)["data"]


def test_note_batch_promotion_move_search_and_html_preserve_bindings(tmp_vault, monkeypatch):
    store, note = seeded_x(tmp_vault)
    monkeypatch.chdir(tmp_vault.root)
    shown = envelope(runner.invoke(app, ["note", "show", note["note_id"], "--json"]))
    assert shown["x_evidence"] == note["x_evidence"]
    envelope(runner.invoke(app, ["note", "update", note["note_id"], "--status", "review", "--json"]))
    envelope(runner.invoke(app, ["batch", "tag-add", "curated", "--json"]))
    envelope(runner.invoke(app, ["note", "mv", note["note_id"], "research/temp/moved.md", "--json"]))
    results = envelope(runner.invoke(app, ["search", "--x-capture", note["x_evidence"]["capture_refs"][0]["path"], "--json"]))
    assert results["results"][0]["x_evidence"] == note["x_evidence"]
    assert results["results"][0]["fetch_provider"] == "opencli"
    moved = parse_frontmatter((tmp_vault.root / "research/temp/moved.md").read_text())[0]
    assert moved.x_evidence == note["x_evidence"]
    from hyperresearch.serve.renderer import render_markdown

    html = render_markdown('<script>run()</script> ![remote](https://evil.test/img)', inert=True)
    assert "<script>" not in html and "<img" not in html
    assert "&lt;script&gt;" in html


@pytest.mark.parametrize("transport", ["json", "markdown"])
def test_transport_roundtrip_and_genuinely_fresh_cache(tmp_vault, tmp_path, monkeypatch, transport):
    store, note = seeded_x(tmp_vault)
    monkeypatch.chdir(tmp_vault.root)
    if transport == "json":
        source = tmp_path / "vault.json"
        result = runner.invoke(app, ["export", "json", "--output", str(source)])
    else:
        source = tmp_path / "markdown"
        result = runner.invoke(app, ["export", "vault", str(source)])
    assert result.exit_code == 0, result.output
    fresh = Vault.init(tmp_path / f"fresh-{transport}")
    monkeypatch.chdir(fresh.root)
    imported = runner.invoke(app, ["import", str(source), "--json"])
    assert imported.exit_code == 0, imported.output
    fresh.close()
    fresh.db_path.unlink()
    restored = Vault(fresh.root)
    restored.auto_sync()
    shown = envelope(runner.invoke(app, ["note", "show", note["note_id"], "--json"]))
    assert shown["x_evidence"] == note["x_evidence"]
    assert EvidenceStore(restored.root).get_record(note["x_evidence"]["capture_refs"][0]) == store.get_record(note["x_evidence"]["capture_refs"][0])
    assert restored.db.execute("SELECT COUNT(*) FROM x_receipts").fetchone()[0] == tmp_vault.db.execute("SELECT COUNT(*) FROM x_receipts").fetchone()[0]
    for field in ("capture_refs", "receipt_refs", "annotation_refs", "observation_refs", "analytics_refs"):
        assert shown["x_evidence"][field]
        for ref in shown["x_evidence"][field]:
            assert EvidenceStore(restored.root).get_record(ref) == store.get_record(ref)


def test_delete_note_keeps_shared_canonical_evidence(tmp_vault, monkeypatch):
    store, note = seeded_x(tmp_vault)
    monkeypatch.chdir(tmp_vault.root)
    deleted = runner.invoke(app, ["note", "rm", note["note_id"], "--force", "--json"])
    assert deleted.exit_code == 0, deleted.output
    assert store.get_record(note["x_evidence"]["capture_refs"][0])["post_id"] == "123"
    tmp_vault.auto_sync()
    assert tmp_vault.db.execute("SELECT COUNT(*) FROM x_captures").fetchone()[0] >= 1


def test_x_escalation_unreceipted_reader_content_is_explicit_refusal(tmp_vault, tmp_path, monkeypatch):
    from hyperresearch.core.escalation import claim_next, enqueue

    item_id = enqueue(tmp_vault.db, "https://x.com/u/status/123", "interactive_needed")
    claim_next(tmp_vault.db, "fixture")
    body = tmp_path / "reader.txt"
    body.write_text("anonymous extracted reader text")
    monkeypatch.chdir(tmp_vault.root)
    result = runner.invoke(app, ["escalation", "ingest", str(item_id), "--title", "anonymous", "--body-file", str(body), "--json"])
    assert result.exit_code != 0
    assert json.loads(result.output)["error_code"] == "X_SOURCE_REFUSED"
    assert tmp_vault.db.execute("SELECT status FROM escalations WHERE id=?", (item_id,)).fetchone()[0] == "queued"


def test_mcp_read_search_update_preserve_references(tmp_vault, monkeypatch):
    from hyperresearch.mcp import server as mcp

    _, note = seeded_x(tmp_vault)
    monkeypatch.setattr(mcp, "_vault", tmp_vault)
    assert json.loads(mcp.read_note(note["note_id"]))["x_evidence"] == note["x_evidence"]
    assert json.loads(mcp.read_many(note["note_id"]))["notes"][0]["x_evidence"] == note["x_evidence"]
    mcp.update_note(note["note_id"], status="review", summary="curated")
    assert json.loads(mcp.search_notes(x_capture=note["x_evidence"]["capture_refs"][0]["path"]))[0]["x_evidence"] == note["x_evidence"]


def test_native_note_update_index_failure_reports_durable_refs(tmp_vault, monkeypatch):
    from types import SimpleNamespace
    import hyperresearch.core.sync as sync

    _, note = seeded_x(tmp_vault)
    monkeypatch.chdir(tmp_vault.root)
    monkeypatch.setattr(sync, "execute_sync", lambda *args: SimpleNamespace(
        errors=[{"path": note["path"], "error": "offline index interruption"}],
    ))
    result = runner.invoke(app, ["note", "update", note["note_id"], "--summary", "Retained evidence", "--json"])
    assert result.exit_code == 1
    failure = json.loads(result.output)
    assert failure["error_code"] == "INDEX_PROJECTION_FAILED"
    assert failure["data"]["x_evidence"] == note["x_evidence"]
    meta, _ = parse_frontmatter((tmp_vault.root / note["path"]).read_text())
    assert meta.summary == "Retained evidence"
    assert meta.x_evidence == note["x_evidence"]
