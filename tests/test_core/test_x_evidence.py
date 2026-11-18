"""Behavioral coverage for canonical X persistence, closure and fresh projections."""

from __future__ import annotations

import copy
import json
from pathlib import Path

import pytest
from pydantic import ValidationError

from hyperresearch.core.frontmatter import parse_frontmatter, render_note
from hyperresearch.core.note import read_note, write_note
from hyperresearch.core.sync import compute_sync_plan, execute_sync
from hyperresearch.models.note import NoteMeta


PRODUCER = {
    "product": "opencli", "version": "fixture", "runtime": "fixture-runtime",
    "extension_version": None, "owner": "fixture-owner", "profile": "fixture-profile",
}


def reference_set():
    return {
        "schema_version": 1,
        "capture_refs": [{"path": "records/source-capture/a.json", "sha256": "a" * 64}],
        "receipt_refs": [], "annotation_refs": [], "observation_refs": [],
        "analytics_refs": [], "producer": PRODUCER, "receipt_state": "unknown",
    }


def test_declared_reference_fields_survive_frontmatter_before_extra_ignore():
    refs = reference_set()
    meta = NoteMeta(title="public post", x_evidence=refs, fetch_route="builtin")
    restored, body = parse_frontmatter(render_note(meta, "literal body"))
    assert restored.x_evidence == refs
    assert restored.fetch_route == "builtin"
    assert body.strip() == "literal body"


@pytest.mark.parametrize("path", ["../secret", "/etc/passwd", "a/../../secret", "a\\secret"])
def test_note_reference_paths_fail_closed(path):
    refs = reference_set()
    refs["capture_refs"][0]["path"] = path
    with pytest.raises((ValidationError, ValueError)):
        NoteMeta(title="unsafe", x_evidence=refs)


def test_unknown_note_reference_field_is_not_silently_ignored():
    refs = reference_set()
    refs["cookie"] = "credential"
    with pytest.raises((ValidationError, ValueError)):
        NoteMeta(title="unsafe", x_evidence=refs)


def test_historical_x_note_has_unknown_receipt_not_fabricated_success():
    meta, _ = parse_frontmatter("---\ntitle: old\nsource: https://x.com/user/status/123\n---\nold text")
    assert meta.x_evidence["receipt_refs"] == []
    assert meta.x_evidence["receipt_state"] == "unknown"
    assert meta.x_evidence["producer"] == {
        "product": "unknown", "version": None, "runtime": None,
        "extension_version": None, "owner": None, "profile": None,
    }


def test_non_x_note_metadata_unchanged():
    meta = NoteMeta(title="ordinary", source="https://example.org/x.com/article")
    assert meta.x_evidence is None


def test_repeated_partial_note_write_preserves_enrichment_and_references(tmp_vault):
    refs = reference_set()
    path = write_note(tmp_vault.notes_dir, "partial", body="first", extra_frontmatter={"x_evidence": refs})
    meta, body = parse_frontmatter(path.read_text())
    meta.summary = "human enrichment"
    path.write_text(render_note(meta, body))
    repeated = write_note(tmp_vault.notes_dir, "partial", body="second", extra_frontmatter={"x_evidence": refs})
    assert repeated == path
    restored = read_note(path, tmp_vault.root)
    assert restored.meta.summary == "human enrichment"
    assert restored.meta.x_evidence == refs
    assert "first" in restored.body


def test_native_exact_host_dispatch():
    from hyperresearch.web.opencli_provider import is_x_url

    for url in ("https://x.com/a/status/123", "https://www.twitter.com/a/status/123", "https://mobile.twitter.com/a/status/123"):
        assert is_x_url(url)
    for url in ("https://x.com.evil.test/a", "https://example.org/x.com", "https://x.com@evil.test/a", "file://x.com/a", "https://evilx.com/a"):
        assert not is_x_url(url)


def test_canonical_source_is_unchanged_and_projection_is_inert():
    from hyperresearch.core.x_projection import inert_markdown, terminal_text

    text = '---\nadmin: true\n---\n<script>alert(1)</script>\n![remote](https://evil.test/image)\n{{ invoke() }}\x1b[2J'
    original = text.encode()
    projected = inert_markdown(text)
    assert text.encode() == original
    assert "<script>" not in projected
    assert "![remote]" not in projected
    assert "{{ invoke() }}" not in projected
    assert "\x1b" not in terminal_text(text)


def test_sync_refuses_missing_artifact_without_partial_note_projection(tmp_vault):
    path = write_note(tmp_vault.notes_dir, "missing", extra_frontmatter={"x_evidence": reference_set()})
    result = execute_sync(tmp_vault, compute_sync_plan(tmp_vault))
    assert any(str(path) in err["path"] for err in result.errors)
    assert tmp_vault.db.execute("SELECT id FROM notes WHERE id = 'missing'").fetchone() is None


def governed_fixture(kind):
    """Use governed fixtures, not a second handwritten wire model."""
    import hyperresearch.models.x_evidence as contracts

    root = Path(contracts.__file__).parents[1] / "schemas" / "x" / "fixtures"
    candidates = sorted((root / kind).glob("valid-*.json"))
    assert candidates, f"No governed valid fixture for {kind}"
    payload = json.loads(candidates[0].read_text())
    return copy.deepcopy(payload)


def test_put_get_manifest_publication_and_corruption(tmp_vault):
    from hyperresearch.core.x_evidence import EvidenceStore

    store = EvidenceStore(tmp_vault.root)
    payload = governed_fixture("source-capabilities")
    ref = store.put_record("source-capabilities", payload)
    assert store.put_record("source-capabilities", payload) == ref
    assert store.get_record(ref, "source-capabilities") == payload
    assert list(store.list_records("source-capabilities")) == [ref]
    (store.root / ref["path"]).write_text("{}")
    with pytest.raises(ValueError, match="checksum"):
        store.get_record(ref)


def test_json_and_markdown_transport_preserve_artifact_closure(tmp_vault, tmp_path):
    from hyperresearch.core.vault import Vault
    from hyperresearch.core.x_evidence import EvidenceStore

    store = EvidenceStore(tmp_vault.root)
    payload = governed_fixture("source-capabilities")
    ref = store.put_record("source-capabilities", payload)
    bundle = store.export_closure([ref])
    fresh = Vault.init(tmp_path / "fresh")
    fresh_store = EvidenceStore(fresh.root)
    fresh_store.import_closure(bundle)
    assert fresh_store.get_record(ref) == payload
    bundle_path = tmp_path / "markdown" / "x-evidence.json"
    store.export_artifacts(bundle_path, [ref])
    other = Vault.init(tmp_path / "other")
    EvidenceStore(other.root).import_artifacts(bundle_path)
    assert EvidenceStore(other.root).get_record(ref) == payload


def test_fresh_sqlite_rebuild_recovers_zero_note_operation_records(tmp_vault):
    from hyperresearch.core.x_evidence import EvidenceStore
    from hyperresearch.core.vault import Vault

    store = EvidenceStore(tmp_vault.root)
    ref = store.put_record("source-capabilities", governed_fixture("source-capabilities"))
    tmp_vault.close()
    tmp_vault.db_path.unlink()
    fresh = Vault(tmp_vault.root)
    fresh.auto_sync()
    rows = fresh.db.execute("SELECT path, sha256 FROM x_records").fetchall()
    assert [(row["path"], row["sha256"]) for row in rows] == [(ref["path"], ref["sha256"])]
    assert fresh.db.execute("SELECT COUNT(*) FROM notes").fetchone()[0] == 0


def test_transport_rejects_escaping_path_and_hash_before_publication(tmp_vault):
    from hyperresearch.core.x_evidence import EvidenceStore

    store = EvidenceStore(tmp_vault.root)
    ref = store.put_record("source-capabilities", governed_fixture("source-capabilities"))
    bundle = store.export_closure([ref])
    bundle["artifacts"][0]["ref"]["path"] = "../outside.json"
    with pytest.raises(ValueError):
        store.import_closure(bundle)


def test_inert_markdown_transport_is_idempotent():
    from hyperresearch.core.x_projection import inert_markdown

    text = '<script>escape()</script> ![fetch](https://unsafe.test/) {{ tool() }} \x1b[2J'
    rendered = inert_markdown(text)
    assert inert_markdown(rendered) == rendered
    assert "<script>" not in rendered and "![" not in rendered and "{{" not in rendered


def test_public_evidence_rejects_shadowed_json_credentials(tmp_vault):
    from hyperresearch.core.x_evidence import EvidenceStore

    with pytest.raises(ValueError, match="Duplicate"):
        EvidenceStore(tmp_vault.root).put_blob(b'{"authorization":"private","authorization":null}')


@pytest.mark.parametrize("key", ["apiKey", "auth-token", "accessToken", "requestHeaders", "private_key"])
def test_support_artifacts_never_retain_credential_aliases(tmp_vault, key):
    from hyperresearch.core.x_evidence import EvidenceStore

    with pytest.raises(ValueError, match="Credentials"):
        EvidenceStore(tmp_vault.root).put_blob(json.dumps({key: "fixture-private"}).encode())


def test_metadata_mutation_to_historical_x_source_persists_explicit_unknown_facts():
    meta = NoteMeta(title="edited source")
    meta.source = "https://x.com/u/status/123"
    restored, _ = parse_frontmatter(render_note(meta, ""))
    assert restored.x_evidence["receipt_state"] == "unknown"
    assert restored.x_evidence["receipt_refs"] == []
