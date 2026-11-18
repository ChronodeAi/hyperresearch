"""Offline authority/fixture/projection checks for the integration owner to run."""

from __future__ import annotations

import copy
import hashlib
import json
import os
from pathlib import Path

import pytest

from hyperresearch.models.x_evidence import (
    ArtifactReferenceError,
    ContractValidationError,
    RECORD_KINDS,
    SCHEMA_IDS,
    SchemaProjectionError,
    canonical_bytes,
    load_schema,
    plan_digest,
    record_digest,
    validate_artifact_path,
    validate_artifact_ref,
    validate_definition,
    validate_record,
    verify_record_projection,
    verify_reference_projection,
    verify_schema_projections,
)

ASSETS = Path(__file__).resolve().parents[1]
REPOSITORY = Path(__file__).resolve().parents[5]
FIXTURES = ASSETS / "fixtures"


def read_fixture(relative: str):
    return json.loads((FIXTURES / relative).read_text(encoding="utf-8"))


def fixture_parameters():
    catalog = json.loads((ASSETS / "catalog.json").read_text(encoding="utf-8"))
    rows = []
    for domain in catalog["domains"]:
        for artifact in domain["artifacts"]:
            kind = next(name for name, identity in SCHEMA_IDS.items() if identity == artifact["id"])
            for state in ("valid", "invalid"):
                rows.extend((kind, path, state == "valid") for path in artifact["fixtures"][state])
    return rows


@pytest.mark.parametrize("kind,path,valid", fixture_parameters())
def test_catalog_registered_fixtures(kind, path, valid):
    payload = json.loads((REPOSITORY / path).read_text(encoding="utf-8"))
    if valid:
        restored = validate_record(kind, payload)
        assert restored == payload
        assert restored is not payload
    else:
        with pytest.raises(ContractValidationError):
            validate_record(kind, payload)


def test_eight_families_have_identity_ownership_and_boundary_fixtures():
    catalog = json.loads((ASSETS / "catalog.json").read_text(encoding="utf-8"))
    artifacts = [artifact for domain in catalog["domains"] for artifact in domain["artifacts"]]
    assert {artifact["id"] for artifact in artifacts} == set(SCHEMA_IDS.values())
    for artifact in artifacts:
        assert len(artifact["fixtures"]["valid"]) >= 2
        assert len(artifact["fixtures"]["invalid"]) >= 2
        assert artifact["version"] == "1.0.0"
        assert artifact["dialect"].endswith("2020-12/schema")
        assert artifact["policy"]["remoteReferences"] == "deny"
        assert artifact["publication"]["public"] is False
        assert artifact["compatibility"]["mode"] == "none"
        assert artifact["consumers"]
        assert artifact["projections"]


@pytest.mark.parametrize("kind", RECORD_KINDS)
def test_unknown_versions_and_operational_fields_are_not_silently_ignored(kind):
    first = next((FIXTURES / kind).glob("valid-*.json"))
    payload = json.loads(first.read_text(encoding="utf-8"))
    with pytest.raises(ContractValidationError):
        validate_record(kind, {**payload, "schema_version": 99})
    with pytest.raises(ContractValidationError):
        validate_record(kind, {**payload, "authorization_header": "not-retained"})


@pytest.mark.parametrize("relative", sorted(FIXTURES.glob("definitions/*/*.json")))
def test_governed_definition_fixtures(relative):
    definition = relative.parent.name
    value = json.loads(relative.read_text(encoding="utf-8"))
    if relative.name.startswith("valid-"):
        assert validate_definition(definition, value) == value
    else:
        with pytest.raises(ContractValidationError):
            validate_definition(definition, value)


def test_jcs_matches_ecmascript_numbers_and_utf16_key_order():
    assert canonical_bytes([1.0, 1e-7, 1e-6, 1e20, 1e21, -0.0]) == b"[1,1e-7,0.000001,100000000000000000000,1e+21,0]"
    value = {"\ue000": 2, "\U00010000": 1}
    assert canonical_bytes(value) == '{"\U00010000":1,"\ue000":2}'.encode("utf-8")
    assert record_digest({"a": 1.0}) == record_digest({"a": 1})


@pytest.mark.parametrize("name", ["numbers", "utf16-order"])
def test_shared_native_jcs_conformance_fixtures(name):
    value = read_fixture(f"canonicalization/{name}-input.json")
    assert canonical_bytes(value) == (FIXTURES / "canonicalization" / f"{name}-expected.json").read_bytes()


@pytest.mark.parametrize("value", [float("nan"), float("inf"), 2**53, "\ud800", {1: "non-string key"}, (1, 2)])
def test_non_interoperable_json_values_fail_instead_of_being_coerced(value):
    with pytest.raises(ContractValidationError):
        canonical_bytes(value)


@pytest.mark.parametrize("raw", [b'{"text":"\\ud800"}', b'{"text":"\\udfff"}'])
def test_native_import_validation_rejects_lone_surrogates_before_canonicalization(raw):
    payload = read_fixture("source-capture/valid-original.json")
    payload["text"] = json.loads(raw)["text"]
    with pytest.raises(ContractValidationError):
        validate_record("source-capture", payload)


def test_freeform_native_metadata_keys_still_require_utf8_json_transport():
    value = {"schema_version": 1, "notes": [{"path": "notes/one.md", "metadata": {"title": "One", "\ud800": "invalid key"}, "body": "Public text"}], "evidence": {"schema_version": 1, "artifacts": [], "manifests": []}}
    with pytest.raises(ContractValidationError):
        validate_record("note-transport", value)


def test_native_valid_surrogate_pair_decodes_to_preserved_unicode_scalar():
    payload = read_fixture("source-capture/valid-original.json")
    payload["text"] = json.loads(b'{"text":"\\ud800\\udc00"}')["text"]
    assert validate_record("source-capture", payload)["text"] == "\U00010000"


def test_plan_digest_has_no_self_reference_and_binds_all_profile_settings():
    plan = read_fixture("monitor-plan/valid-source-only-sentiment.json")
    assert plan_digest(plan) == plan["digest"]
    assert plan["digest"] == record_digest({key: value for key, value in plan.items() if key != "digest"})
    modified = copy.deepcopy(plan)
    modified["profile"]["target"] = "Another target"
    with pytest.raises(ContractValidationError):
        plan_digest(modified)


def test_schema_loading_is_detached_and_local():
    first = load_schema("source-capture")
    first["properties"]["post_id"] = {"type": "number"}
    assert load_schema("source-capture")["properties"]["post_id"] != {"type": "number"}
    assert load_schema("source-scope")["$ref"].endswith("source-receipt.v1.json#/$defs/source_scope")
    with pytest.raises(ContractValidationError):
        load_schema("https://unknown.example.test/schema.json")


@pytest.mark.parametrize("path", ["../outside.json", "/absolute.json", "a/../b.json", "a/./b.json", "a//b.json", "a\\b.json", "file:///tmp/a.json", "a/%2e%2e/b.json", "a.json\n", "a.json\x00", "", ".hidden.json"])
def test_unsafe_artifact_paths_are_rejected_by_authority(path):
    with pytest.raises(ArtifactReferenceError):
        validate_artifact_path(path)


def test_artifact_ref_proves_checksum_and_regular_file_containment(tmp_path):
    directory = tmp_path / "records"
    directory.mkdir()
    raw = b'{"schema_version":1,"fixture":"exact raw bytes"}'
    target = directory / "one.json"
    target.write_bytes(raw)
    ref = {"path": "records/one.json", "sha256": hashlib.sha256(raw).hexdigest()}
    assert validate_artifact_ref(ref, root=tmp_path, verify_checksum=True) == ref
    with pytest.raises(ArtifactReferenceError):
        validate_artifact_ref({**ref, "sha256": "0" * 64}, root=tmp_path, verify_checksum=True)
    with pytest.raises(ArtifactReferenceError):
        validate_artifact_ref(ref, verify_checksum=True)
    with pytest.raises(ArtifactReferenceError):
        validate_artifact_ref({"path": "records", "sha256": ref["sha256"]}, root=tmp_path)


def test_symlink_parent_and_leaf_never_escape_artifact_root(tmp_path):
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "one.json").write_bytes(b"fixture")
    root = tmp_path / "root"
    root.mkdir()
    (root / "linked").symlink_to(outside, target_is_directory=True)
    (root / "leaf.json").symlink_to(outside / "one.json")
    for relative in ("linked/one.json", "leaf.json"):
        with pytest.raises(ArtifactReferenceError):
            validate_artifact_ref({"path": relative, "sha256": hashlib.sha256(b"fixture").hexdigest()}, root=root, verify_checksum=True)


def test_governed_note_projection_preserves_actual_producer_and_every_ref():
    payload = read_fixture("definitions/note-evidence-refs/valid-recorded.json")
    restored = json.loads(canonical_bytes(payload))
    verify_reference_projection(payload, restored)
    changed = copy.deepcopy(restored)
    changed["producer"]["product"] = "configured-route-not-actual-producer"
    with pytest.raises(SchemaProjectionError):
        verify_reference_projection(payload, changed)
    changed = copy.deepcopy(restored)
    changed["annotation_refs"] = []
    with pytest.raises(SchemaProjectionError):
        verify_reference_projection(payload, changed)


def test_partial_page_record_roundtrip_keeps_unknown_ownership_and_lineage():
    payload = read_fixture("source-receipt/valid-durable-partial-unknown-execution.json")
    verify_record_projection("source-receipt", payload, json.loads(canonical_bytes(payload)))
    assert payload["execution"]["state"] == "unknown"
    assert payload["durability"]["committed_pages"] == 1
    assert payload["coverage"]["state"] == "partial"
    assert payload["continuation"]["frontier"]["page_ordinal"] == 0
    assert payload["artifacts"]


def test_raw_related_delivery_preserves_bytes_without_inflating_context_quota():
    payload = read_fixture("source-capture/valid-delivered-raw-context-clipped.json")
    relation = payload["relationships"][0]
    assert relation["delivery"] == "delivered"
    assert relation["capture_ref"]["record_id"] == "post-2002"
    assert "schema_id" not in relation["capture_ref"]
    verify_record_projection("source-capture", payload, json.loads(canonical_bytes(payload)))
    receipt = read_fixture("source-receipt/valid-context-cap-retains-delivered-raw.json")
    assert receipt["scope"]["limits"]["max_context"] == 0
    assert receipt["counters"]["context_count"] == 0
    assert receipt["counters"]["capture_count"] == 1
    validate_record("source-receipt", receipt)


def test_note_transport_keeps_unicode_names_but_rejects_path_escape():
    value = {"schema_version": 1, "notes": [{"path": "知识/主题.md", "metadata": {"title": "主题"}, "body": "Inert text"}], "evidence": {"schema_version": 1, "artifacts": [], "manifests": []}}
    assert validate_record("note-transport", value) == value
    for unsafe in ("../主题.md", "/主题.md", "知识/../主题.md", "知识//主题.md", "知识\\主题.md", "知识/主题.md\n"):
        changed = copy.deepcopy(value)
        changed["notes"][0]["path"] = unsafe
        with pytest.raises(ContractValidationError):
            validate_record("note-transport", changed)


def test_model_envelope_requires_exact_billing_bound_reference():
    value = read_fixture("definitions/approval-payload/valid-envelope-structural.json")
    validate_record("approval-payload", value)
    del value["envelope"]["provider_bounds_ref"]
    with pytest.raises(ContractValidationError):
        validate_record("approval-payload", value)


def test_packaged_authority_pins_and_peer_byte_mirrors():
    assert set(verify_schema_projections()) == set(SCHEMA_IDS.values())
    peer = Path(os.environ.get("OPENCLI_X_CONTRACT_ROOT", str(REPOSITORY.parent / "opencli")))
    if not peer.is_dir():
        pytest.skip("Cross-product parity needs the OpenCLI checkout; packaged pins were checked")
    assert set(verify_schema_projections(peer)) == set(SCHEMA_IDS.values())
