"""Catalog-selected offline records and independently owned authority bytes.

Only the protected-file read boundary is supplied by this fixture. Signature,
plan, scope, budget, host, model and expiry checks still run through production
verification. The synthetic signing key never enters a vault or live authority.
"""

from __future__ import annotations

import base64
import hashlib
import json
from pathlib import Path
from types import SimpleNamespace

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from hyperresearch.core import x_authority as authority
from hyperresearch.models import x_evidence as contracts
from hyperresearch.models.x_evidence import canonical_bytes, validate_record

SCHEMA_ROOT = Path(contracts.__file__).parents[1] / "schemas" / "x"
REPOSITORY_ROOT = Path(contracts.__file__).parents[3]
START = "2026-10-10T00:00:00Z"
EXPIRES = "2026-10-10T00:30:00Z"


def governed_fixture_path(kind: str, case: str) -> Path:
    catalog = json.loads((SCHEMA_ROOT / "catalog.json").read_text(encoding="utf-8"))
    artifacts = [artifact for domain in catalog["domains"] for artifact in domain["artifacts"]
                 if artifact["logicalName"] == f"x-{kind}"]
    assert len(artifacts) == 1, f"Missing or ambiguous governed catalog entry for {kind}"
    paths = [REPOSITORY_ROOT / path for path in artifacts[0]["fixtures"]["valid"]
             if Path(path).name == f"valid-{case}.json"]
    assert len(paths) == 1, f"Missing or ambiguous governed valid fixture for {kind}/{case}"
    return paths[0]


def governed_fixture(kind: str, case: str) -> dict:
    return json.loads(governed_fixture_path(kind, case).read_text(encoding="utf-8"))


def approval_payload(plan: dict, *, operations: tuple[str, ...], hosts: tuple[str, ...],
                     approval_id: str = "offline-approval", export: bool = True) -> dict:
    analysis, session = plan["limits"]["analysis"], plan["limits"]["session"]
    model = "model.classify" in operations
    payload = {
        "schema_version": 1, "purpose": "x-research-approval", "approval_id": approval_id,
        "plan_id": plan["plan_id"], "plan_digest": plan["digest"], "plan_revision": plan["revision"],
        "source_owner": plan["source"]["owner"], "source_profile": plan["source"]["profile"],
        "operations": list(operations), "not_before": START, "expires_at": EXPIRES,
        "budget_ceilings": {
            "source_requests": session["max_requests"], "source_pages": session["max_pages"],
            "total_captures": session["max_captures"],
            "operation_timeout_s": plan["limits"]["poll"]["max_elapsed_s"],
            "session_duration_s": session["max_elapsed_s"],
            "model_requests": analysis["max_requests"] if model else 0,
            "model_tokens": analysis["max_tokens"] if model else 0,
            "model_cost_usd": analysis["max_cost_usd"] if model else "0",
        },
        "allowed_hosts": list(hosts), "allowed_models": [plan["analysis"]["model"]] if model else [],
        "envelope": None,
        "export_policy": plan["analysis"]["export_policy"] if model and export else None,
    }
    if "observations.read" in operations:
        payload["budget_ceilings"].update(observation_requests=100, observation_timeout_s=30)
        payload["observation_bindings"] = plan["profile"].get("observation_sources", [])
    return validate_record("approval-payload", payload)


class ProtectedOrigin:
    """Supply exact host-owned files, never imported records' self-declared keys."""

    def __init__(self, monkeypatch, *, clock):
        self.clock = clock
        self.trust_path = "/offline-x-authority/trust.json"
        self.grant_root = "/offline-x-authority/grants"
        self.approval_ref = "offline-grant.json"
        self._signer = Ed25519PrivateKey.from_private_bytes(bytes([71]) * 32)
        public = self._signer.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        self.keys = {"test-operator": base64.b64encode(public).decode("ascii")}
        self._trust = {"schema_version": 1, "purpose": "x-research-trust-store",
                       "keys": self.keys, "revoked_approval_ids": [], "grant_root": self.grant_root}
        self._files = {self.trust_path: canonical_bytes(validate_record("trust-store", self._trust))}
        self.vault = SimpleNamespace(config=SimpleNamespace(x=SimpleNamespace(
            trust_store=self.trust_path, approval_ref=self.approval_ref)))
        monkeypatch.setattr(authority, "_protected_read", self._read)
        monkeypatch.setattr(authority, "utc_now", lambda: self.clock())

    def _read(self, path, *, limit=262144):
        raw = self._files.get(str(path))
        if raw is None:
            raise authority.ApprovalError("host_authority_unavailable")
        if len(raw) > limit:
            raise authority.ApprovalError("authority_artifact_too_large")
        return raw

    @property
    def trust_digest(self):
        return hashlib.sha256(self._files[self.trust_path]).hexdigest()

    def install(self, payload):
        raw = canonical_bytes(validate_record("approval-payload", payload))
        envelope = validate_record("approval-envelope", {
            "schema_version": 1, "key_id": "test-operator",
            "payload_b64": base64.b64encode(raw).decode("ascii"),
            "signature_b64": base64.b64encode(self._signer.sign(raw)).decode("ascii"),
        })
        self._files[f"{self.grant_root}/{self.approval_ref}"] = canonical_bytes(envelope)

    def resolve(self, plan, request, *, now=None):
        return authority.resolve_approval(self.vault, plan, request["action"],
            approval_ref=self.approval_ref, request=request, now=now or self.clock())

    def admit(self, plan, request, payload, *, now=None):
        self.install(payload)
        return self.resolve(plan, request, now=now)

    def revoke(self, approval_id):
        self._trust["revoked_approval_ids"].append(approval_id)
        self._files[self.trust_path] = canonical_bytes(validate_record("trust-store", self._trust))

    def snapshot(self, admissions, refs):
        unique = {admission["grant_digest"]: admission for admission in admissions}
        return authority.authority_snapshot(self.vault, list(unique.values()), evidence_refs=list(refs))
