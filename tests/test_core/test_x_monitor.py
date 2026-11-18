"""Canonical monitor transitions, fair restart scheduling, and network-free replay."""
from __future__ import annotations

import asyncio
import copy
import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from hyperresearch.core.x_evidence import EvidenceStore
from hyperresearch.core.x_monitor import (
    MonitorRunner, load_session, new_session, replay_monitor, status_monitor, stop_monitor,
)
from hyperresearch.core.x_plans import QueryError, prepare_plan
from hyperresearch.models import x_evidence
from hyperresearch.models.x_evidence import record_digest

FIXTURES = Path(x_evidence.__file__).parents[1] / "schemas" / "x" / "fixtures"
NOW = datetime(2026, 10, 10, tzinfo=UTC)


def fixture(kind, name):
    return json.loads((FIXTURES / kind / f"valid-{name}.json").read_text(encoding="utf-8"))


def plan():
    return prepare_plan(fixture("monitor-plan", "source-only-sentiment"))


def test_enabled_analysis_rejects_unbounded_zero_queue():
    proposal = fixture("monitor-plan", "analyzed-sentiment")
    proposal["limits"]["analysis"]["max_queue"] = 0
    with pytest.raises(QueryError, match="bounded nonzero queue"):
        prepare_plan(proposal)


def test_restart_preserves_due_query_pointer_deadline_and_analysis_backlog(tmp_vault):
    store = EvidenceStore(tmp_vault.root)
    proposal = plan()
    if len(proposal["queries"]) == 1:
        proposal["queries"].append({**proposal["queries"][0], "id": "q2", "expression": '"Second product"'})
        proposal = prepare_plan(proposal)
    session = new_session(store, proposal, now=NOW, stop_after=60)
    session["next_query_index"] = 1
    session["query_state"][0]["next_due_at"] = (NOW + timedelta(seconds=40)).isoformat().replace("+00:00", "Z")
    session["query_state"][1]["next_due_at"] = NOW.isoformat().replace("+00:00", "Z")
    job_ref = store.put_blob(b'{"durable":"pending-analysis"}')
    session["deferred_work"] = [{"id": "pending-job", "kind": "annotation", "operation_id": None, "ref": job_ref, "state": "queued"}]
    session["accounting"]["analysis"]["tokens"]["unknown"] = 200
    original_expiry = session["expires_at"]
    runner = MonitorRunner(tmp_vault, proposal, session, clock=lambda: NOW)
    runner.checkpoint()
    recovered, _ = load_session(store, session["monitor_id"])
    restarted = MonitorRunner(tmp_vault, proposal, recovered, clock=lambda: NOW + timedelta(seconds=10))
    assert restarted._next_query() == 1
    assert restarted.session["expires_at"] == original_expiry
    assert restarted.session["deferred_work"] == session["deferred_work"]
    assert restarted.session["accounting"]["analysis"]["tokens"]["unknown"] == 200


def test_unknown_execution_keeps_full_source_reservation_after_restart(tmp_vault):
    store = EvidenceStore(tmp_vault.root)
    proposal = plan()
    session = new_session(store, proposal, now=NOW)
    runner = MonitorRunner(tmp_vault, proposal, session, clock=lambda: NOW)
    receipt = fixture("source-receipt", "durable-partial-unknown-execution")
    scope = copy.deepcopy(receipt["scope"])
    scope["plan_ref"] = copy.deepcopy(session["plan_ref"])
    receipt["scope"] = scope
    receipt["artifacts"] = []
    receipt["continuation"]["scope_digest"] = record_digest(scope)
    receipt_ref = store.put_record("source-receipt", receipt)
    runner._reserve_source(scope)
    runner._source_result({"scope": scope, "receipt_refs": [receipt_ref], "final_receipt_ref": receipt_ref})
    recovered, _ = load_session(store, session["monitor_id"])
    assert recovered["active_operation"]["state"] == "unknown"
    assert recovered["active_operation"]["deadline"] == scope["deadline"]
    assert recovered["accounting"]["source"]["requests"] == {"reserved": 0, "actual": 0, "unknown": scope["limits"]["max_requests"]}
    assert recovered["coverage_gaps"][0]["state"] == "partial"
    assert recovered["coverage_gaps"][0]["receipt_ref"] == receipt_ref


def test_stop_retains_original_identity_counters_and_canonical_evidence(tmp_vault):
    store = EvidenceStore(tmp_vault.root)
    proposal = plan()
    session = new_session(store, proposal, now=NOW)
    session["accounting"]["analysis"]["requests"]["unknown"] = 1
    runner = MonitorRunner(tmp_vault, proposal, session, clock=lambda: NOW)
    before = runner.checkpoint()
    stop_monitor(store, session["monitor_id"])
    status = status_monitor(store, session["monitor_id"])
    current, after = load_session(store, session["monitor_id"])
    assert before == after
    assert current["session_id"] == session["session_id"]
    assert current["accounting"]["analysis"]["requests"]["unknown"] == 1
    assert runner._stopping() is True
    assert status["monitor_id"] == session["monitor_id"]


def test_replay_is_idempotent_at_frozen_evaluation_with_acquisition_disabled(tmp_vault):
    store = EvidenceStore(tmp_vault.root)
    proposal = plan()
    session = new_session(store, proposal, now=NOW)
    session["state"] = "completed"
    session["stopped_at"] = (NOW + timedelta(seconds=30)).isoformat().replace("+00:00", "Z")
    runner = MonitorRunner(tmp_vault, proposal, session, clock=lambda: NOW)
    runner.checkpoint()
    first = replay_monitor(tmp_vault, session["monitor_id"])
    second = replay_monitor(tmp_vault, session["monitor_id"])
    assert first["session_ref"] == second["session_ref"]
    assert first["output_refs"] == second["output_refs"]
    assert first["external_calls"] == second["external_calls"] == 0
    assert first["new_model_requests"] == first["new_source_requests"] == 0
    events = [store.get_record(ref, "analytics-event") for ref in first["output_refs"]]
    assert all(event["metrics"]["post_count"] == 0 and event["coverage"]["state"] == "unknown" for event in events)


def test_disabled_source_monitor_returns_durable_refusal_without_dispatch(tmp_vault):
    store = EvidenceStore(tmp_vault.root)
    proposal = plan()
    session = new_session(store, proposal, now=NOW)
    runner = MonitorRunner(tmp_vault, proposal, session, clock=lambda: NOW)
    result = asyncio.run(runner.run())
    assert result["state"] == "blocked"
    assert result["accounting"]["source"]["requests"] == {"reserved": 0, "actual": 0, "unknown": 0}
    persisted = store.get_record(result["session_ref"], "monitor-session")
    assert persisted["state"] == "blocked"
    assert persisted["active_operation"] is None


def test_cli_stop_acknowledges_blocked_target_without_changing_session(tmp_vault, monkeypatch):
    from dataclasses import replace
    from typer.testing import CliRunner
    from hyperresearch.cli import app

    tmp_vault._config = replace(tmp_vault.config, x=replace(tmp_vault.config.x, enabled=False))
    store = EvidenceStore(tmp_vault.root)
    proposal = plan()
    session = new_session(store, proposal, now=NOW)
    result = asyncio.run(MonitorRunner(tmp_vault, proposal, session, clock=lambda: NOW).run())
    before = store.get_record(result["session_ref"], "monitor-session")
    monkeypatch.chdir(tmp_vault.root)
    stopped = CliRunner().invoke(app, ["x", "stop", "--monitor", session["monitor_id"], "--json"])
    assert stopped.exit_code == 0, stopped.stdout
    acknowledgement = json.loads(stopped.stdout)["data"]
    assert acknowledgement["stop_requested"] is True
    assert acknowledgement["state"] == "blocked"
    after, after_ref = load_session(store, session["monitor_id"])
    assert after_ref == result["session_ref"]
    assert after["accounting"] == before["accounting"]
    assert after["expires_at"] == before["expires_at"]
    assert status_monitor(store, session["monitor_id"])["stop_requested"] is True
