"""MCP control requests must not misreport the target monitor's outcome."""
from __future__ import annotations

import pytest

from hyperresearch.core.x_evidence import EvidenceStore
from hyperresearch.core.x_monitor import load_session, new_session
from tests.x_fixtures import governed_fixture

mcp = pytest.importorskip("hyperresearch.mcp.server")


@pytest.mark.parametrize("state", ["blocked", "failed"])
def test_stop_acknowledges_request_without_changing_target_state(tmp_vault, monkeypatch, state):
    monkeypatch.chdir(tmp_vault.root)
    store = EvidenceStore(tmp_vault.root)
    plan = governed_fixture("monitor-plan", "source-only-sentiment")
    session = new_session(store, plan, monitor_id="stop-target")
    session["state"] = state
    session["stop_reason"] = "source-not-running"
    original_ref = store.put_record("monitor-session", session)

    reply = mcp.x_stop("stop-target")

    assert reply["ok"] is True
    assert reply["data"]["stop_requested"] is True
    assert reply["data"]["state"] == state
    assert reply["data"]["source_lease_released"] is False
    current, current_ref = load_session(store, "stop-target")
    assert current_ref == original_ref
    assert current == session


def test_stop_failure_is_not_acknowledged(tmp_vault, monkeypatch):
    monkeypatch.chdir(tmp_vault.root)
    reply = mcp.x_stop("absent-monitor")
    assert reply["ok"] is False
    assert "stop_requested" not in reply["data"]
