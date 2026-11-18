"""Spend history survives vault/restart/environment changes and refuses corrupt state."""
from __future__ import annotations

import json
from decimal import Decimal

import pytest

from hyperresearch.core import x_budget
from hyperresearch.core.x_budget import BudgetError, GrantBudget

GRANT = {"grant_digest": "a" * 64, "approval_id": "signed-grant-one"}


@pytest.fixture
def ledger_root(tmp_path, monkeypatch):
    root = tmp_path / "private-host-ledgers"
    monkeypatch.setattr(x_budget, "host_budget_root", lambda: root)
    return root


def test_unknown_spend_and_request_identity_survive_new_consumers(ledger_root, monkeypatch, tmp_path):
    with GrantBudget(GRANT).locked() as original:
        original.change("analysis", "requests", "reserved", 1)
        original.change("analysis", "tokens", "reserved", 200)
        original.change("analysis", "cost_usd", "reserved", "0.25")
        original.state["model_request_ids"].append("wire-request-one")
        original.save()
    monkeypatch.setenv("HOME", str(tmp_path / "fresh-vault-home"))
    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path / "fresh-vault-state"))
    with GrantBudget(GRANT).locked() as restarted:
        assert restarted.total("analysis", "requests") == 1
        assert restarted.state["model_request_ids"] == ["wire-request-one"]
        for key, value in {"requests": 1, "tokens": 200, "cost_usd": "0.25"}.items():
            restarted.change("analysis", key, "reserved", -Decimal(str(value)))
            restarted.change("analysis", key, "unknown", value)
        restarted.save()
    with GrantBudget(GRANT).locked() as another_vault:
        assert another_vault.state["accounting"]["analysis"]["requests"] == {"reserved": 0, "actual": 0, "unknown": 1}
        assert another_vault.total("analysis", "tokens") == 200
        assert another_vault.total("analysis", "cost_usd") == Decimal("0.25")
        assert another_vault.state["model_request_ids"] == ["wire-request-one"]


def test_conclusively_undispatched_observation_can_release_only_its_hold(ledger_root):
    with GrantBudget(GRANT).locked() as ledger:
        ledger.change("observations", "requests", "unknown", 2)
        ledger.state["observation_request_ids"] = ["emitted-unknown", "not-emitted"]
        ledger.save()
    with GrantBudget(GRANT).locked() as ledger:
        ledger.change("observations", "requests", "unknown", -1)
        ledger.state["observation_request_ids"].remove("not-emitted")
        ledger.save()
    with GrantBudget(GRANT).locked() as recovered:
        assert recovered.total("observations", "requests") == 1
        assert recovered.state["observation_request_ids"] == ["emitted-unknown"]


def test_corrupt_history_never_becomes_an_empty_balance(ledger_root):
    with GrantBudget(GRANT).locked() as ledger:
        ledger.change("analysis", "requests", "unknown", 1)
        ledger.save()
        path = ledger.path
    path.write_text("{not-json", encoding="utf-8")
    with pytest.raises(BudgetError, match="invalid_host_budget_ledger"):
        with GrantBudget(GRANT).locked():
            pytest.fail("corrupt spend history was admitted")
    assert path.read_text(encoding="utf-8") == "{not-json"


def test_same_digest_cannot_take_another_approval_identity(ledger_root):
    with GrantBudget(GRANT).locked() as ledger:
        ledger.save()
    with pytest.raises(BudgetError, match="host_budget_identity_mismatch"):
        with GrantBudget({**GRANT, "approval_id": "different-grant"}).locked():
            pytest.fail("ledger identity was replaced")


@pytest.mark.parametrize("amount", [-1, Decimal("0.5"), Decimal("NaN")])
def test_count_reservations_refuse_underflow_fraction_and_nonfinite(ledger_root, amount):
    with GrantBudget(GRANT).locked() as ledger:
        with pytest.raises(BudgetError):
            ledger.change("analysis", "requests", "reserved", amount)
        assert ledger.total("analysis", "requests") == 0


def test_symlinked_ledger_cannot_select_fresh_or_external_history(ledger_root, tmp_path):
    with GrantBudget(GRANT).locked() as ledger:
        ledger.save()
        path = ledger.path
    outside = tmp_path / "outside.json"
    outside.write_text(json.dumps({"untrusted": True}), encoding="utf-8")
    path.unlink()
    path.symlink_to(outside)
    with pytest.raises(BudgetError, match="unsafe_host_budget_path"):
        with GrantBudget(GRANT).locked():
            pytest.fail("symlinked ledger was admitted")
    assert json.loads(outside.read_text()) == {"untrusted": True}
