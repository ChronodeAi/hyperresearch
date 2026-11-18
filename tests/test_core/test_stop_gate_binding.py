"""Run-bound stop gates must never attach another writer's manifest."""

import json
from datetime import UTC, datetime, timedelta

import pytest
from typer.testing import CliRunner

from hyperresearch.cli import app
from hyperresearch.core import runs
from hyperresearch.core.codex import stop_gate_decision

NOW = datetime(2026, 1, 2, 12, tzinfo=UTC)
runner = CliRunner()


@pytest.fixture
def bound_vault(tmp_vault, monkeypatch):
    monkeypatch.delenv("HYPERRESEARCH_STOP_GATE", raising=False)
    monkeypatch.setattr(runs, "_now", lambda: (NOW - timedelta(hours=1)).isoformat())
    runs.init_run(tmp_vault, "bound-run")
    runs.set_step(tmp_vault, "bound-run", "1", "done")
    monkeypatch.setattr(runs, "_now", lambda: NOW.isoformat())
    runs.init_run(tmp_vault, "foreign-run")
    return tmp_vault


def _gate(vault, tag="bound-run", **kwargs):
    return stop_gate_decision(vault, now=NOW, vault_tag=tag, **kwargs)


def _cli(vault, monkeypatch, tag="bound-run", *, bound=True, extra=()):
    # Keep CLI's clock deterministic without replacing the decision implementation.
    class Clock(datetime):
        @classmethod
        def now(cls, tz=None):
            return NOW

    monkeypatch.setattr("hyperresearch.core.codex.datetime", Clock)
    args = ["run", "stop-gate", "--cwd", str(vault.root), "--platform", "omp"]
    if bound:
        args += ["--vault-tag", tag]
    return runner.invoke(app, args + list(extra), input="not JSON")


def test_completed_bound_run_ignores_newer_active_run(bound_vault, monkeypatch):
    runs.set_status(bound_vault, "bound-run", "done")
    assert _gate(bound_vault) is None
    result = _cli(bound_vault, monkeypatch)
    assert result.exit_code == 0
    assert result.stdout == ""
    assert "foreign-run is at step 1" in stop_gate_decision(bound_vault, now=NOW)["reason"]


@pytest.mark.parametrize("foreign_status", ["done", "running"])
def test_active_bound_run_keeps_its_own_next_step(bound_vault, monkeypatch, foreign_status):
    runs.set_status(bound_vault, "foreign-run", foreign_status)
    decision = _gate(bound_vault, platform="omp")
    result = _cli(bound_vault, monkeypatch)
    assert result.exit_code == 0
    assert json.loads(result.stdout) == decision
    assert result.stdout.count("\n") == 1
    assert "bound-run is at step 2 (hyperresearch-2-width-sweep)" in decision["reason"]
    assert ".hyperresearch/omp/steps/hyperresearch-2-width-sweep.md" in decision["reason"]
    assert "foreign-run" not in decision["reason"]
    legacy = stop_gate_decision(bound_vault, now=NOW)
    if foreign_status == "done":
        assert legacy is None
    else:
        assert "foreign-run is at step 1" in legacy["reason"]
        assert ".hyperresearch/codex/steps/" in legacy["reason"]


@pytest.mark.parametrize("target", ["missing", "corrupt", "invalid-shape", "wrong-tag", "invalid-tag"])
def test_unavailable_bound_target_never_falls_back(bound_vault, monkeypatch, target):
    tag = "bound-run"
    manifest = runs.manifest_path(bound_vault, tag)
    if target == "missing":
        tag = "missing-run"
    elif target == "corrupt":
        manifest.write_text("{broken", encoding="utf-8")
    elif target == "invalid-shape":
        manifest.write_text("[]", encoding="utf-8")
    elif target == "wrong-tag":
        manifest.write_text(json.dumps(runs.load_manifest(bound_vault, "foreign-run")), encoding="utf-8")
    else:
        tag = "../foreign-run"
    assert _gate(bound_vault, tag) is None
    result = _cli(bound_vault, monkeypatch, tag)
    assert result.exit_code == 0
    assert result.stdout == ""


def test_bound_gate_preserves_stale_and_declared_tier_semantics(bound_vault):
    decomposition = bound_vault.run_dir("bound-run") / "prompt-decomposition.json"
    decomposition.write_text(json.dumps({"pipeline_tier": "light"}), encoding="utf-8")
    runs.set_step(bound_vault, "bound-run", "2", "done")
    assert "bound-run is at step 10" in _gate(bound_vault)["reason"]
    assert stop_gate_decision(bound_vault, now=NOW + timedelta(hours=7), vault_tag="bound-run") is None


def test_unbound_cli_preserves_newest_run_selection(bound_vault, monkeypatch):
    result = _cli(bound_vault, monkeypatch, bound=False)
    assert result.exit_code == 0
    assert "foreign-run is at step 1" in json.loads(result.stdout)["reason"]


def test_bound_cli_keeps_opt_out_and_stop_hook_active(bound_vault, monkeypatch):
    monkeypatch.setenv("HYPERRESEARCH_STOP_GATE", "0")
    result = _cli(bound_vault, monkeypatch)
    assert result.exit_code == 0
    assert result.stdout == ""
    monkeypatch.delenv("HYPERRESEARCH_STOP_GATE")
    result = runner.invoke(
        app, ["run", "stop-gate", "--vault-tag", "bound-run"],
        input=json.dumps({"cwd": str(bound_vault.root), "stop_hook_active": True}),
    )
    assert result.exit_code == 0
    assert result.stdout == ""
