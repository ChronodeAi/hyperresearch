"""Runtime procedure hints and silent stop-hook transport."""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path

import typer


def step_file(skill: str | None, platform: str) -> str | None:
    """Project-relative path of a runtime's step procedure, or None."""
    if skill is None:
        return None
    from hyperresearch.core.platforms import paths_for

    return f"{paths_for(platform).steps_dir}/{skill}.md"


def _hook_payload(cwd: str | None) -> dict:
    if cwd is not None:
        return {"cwd": cwd}
    try:
        raw = sys.stdin.read() if sys.stdin is not None else ""
        loaded = json.loads(raw) if raw.strip() else {}
    except (OSError, ValueError):
        loaded = {}
    return loaded if isinstance(loaded, dict) else {}


def run_stop_gate(
    cwd: str | None = typer.Option(
        None, "--cwd",
        help="Session directory. When given, stdin is not read (OMP's extension passes it).",
    ),
    platform: str | None = typer.Option(
        None, "--platform", help="Runtime whose step file the reason names (default codex)",
    ),
    vault_tag: str | None = typer.Option(
        None, "--vault-tag", help="Bind the gate to this run only (default: newest run)",
    ),
) -> None:
    """Emit one block decision for an active run, otherwise remain silent.

    Explicit tags never select another run. Codex supplies JSON on stdin;
    OMP supplies cwd, platform and tag options. Always exit successfully:
    a broken gate must not wedge the agent.
    """
    try:
        from hyperresearch.core.codex import STOP_GATE_ENV, stop_gate_decision
        from hyperresearch.core.vault import Vault, VaultError

        if os.environ.get(STOP_GATE_ENV, "").strip().lower() in ("0", "false", "no", "off"):
            return
        payload = _hook_payload(cwd)
        if payload.get("stop_hook_active"):
            return
        start_dir = payload.get("cwd")
        start = Path(start_dir) if isinstance(start_dir, str) and start_dir else None
        try:
            vault = Vault.discover(start)
        except VaultError:
            return
        decision = stop_gate_decision(vault, platform=platform, vault_tag=vault_tag)
        if decision is not None:
            sys.stdout.write(json.dumps(decision) + "\n")
            sys.stdout.flush()
    except Exception:
        return
