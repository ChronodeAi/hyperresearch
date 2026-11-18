"""Bounded native X acquisition and observational analytics; no implicit grants."""
from __future__ import annotations

import asyncio
import json
from collections.abc import Callable
from pathlib import Path

import typer

from hyperresearch.cli._output import output
from hyperresearch.models.output import error, success

app = typer.Typer(no_args_is_help=True)


def _execute(operation: Callable[[], dict], json_output: bool, *, state_is_outcome: bool = True) -> None:
    try:
        result = operation()
    except (ValueError, TypeError, KeyError, PermissionError, RuntimeError, OSError, ImportError) as exc:
        output(error(str(exc), getattr(exc, "code", "X_REQUEST_REFUSED")), json_mode=json_output)
        raise typer.Exit(1) from exc
    output(success(result), json_mode=json_output)
    if state_is_outcome and result.get("state") in {"blocked", "failed"}:
        raise typer.Exit(1)


def _payload(value: str | Path):
    text = str(value)
    if not text.lstrip().startswith(("{", "[")):
        text = Path(text).read_text(encoding="utf-8")

    def pairs(items):
        obj = {}
        for key, item in items:
            if key in obj:
                raise ValueError("Duplicate JSON keys are not accepted")
            obj[key] = item
        return obj

    def nonfinite(_):
        raise ValueError("Non-finite JSON numbers are not accepted")

    return json.loads(text, object_pairs_hook=pairs, parse_constant=nonfinite)


def _vault():
    from hyperresearch.core.vault import Vault
    return Vault.discover()


def _reference(store, value: str | dict, kind: str | None = None) -> dict:
    from hyperresearch.models.x_evidence import validate_artifact_ref
    if isinstance(value, dict):
        candidate = value
    else:
        try:
            candidate = _payload(value)
        except (FileNotFoundError, json.JSONDecodeError, UnicodeDecodeError):
            return store.ref_from_path(Path(value))
    if not isinstance(candidate, dict):
        raise ValueError("An artifact reference or canonical record is required")
    if "path" in candidate and "sha256" in candidate:
        ref = validate_artifact_ref(candidate)
    elif kind is not None:
        ref = store.put_record(kind, candidate)
    else:
        raise ValueError("Expected a checksum-bound artifact reference")
    if kind is not None:
        store.get_record(ref, kind)
    return ref


def _plan(store, value: str | dict) -> tuple[dict, dict]:
    from hyperresearch.core.x_plans import validate_plan
    ref = _reference(store, value, "monitor-plan")
    return validate_plan(store.get_record(ref, "monitor-plan")), ref


@app.command("schema")
def schema(kind: str = typer.Option("monitor-plan", "--kind"),
           json_output: bool = typer.Option(False, "--json", "-j")) -> None:
    """Read a packaged governed schema locally, without initializing a source."""
    from hyperresearch.models.x_evidence import load_schema, schema_uri
    _execute(lambda: {"kind": kind, "schema_id": schema_uri(kind), "schema": load_schema(kind)}, json_output)


@app.command("plan")
def plan(file: Path = typer.Option(..., "--file", exists=True, dir_okay=False),
         dry_run: bool = typer.Option(False, "--dry-run"),
         json_output: bool = typer.Option(False, "--json", "-j")) -> None:
    """Compile a versioned proposal. Compilation never authorizes a read or spend."""
    def action():
        from hyperresearch.core.x_evidence import EvidenceStore
        from hyperresearch.core.x_plans import prepare_plan
        from hyperresearch.models.x_evidence import plan_digest
        proposal = prepare_plan(_payload(file))
        result = {"plan": proposal, "plan_digest": plan_digest(proposal),
                  "authority": "proposal-not-approved", "source_requests": 0, "model_requests": 0}
        if not dry_run:
            result["plan_ref"] = EvidenceStore(_vault().root).put_record("monitor-plan", proposal)
        return result
    _execute(action, json_output)


@app.command("collect")
def collect(scope: Path = typer.Option(..., "--scope", exists=True, dir_okay=False),
            json_output: bool = typer.Option(False, "--json", "-j")) -> None:
    """Execute one exact source scope; commit partial receipts before indexing."""
    def action():
        from hyperresearch.core.x_evidence import EvidenceStore
        from hyperresearch.core.x_monitor import collect_scope
        vault = _vault()
        store = EvidenceStore(vault.root)
        request = _payload(scope)
        proposal = store.get_record(request["plan_ref"]["artifact_ref"], "monitor-plan")
        return asyncio.run(collect_scope(vault, proposal, request))
    _execute(action, json_output)


@app.command("resume")
def resume(receipt: str = typer.Option(..., "--receipt"),
           json_output: bool = typer.Option(False, "--json", "-j")) -> None:
    """Recover an original operation. Expiry cannot renew its source scope."""
    def action():
        from hyperresearch.core.x_evidence import EvidenceStore
        from hyperresearch.core.x_monitor import resume_receipt
        vault = _vault()
        store = EvidenceStore(vault.root)
        ref = _reference(store, receipt, "source-receipt")
        return asyncio.run(resume_receipt(vault, ref))
    _execute(action, json_output)


@app.command("monitor")
def monitor(plan: str | None = typer.Option(None, "--plan"),
            approval: str | None = typer.Option(None, "--approval"),
            resume: str | None = typer.Option(None, "--resume"),
            monitor_id: str | None = typer.Option(None, "--monitor"),
            stop_after: str | None = typer.Option(None, "--stop-after"),
            json_output: bool = typer.Option(False, "--json", "-j")) -> None:
    """Run or resume a finite monitor; durable counters/deadline are never reset."""
    def action():
        from hyperresearch.core.x_evidence import EvidenceStore
        from hyperresearch.core.x_monitor import (
            MonitorRunner,
            load_session,
            new_session,
            session_plan,
        )
        from hyperresearch.core.x_plans import parse_duration
        vault = _vault()
        store = EvidenceStore(vault.root)
        if resume:
            if plan is not None or monitor_id is not None or stop_after is not None:
                raise ValueError("Resume preserves the original plan, monitor identity and deadline")
            session, _ = load_session(store, resume)
            proposal, _ = session_plan(store, session)
        else:
            if plan is None:
                raise ValueError("A compiled --plan is required")
            proposal, _ = _plan(store, plan)
            session = new_session(store, proposal, monitor_id=monitor_id,
                                  stop_after=parse_duration(stop_after) if stop_after else None)
        return asyncio.run(MonitorRunner(vault, proposal, session, approval_ref=approval).run(resume=bool(resume)))
    _execute(action, json_output)


@app.command("status")
def status(monitor: str = typer.Option(..., "--monitor"),
           json_output: bool = typer.Option(False, "--json", "-j")) -> None:
    """Inspect durable source, backlog, budget and analytics state without dispatch."""
    def action():
        from hyperresearch.core.x_evidence import EvidenceStore
        from hyperresearch.core.x_monitor import status_monitor
        return status_monitor(EvidenceStore(_vault().root), monitor)
    _execute(action, json_output)


@app.command("stop")
def stop(monitor: str = typer.Option(..., "--monitor"),
         json_output: bool = typer.Option(False, "--json", "-j")) -> None:
    """Request the owned monitor stop; never kill a shared daemon or browser."""
    def action():
        from hyperresearch.core.x_evidence import EvidenceStore
        from hyperresearch.core.x_monitor import stop_monitor
        return stop_monitor(EvidenceStore(_vault().root), monitor)
    _execute(action, json_output, state_is_outcome=False)


@app.command("classify")
def classify(capture_set: str = typer.Option(..., "--capture-set"),
             classifier: str = typer.Option(..., "--classifier"),
             stop_after: str | None = typer.Option(None, "--stop-after"),
             json_output: bool = typer.Option(False, "--json", "-j")) -> None:
    """Analyze existing captures with independent paid/export permission; no X read."""
    def action():
        from hyperresearch.core.x_evidence import EvidenceStore
        from hyperresearch.core.x_monitor import classify_captures
        from hyperresearch.core.x_plans import parse_duration
        vault = _vault()
        store = EvidenceStore(vault.root)
        proposal, _ = _plan(store, classifier)
        selected = _payload(capture_set)
        if isinstance(selected, dict):
            selected = selected.get("capture_refs", selected.get("source_frontier"))
        if not isinstance(selected, list):
            raise ValueError("Capture set must contain a bounded list of canonical capture references")
        refs = [_reference(store, item, "source-capture") for item in selected]
        return asyncio.run(classify_captures(vault, proposal, refs,
                          stop_after_s=parse_duration(stop_after) if stop_after else None))
    _execute(action, json_output)


@app.command("replay")
def replay(monitor: str = typer.Option(..., "--monitor"),
           policy: Path | None = typer.Option(None, "--policy", exists=True, dir_okay=False),
           evaluation_time: str | None = typer.Option(None, "--evaluation-time"),
           json_output: bool = typer.Option(False, "--json", "-j")) -> None:
    """Produce a separately referenced local replay. No browser/API/SDK calls."""
    def action():
        from hyperresearch.core.x_monitor import replay_monitor
        return replay_monitor(_vault(), monitor, policy=_payload(policy) if policy else None,
                              evaluation_time=evaluation_time)
    _execute(action, json_output)


@app.command("analytics")
def analytics(monitor: str = typer.Option(..., "--monitor"),
              window: str = typer.Option("5m", "--window"),
              evaluation_time: str | None = typer.Option(None, "--evaluation-time"),
              json_output: bool = typer.Option(False, "--json", "-j")) -> None:
    """Reduce canonical evidence for one explicit window, including correction lineage."""
    def action():
        from hyperresearch.core.x_monitor import reduce_monitor
        from hyperresearch.core.x_plans import parse_duration
        return reduce_monitor(_vault(), monitor, window_s=parse_duration(window),
                              evaluation_time=evaluation_time)
    _execute(action, json_output)


@app.command("export")
def export(monitor: str = typer.Option(..., "--monitor"),
           path: Path = typer.Option(..., "--path"),
           json_output: bool = typer.Option(False, "--json", "-j")) -> None:
    """Export exactly the monitor's declared evidence closure for local replay."""
    def action():
        from hyperresearch.core.x_evidence import EvidenceStore
        from hyperresearch.core.x_monitor import load_session
        store = EvidenceStore(_vault().root)
        _, ref = load_session(store, monitor)
        from hyperresearch.models.x_evidence import canonical_bytes
        result = store.export_closure([ref])
        if path.exists() or path.is_symlink():
            raise ValueError("Export destination already exists; choose a new path")
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("xb") as destination:
            destination.write(canonical_bytes(result))
        return {"path": str(path), "session_ref": ref, "artifacts": len(result["artifacts"]), "external_calls": 0}
    _execute(action, json_output)


@app.command("import")
def import_evidence(path: Path = typer.Option(..., "--path", exists=True),
                    json_output: bool = typer.Option(False, "--json", "-j")) -> None:
    """Import archived evidence without granting imported HTTP claims live-origin trust."""
    def action():
        from hyperresearch.core.x_evidence import EvidenceStore
        result = EvidenceStore(_vault().root).import_closure(_payload(path))
        return {"imported": result, "external_calls": 0, "authority": "unverified-unless-independently-admitted"}
    _execute(action, json_output)


@app.command("install-skill")
def install_skill(platform: str = typer.Option("omp", "--platform"),
                  scope: str = typer.Option("user", "--scope"),
                  dry_run: bool = typer.Option(False, "--dry-run"),
                  json_output: bool = typer.Option(False, "--json", "-j")) -> None:
    """Deliver only the monitor skill; preserve custom/symlinked destinations."""
    def action():
        from hyperresearch.core.x_skills import install_monitor_skill
        return install_monitor_skill(platform=platform, scope=scope,
                                     root=Path.cwd(), dry_run=dry_run)
    _execute(action, json_output)
