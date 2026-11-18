"""One bounded native source lane with durable analytics and independent billing.

Monitor locks protect monitor checkpoint writers, not browser execution. Only native
receipts can settle a source operation. Canonical session snapshots are immutable;
current.json is a checksum-checked pointer and SQLite is never runtime authority.
"""
from __future__ import annotations

import asyncio
import contextlib
import copy
import fcntl
import json
import os
import threading
import uuid
from datetime import datetime, timedelta
from decimal import Decimal
from pathlib import Path

from hyperresearch.core.vault import validate_run_tag
from hyperresearch.core.x_artifacts import artifact_path, atomic_write
from hyperresearch.core.x_authority import (
    ApprovalError,
    authority_snapshot,
    authorize_source_scope,
    parse_time,
    read_host_trust,
    resolve_approval,
    timestamp,
    utc_now,
    validate_snapshot_anchor,
    verify_observation_admission,
)
from hyperresearch.core.x_evidence import EvidenceStore
from hyperresearch.core.x_plans import validate_plan
from hyperresearch.models.x_evidence import (
    canonical_bytes,
    plan_digest,
    record_digest,
    validate_record,
)


class MonitorError(RuntimeError):
    def __init__(self, code: str):
        self.code = code
        super().__init__(code)


def _cell(*, decimal: bool = False) -> dict:
    zero = "0" if decimal else 0
    return {"reserved": zero, "actual": zero, "unknown": zero}


def empty_accounting() -> dict:
    return {"source": {key: _cell() for key in ("requests", "pages", "captures", "operations")},
            "analysis": {"requests": _cell(), "tokens": _cell(), "cost_usd": _cell(decimal=True)},
            "observations": {"requests": _cell()}}


def _total(cell: dict) -> Decimal:
    return sum((Decimal(str(cell[key])) for key in ("reserved", "actual", "unknown")), Decimal(0))


def _change(cell: dict, field: str, amount) -> None:
    value = Decimal(str(cell[field])) + Decimal(str(amount))
    if value < 0:
        raise MonitorError("accounting_underflow")
    cell[field] = format(value, "f") if isinstance(cell[field], str) else int(value)


def _add_refs(target: list[dict], refs) -> None:
    seen = {(ref["path"], ref["sha256"]) for ref in target}
    for ref in refs:
        key = ref["path"], ref["sha256"]
        if key not in seen:
            target.append(ref)
            seen.add(key)


def _latest_sessions(store: EvidenceStore) -> list[dict]:
    latest = {}
    for ref in store.list_records("monitor-session"):
        value = store.get_record(ref, "monitor-session")
        key = value["monitor_id"], value["session_id"]
        old = latest.get(key)
        if old is not None and old["revision"] == value["revision"] and canonical_bytes(old) != canonical_bytes(value):
            raise MonitorError("conflicting_checkpoint_revision")
        if old is None or old["revision"] < value["revision"]:
            latest[key] = value
    return list(latest.values())


def _monitor_path(store: EvidenceStore, monitor_id: str, name: str) -> Path:
    validate_run_tag(monitor_id)
    return artifact_path(store.root, f"monitors/{monitor_id}/{name}")


@contextlib.contextmanager
def _file_lock(path: Path, *, blocking: bool = True):
    path.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(path, os.O_RDWR | os.O_CREAT | os.O_CLOEXEC | os.O_NOFOLLOW, 0o600)
    try:
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | (0 if blocking else fcntl.LOCK_NB))
        except BlockingIOError as exc:
            raise MonitorError("monitor_already_running") from exc
        yield
    finally:
        os.close(fd)


def load_session(store: EvidenceStore, monitor: str | dict) -> tuple[dict, dict]:
    if isinstance(monitor, dict):
        ref = monitor
    else:
        pointer_path = _monitor_path(store, monitor, "current.json")
        if pointer_path.is_file():
            pointer = validate_record("monitor-pointer", json.loads(pointer_path.read_bytes()))
            if pointer["monitor_id"] != monitor:
                raise MonitorError("monitor_pointer_identity_mismatch")
            ref = pointer["session_ref"]
        else:
            matches = [(value, ref) for ref in store.list_records("monitor-session")
                       if (value := store.get_record(ref, "monitor-session"))["monitor_id"] == monitor]
            if not matches:
                raise MonitorError("monitor_not_found")
            matches.sort(key=lambda pair: pair[0]["revision"])
            ref = matches[-1][1]
    return store.get_record(ref, "monitor-session"), ref


def session_plan(store: EvidenceStore, session: dict) -> tuple[dict, dict]:
    reference = session["plan_ref"]
    ref = reference.get("artifact_ref")
    if ref is None:
        matches = [item for item in store.list_records("monitor-plan")
                   if plan_digest(store.get_record(item, "monitor-plan")) == reference["digest"]]
        if len(matches) != 1:
            raise MonitorError("session_plan_artifact_missing_or_ambiguous")
        ref = matches[0]
    plan = validate_plan(store.get_record(ref, "monitor-plan"))
    if reference["plan_id"] != plan["plan_id"] or reference["revision"] != plan["revision"] or reference["digest"] != plan_digest(plan):
        raise MonitorError("session_plan_binding_mismatch")
    return plan, ref


def new_session(store: EvidenceStore, plan: dict, *, monitor_id: str | None = None,
                stop_after: int | None = None, now: datetime | None = None) -> dict:
    plan = validate_plan(plan)
    now = now or utc_now()
    plan_ref = store.put_record("monitor-plan", plan)
    duration = plan["limits"]["session"]["max_elapsed_s"]
    if stop_after is not None:
        if type(stop_after) is not int or stop_after < 1:
            raise MonitorError("invalid_monitor_duration")
        duration = min(duration, stop_after)
    identity = monitor_id or f"xmon-{uuid.uuid4().hex}"
    validate_run_tag(identity)
    return validate_record("monitor-session", {
        "schema_version": 1, "monitor_id": identity, "session_id": f"xsession-{uuid.uuid4().hex}",
        "revision": 1, "state": "stopped",
        "plan_ref": {"plan_id": plan["plan_id"], "revision": plan["revision"], "digest": plan_digest(plan), "artifact_ref": plan_ref},
        "approval_refs": [], "started_at": timestamp(now), "expires_at": timestamp(now + timedelta(seconds=duration)),
        "accounting": empty_accounting(), "next_query_index": 0,
        "query_state": [{"query_id": query["id"], "revision": query["revision"], "next_due_at": timestamp(now),
                         "last_operation_id": None, "last_receipt_ref": None, "last_started_at": None}
                        for query in plan["queries"]],
        "source_frontier": [], "analysis_frontier": [], "observation_frontier": [],
        "deferred_work": [], "output_refs": [], "active_operation": None, "coverage_gaps": [],
        "policy_refs": [],
        "model_request_ids": [], "completed_job_ids": [],
    })


def stop_monitor(store: EvidenceStore, monitor_id: str, *, reason: str = "user-request") -> dict:
    session, _ = load_session(store, monitor_id)
    control = validate_record("monitor-control", {"schema_version": 1, "monitor_id": monitor_id,
               "requested_at": timestamp(utc_now()), "reason": reason})
    atomic_write(_monitor_path(store, monitor_id, "stop.json"), canonical_bytes(control))
    return {"monitor_id": monitor_id, "stop_requested": True, "state": session["state"],
            "execution_settled": session["active_operation"] is None,
            "source_lease_released": False}


def status_monitor(store: EvidenceStore, monitor_id: str) -> dict:
    session, ref = load_session(store, monitor_id)
    plan, _ = session_plan(store, session)
    now = utc_now()
    active = session["active_operation"]
    return {"monitor_id": monitor_id, "session_ref": ref, "session": session,
            "source": {"backend": "opencli", "owner": plan["source"]["owner"], "profile": plan["source"]["profile"],
                       "execution": active["state"] if active else "no-active-operation",
                       "coverage_gap_count": len(session["coverage_gaps"])},
            "backlog": {"source_lag_s": {query["query_id"]: max(0, (now - parse_time(query["next_due_at"])).total_seconds()) for query in session["query_state"]},
                        "deferred": {state: sum(item["state"] == state for item in session["deferred_work"]) for state in ("queued", "running", "unknown")}},
            "stop_requested": _monitor_path(store, monitor_id, "stop.json").is_file(),
            "deadline_expired": now >= parse_time(session["expires_at"]),
            "analysis_enabled": plan["analysis"]["enabled"], "observational_only": True}


class MonitorRunner:
    """Own one monitor writer, one native operation and at most four SDK workers."""

    def __init__(self, vault, plan: dict, session: dict, *, approval_ref: str | None = None,
                 provider=None, classifier_factory=None, clock=utc_now):
        self.vault, self.store = vault, EvidenceStore(vault.root)
        self.plan, self.session = validate_plan(plan), validate_record("monitor-session", session)
        self.approval_ref, self.clock = approval_ref, clock
        if self.session["plan_ref"]["digest"] != plan_digest(self.plan):
            raise MonitorError("session_plan_binding_mismatch")
        self._guard = threading.RLock()
        self._cancel = threading.Event()
        self._admissions: dict[str, dict] = {}
        self._model_reservations: dict[str, dict] = {}
        self._live_observation_refs: list[dict] = []
        self._owned_observation_proofs: set[tuple[str, str]] = set()
        self._owned_observation_refs: list[dict] = []
        self._observation_reservations: dict[str, dict] = {}
        self._materialization_results: dict[str, dict] = {}
        self._projection_refs: list[dict] = []
        self._queue: asyncio.Queue | None = None
        self._queued: set[str] = set()
        self._loop = None
        self._session_ref = None
        self._classifier_factory = classifier_factory
        if provider is None:
            from hyperresearch.web.opencli_provider import OpenCLIProvider
            provider = OpenCLIProvider(vault, source_authorizer=self._source_authorizer)
        self.provider = provider

    def checkpoint(self, *, pid: int | None = None) -> dict:
        with self._guard:
            self.session["revision"] += 1
            self.session = validate_record("monitor-session", self.session)
            self._session_ref = self.store.put_record("monitor-session", self.session)
            pointer = validate_record("monitor-pointer", {"schema_version": 1,
                       "monitor_id": self.session["monitor_id"], "session_ref": self._session_ref,
                       "pid": pid, "updated_at": timestamp(self.clock())})
            atomic_write(_monitor_path(self.store, self.session["monitor_id"], "current.json"), canonical_bytes(pointer))
            return self._session_ref

    def _stopping(self) -> bool:
        path = _monitor_path(self.store, self.session["monitor_id"], "stop.json")
        if not path.is_file():
            return self._cancel.is_set()
        control = validate_record("monitor-control", json.loads(path.read_bytes()))
        if control["monitor_id"] != self.session["monitor_id"]:
            raise MonitorError("stop_control_identity_mismatch")
        self._cancel.set()
        return True

    def _admit(self, admission: dict) -> None:
        ref = admission["approval_ref"]
        if ref not in self.session["approval_refs"]:
            self.session["approval_refs"].append(ref)
        self._admissions[admission["grant_digest"]] = admission

    def _source_authorizer(self, scope: dict) -> dict:
        if self._stopping():
            raise ApprovalError("monitor_stop_requested")
        authorized = authorize_source_scope(self.vault, scope, plan=self.plan, approval_ref=self.approval_ref)
        admitted = resolve_approval(self.vault, self.plan, "source." + scope["operation"],
                                    approval_ref=authorized["approval_ref"], request=authorized, now=self.clock())
        with self._guard:
            self._admit(admitted)
            self.checkpoint(pid=os.getpid())
        return authorized

    def _grant_lock(self, grant: dict):
        from hyperresearch.core.x_budget import GrantBudget
        return GrantBudget(grant).locked()

    def _request_seen(self, request_id: str) -> bool:
        if request_id in self._model_reservations:
            return True
        for ref in self.store.list_records("analysis-annotation"):
            reservation = self.store.get_record(ref, "analysis-annotation")["reservation"]
            if reservation.get("request_id") == request_id and reservation.get("attempts", 0):
                return True
        for session in _latest_sessions(self.store):
            if request_id in session.get("model_request_ids", []):
                return True
            if session["session_id"] == self.session["session_id"]:
                continue
            for item in session["deferred_work"]:
                if item["kind"] == "annotation" and item["state"] in {"running", "unknown"} and item["ref"]:
                    job = json.loads(self.store.read_blob(item["ref"]))
                    if job.get("reservation", {}).get("request_id") == request_id:
                        return True
        return False

    def authorize_request(self, request: dict) -> dict:
        """Persist spend before a supplied-data SDK or declared read-only API call."""
        if self._stopping() or self.clock() >= parse_time(self.session["expires_at"]):
            raise ApprovalError("monitor_dispatch_deadline_or_stop")
        request = copy.deepcopy(request)
        action = request.get("action")
        if action not in {"model.classify", "observations.read"}:
            raise ApprovalError("unknown_analysis_operation")
        if action == "observations.read":
            self._resolve_observation_inputs(request)
            request.setdefault("request_id", f"observation-{uuid.uuid4().hex}")
        else:
            request["request_id"] = (request.get("reservation") or {}).get("request_id")
        admitted = resolve_approval(self.vault, self.plan, action, request=request, now=self.clock())
        with self._grant_lock(admitted) as ledger, self._guard:
            # Revalidate under the shared per-grant billing lock, never reuse a grant result.
            admitted = resolve_approval(self.vault, self.plan, action, approval_ref=admitted["approval_ref"], request=request, now=self.clock())
            if action == "model.classify":
                if not self.vault.config.x.analysis_enabled:
                    raise ApprovalError("configured_model_analysis_disabled")
                reserve = request["reservation"]
                identity = reserve.get("request_id")
                if not identity or identity in ledger.state["model_request_ids"] or self._request_seen(identity):
                    raise ApprovalError("model_request_already_reserved_or_attempted")
                amounts = {"requests": reserve["model_requests"], "tokens": reserve["model_tokens"], "cost_usd": reserve["model_cost_usd"]}
                limits = self.plan["limits"]["analysis"]
                config = self.vault.config.x
                ceilings = {"requests": min(limits["max_requests"], config.max_model_requests),
                            "tokens": min(limits["max_tokens"], config.max_model_tokens),
                            "cost_usd": min(Decimal(limits["max_cost_usd"]), Decimal(config.max_model_cost_usd))}
                for key, amount in amounts.items():
                    if _total(self.session["accounting"]["analysis"][key]) + Decimal(str(amount)) > Decimal(str(ceilings[key])):
                        raise ApprovalError("session_model_budget_exhausted")
                    grant_key = {"requests": "model_requests", "tokens": "model_tokens", "cost_usd": "model_cost_usd"}[key]
                    if ledger.total("analysis", key) + Decimal(str(amount)) > Decimal(str(admitted["budget_ceilings"][grant_key])):
                        raise ApprovalError("grant_model_budget_exhausted")
                self._admit(admitted)
                self.session.setdefault("model_request_ids", []).append(identity)
                ledger.state["model_request_ids"].append(identity)
                for key, amount in amounts.items():
                    _change(self.session["accounting"]["analysis"][key], "reserved", amount)
                    ledger.change("analysis", key, "reserved", amount)
                self._model_reservations[identity] = {"amounts": amounts, "grant": admitted}
            else:
                cell = self.session["accounting"]["observations"]["requests"]
                if request["timeout_s"] > self.vault.config.x.observation_timeout_s or _total(cell) + 1 > self.vault.config.x.max_observation_requests:
                    raise ApprovalError("configured_observation_budget_exhausted")
                if ledger.total("observations", "requests") + 1 > admitted["budget_ceilings"].get("observation_requests", 0):
                    raise ApprovalError("grant_observation_budget_exhausted")
                self._admit(admitted)
                # Each callback is one dispatched HTTP attempt; if no reply follows its
                # completion remains unknown, never silently credited or retried.
                _change(cell, "unknown", 1)
                identity = request["request_id"]
                if identity in ledger.state["observation_request_ids"]:
                    raise ApprovalError("observation_request_already_reserved")
                ledger.state["observation_request_ids"].append(identity)
                ledger.change("observations", "requests", "unknown", 1)
                self._observation_reservations[identity] = admitted
                admitted["request_id"] = request["request_id"]
            ledger.save()
            admitted["deadline_at"] = timestamp(min(parse_time(self.session["expires_at"]), parse_time(admitted["payload"]["expires_at"])))
            self._snapshot()
            self.checkpoint(pid=os.getpid())
            admitted["session_ref"] = self._session_ref
            admitted["request_id"] = request["request_id"]
            return admitted

    def _resolve_observation_inputs(self, request: dict) -> None:
        trust = read_host_trust(self.vault.config.x.trust_store)
        proofs = []
        for ref in request.get("proof_refs", []):
            if (ref["path"], ref["sha256"]) not in self._owned_observation_proofs and not self._archived_proof_admitted(ref):
                raise ApprovalError("descendant_proof_origin_not_admitted")
            envelope = json.loads(self.store.read_blob(ref))
            admission = json.loads(self.store.read_blob(envelope["admission_ref"]))
            proof = {"request": envelope["request"], "admission": admission, "response": envelope["response"]}
            verify_observation_admission(self.plan, proof["request"], admission,
                trusted_digest=admission["trust"]["trust_store_digest"], trusted_keys=trust["keys"])
            proofs.append(proof)
        request["proof_rows"] = proofs
        if request.get("lead_capture_ref"):
            ref = request["lead_capture_ref"]
            closure = self.store.resolve_closure(self.session["source_frontier"])
            if not any(item.get("ref") == ref and item.get("kind") == "source-capture" for item in closure):
                raise ApprovalError("lead_not_in_admitted_source_frontier")
            request["lead_capture"] = self.store.get_record(ref, "source-capture")

    def _archived_proof_admitted(self, ref: dict) -> bool:
        snapshot_ref = self.session.get("authority_snapshot_ref")
        if not snapshot_ref:
            return False
        trust = read_host_trust(self.vault.config.x.trust_store)
        if snapshot_ref["sha256"] not in trust.get("admitted_snapshot_digests", []):
            return False
        snapshot = validate_snapshot_anchor(self.vault, json.loads(self.store.read_blob(snapshot_ref)))
        if ref in snapshot["evidence_refs"]:
            return True
        for observation_ref in snapshot["evidence_refs"]:
            try:
                observation = self.store.get_record(observation_ref, "verified-observation")
            except ValueError:
                continue
            if ref in observation["source"]["evidence_refs"]:
                return True
        return False


    def _snapshot(self) -> None:
        if not self._admissions:
            return
        evidence_refs = list(self._live_observation_refs)
        _add_refs(evidence_refs, self._owned_observation_refs)
        previous_ref = self.session.get("authority_snapshot_ref")
        if previous_ref:
            trust = read_host_trust(self.vault.config.x.trust_store)
            if previous_ref["sha256"] in trust.get("admitted_snapshot_digests", []):
                previous = validate_snapshot_anchor(self.vault, json.loads(self.store.read_blob(previous_ref)))
                _add_refs(evidence_refs, previous.get("evidence_refs", []))
        snapshot = authority_snapshot(self.vault, list(self._admissions.values()), evidence_refs=evidence_refs)
        self.session["authority_snapshot_ref"] = self.store.put_blob(canonical_bytes(snapshot))

    def _analytics_engine(self):
        from hyperresearch.core.x_analytics import AnalyticsEngine
        trusted_keys, digest, origin = None, None, list(self._live_observation_refs)
        snapshot_ref = self.session.get("authority_snapshot_ref")
        if snapshot_ref:
            try:
                snapshot = validate_snapshot_anchor(self.vault, json.loads(self.store.read_blob(snapshot_ref)))
                trust = read_host_trust(self.vault.config.x.trust_store)
                trusted_keys, digest = snapshot["trusted_keys"], snapshot["trust_store_digest"]
                if snapshot_ref["sha256"] in trust.get("admitted_snapshot_digests", []):
                    _add_refs(origin, snapshot.get("evidence_refs", []))
            except (ApprovalError, ValueError):
                # Local archive inspection is legal without a host grant. Imported
                # HTTP facts then remain observed/unverified, not invented truths.
                trusted_keys, digest = None, None
        return AnalyticsEngine(self.store, trusted_keys=trusted_keys, trusted_digest=digest,
                               trusted_observation_refs=origin)

    def publish(self, *, evaluation_time: datetime | str | None = None, policy: dict | None = None) -> list[dict]:
        with self._guard:
            evaluation = evaluation_time or self.clock()
            engine = self._analytics_engine()
            outputs = []
            for window in self.plan["schedule"]["windows_s"]:
                _add_refs(outputs, engine.reduce(self.plan, self.session, window_s=window,
                          evaluation_time=evaluation, policy=policy))
            _add_refs(self.session["output_refs"], outputs)
            for ref in outputs:
                event = self.store.get_record(ref, "analytics-event")
                identity = record_digest(event)
                for format_name in self.plan["outputs"]["formats"]:
                    suffix = ".json" if format_name == "json" else ".md"
                    relative = f"{self.plan['outputs']['path']}/{identity}{suffix}"
                    content = canonical_bytes(event) if format_name == "json" else (
                        "# X observational analytics\n\n```json\n"
                        + json.dumps(event, ensure_ascii=True, indent=2, allow_nan=False)
                        + "\n```\n").encode("utf-8")
                    path = artifact_path(self.store.root, relative)
                    atomic_write(path, content, immutable=True)
                    _add_refs(self._projection_refs, [self.store.ref_from_path(path)])
            if self.plan["outputs"]["materialize_notes"]:
                capture_refs = []
                for ref in outputs:
                    _add_refs(capture_refs, self.store.get_record(ref, "analytics-event")["input_refs"]["capture_refs"])
                for ref in capture_refs:
                    materialized = self.store.materialize_capture(ref)
                    self._materialization_results[materialized["note_id"]] = materialized
            self.checkpoint(pid=os.getpid() if self.session["state"] == "running" else None)
            return outputs

    def _job(self, capture_ref: dict) -> dict | None:
        capture = self.store.get_record(capture_ref, "source-capture")
        if capture["role"] != "primary":
            return None
        context, versions = [], []
        for relation in capture["relationships"]:
            if relation["delivery"] == "delivered" and relation["capture_ref"]:
                ref = self.store.resolve_ref(relation["capture_ref"], origin_ref=capture_ref)
                try:
                    normalized = self.store.get_record(ref, "source-capture")
                except ValueError:
                    # Raw delivered context is retained, not model-ready. Its absence
                    # from this list makes the typed classifier guard incomplete.
                    continue
                _add_refs(context, [ref])
                versions.append({key: normalized[key] for key in
                                ("post_id", "revision", "text", "author", "event_type")})
        relationships = [{key: relation[key] for key in ("kind", "target_post_id", "delivery")}
                         for relation in capture["relationships"]]
        key = record_digest({"post_id": capture["post_id"], "revision": capture["revision"],
             "text": capture["text"], "author": capture["author"], "event_type": capture["event_type"],
             "query_id": capture["occurrence"]["query_id"], "query_revision": capture["occurrence"]["query_revision"],
             "relationships": relationships, "context": sorted(versions, key=lambda item: item["post_id"]),
             "analysis": self.plan["analysis"]})
        return {"id": f"analysis-{key}", "capture_ref": capture_ref, "context_refs": context}


    def _queue_captures(self, capture_refs) -> None:
        if not self.plan["analysis"]["enabled"] or not self.vault.config.x.analysis_enabled:
            return
        existing = {item["id"] for item in self.session["deferred_work"]} | set(self.session.get("completed_job_ids", []))
        for ref in capture_refs:
            job = self._job(ref)
            if job is None or job["id"] in existing:
                continue
            job_ref = self.store.put_blob(canonical_bytes(job))
            self.session["deferred_work"].append({"id": job["id"], "kind": "annotation",
                    "operation_id": None, "ref": job_ref, "state": "queued"})
            existing.add(job["id"])
        if self._loop is not None:
            self._loop.call_soon_threadsafe(self._refill_queue)

    def _refill_queue(self) -> None:
        if self._queue is None or self._stopping():
            return
        with self._guard:
            for work in self.session["deferred_work"]:
                if work["kind"] == "annotation" and work["state"] == "queued" and work["id"] not in self._queued:
                    if self._queue.full():
                        break
                    self._queue.put_nowait(work["id"])
                    self._queued.add(work["id"])

    def _accept_page(self, result: dict) -> None:
        with self._guard:
            _add_refs(self.session["source_frontier"], result.get("page_refs", []))
            _add_refs(self.session["source_frontier"], result.get("capture_refs", []))
            if self.plan["outputs"]["materialize_notes"]:
                receipt_ref = result.get("final_receipt_ref") or (result.get("page_refs") or [None])[-1]
                for ref in result.get("capture_refs", []):
                    materialized = self.store.materialize_capture(ref, receipt_ref=receipt_ref)
                    self._materialization_results[materialized["note_id"]] = materialized
            self._queue_captures(result.get("capture_refs", []))
            active = self.session["active_operation"]
            if active and result.get("scope"):
                active["scope_ref"] = self.store.put_blob(canonical_bytes(result["scope"]))
            self.publish()

    def _source_amounts(self, scope: dict) -> dict:
        limits = scope["limits"]
        return {"requests": limits["max_requests"], "pages": limits["max_pages"],
                "captures": limits["max_captures"], "operations": 1}

    def _reserve_source(self, scope: dict) -> None:
        amounts = self._source_amounts(scope)
        limits = self.plan["limits"]["session"]
        for key, amount in amounts.items():
            if _total(self.session["accounting"]["source"][key]) + amount > limits["max_" + key]:
                raise MonitorError("source_session_budget_exhausted")
        if _total(self.session["accounting"]["source"]["requests"]) + amounts["requests"] > self.vault.config.x.max_session_source_requests:
            raise MonitorError("configured_source_session_budget_exhausted")
        for key, amount in amounts.items():
            _change(self.session["accounting"]["source"][key], "reserved", amount)
        self.session["active_operation"] = {"operation_id": scope["operation_id"],
                "scope_ref": self.store.put_blob(canonical_bytes(scope)), "receipt_ref": None,
                "state": "reserved", "started_at": scope["started_at"], "deadline": scope["deadline"]}

    def _source_result(self, result: dict) -> None:
        with self._guard:
            self._accept_page(result)
            _add_refs(self.session["source_frontier"], result.get("receipt_refs", []))
            active = self.session["active_operation"]
            if active is None:
                return
            scope = result.get("scope") or json.loads(self.store.read_blob(active["scope_ref"]))
            ref = result.get("final_receipt_ref")
            receipt = self.store.get_record(ref, "source-receipt") if ref else None
            if receipt and receipt["operation_id"] != active["operation_id"]:
                raise MonitorError("native_operation_identity_mismatch")
            prior = "unknown" if active["state"] == "unknown" else "reserved"
            amounts = self._source_amounts(scope)
            settled = receipt is not None and receipt["execution"]["state"] in {"settled", "aborted", "not-started"}
            if settled:
                names = {"requests": "request_count", "pages": "page_count", "captures": "capture_count"}
                for key, reserved in amounts.items():
                    cell = self.session["accounting"]["source"][key]
                    _change(cell, prior, -reserved)
                    actual = 1 if key == "operations" else receipt["counters"][names[key]]
                    if actual is None:
                        _change(cell, "unknown", reserved)
                    elif actual > reserved:
                        _change(cell, "actual", actual)
                        self.session["state"] = "blocked"
                        self.session["stop_reason"] = "native_counter_exceeded_reserved_limit"
                    else:
                        _change(cell, "actual", actual)
                self.session["active_operation"] = None
            else:
                if prior == "reserved":
                    for key, reserved in amounts.items():
                        _change(self.session["accounting"]["source"][key], "reserved", -reserved)
                        _change(self.session["accounting"]["source"][key], "unknown", reserved)
                active["state"] = "unknown"
                active["receipt_ref"] = ref or (result.get("page_refs") or [None])[-1]
                self.session["state"] = "blocked"
                self.session["stop_reason"] = "native_execution_unknown"
            query = next((item for item in self.session["query_state"] if item["last_operation_id"] == scope["operation_id"]), None)
            if query:
                query["last_receipt_ref"] = ref or (result.get("page_refs") or [None])[-1]
            self.session["coverage_gaps"] = [gap for gap in self.session["coverage_gaps"] if gap["scope_id"] != scope["scope_id"]]
            if receipt and receipt["coverage"]["state"] != "complete":
                gap = {"scope_id": scope["scope_id"], "query_id": (scope["query_ref"] or {}).get("query_id"),
                       "state": "unknown" if receipt["coverage"]["state"] in {"unknown", "not-started"} else "partial",
                       "start": receipt["coverage"]["interval_start"], "end": receipt["coverage"]["interval_end"],
                       "receipt_ref": ref, "reasons": receipt["coverage"]["reasons"] or [receipt["stop_reason"]]}
                self.session["coverage_gaps"].append(gap)
            self.publish()

    def _next_query(self) -> int | None:
        count, now = len(self.session["query_state"]), self.clock()
        for offset in range(count):
            index = (self.session["next_query_index"] + offset) % count
            if parse_time(self.session["query_state"][index]["next_due_at"]) <= now:
                return index
        return None

    def _scope(self, index: int) -> dict:
        now = self.clock()
        query = self.plan["queries"][index]
        limits = copy.deepcopy(self.plan["limits"]["poll"])
        deadline = min(now + timedelta(seconds=limits["max_elapsed_s"]), parse_time(self.session["expires_at"]))
        admission = resolve_approval(self.vault, self.plan, "source.search", approval_ref=self.approval_ref, now=now)
        deadline = min(deadline, parse_time(admission["payload"]["expires_at"]))
        self._admit(admission)
        scope = {"schema_version": 1, "operation_id": f"xop-{uuid.uuid4().hex}",
                 "scope_id": "xscope-" + record_digest({"plan": plan_digest(self.plan), "query": query})[:32],
                 "operation": "search", "plan_ref": self.session["plan_ref"],
                 "query_ref": {"query_id": query["id"], "revision": query["revision"]},
                 "owner": self.plan["source"]["owner"], "profile": self.plan["source"]["profile"],
                 "allowed_hosts": self.plan["source"]["allowed_hosts"], "product": "Latest",
                 "expression": query["expression"], "target": None,
                 "started_at": timestamp(now), "deadline": timestamp(deadline), "limits": limits,
                 "interval_start": timestamp(now - timedelta(seconds=self.plan["schedule"]["lookback_s"])),
                 "interval_end": timestamp(now), "approval_ref": admission["approval_ref"]}
        return validate_record("source-scope", scope)

    async def _operation(self, scope: dict, *, resume_ref: dict | None = None) -> None:
        from hyperresearch.web.opencli_provider import NativeSourceError
        with self._guard:
            active = self.session["active_operation"]
            if active["state"] != "unknown":
                active["state"] = "running"
            self.checkpoint(pid=os.getpid())
        future = asyncio.create_task(asyncio.to_thread(self.provider.execute_scope, scope,
                    resume_ref=resume_ref, on_page=self._accept_page, cancel_event=self._cancel))
        cancelled = False
        while not future.done():
            try:
                self._stopping()
                await asyncio.sleep(0.05)
            except asyncio.CancelledError:
                self._cancel.set()
                cancelled = True
        try:
            result = await asyncio.shield(future)
        except NativeSourceError as exc:
            if exc.result:
                self._source_result(exc.result)
            else:
                # Policy/refusal before native admission confirms zero local requests;
                # an arbitrary executor failure does NOT confirm browser settlement.
                if exc.code in {"X_SOURCE_POLICY", "X_SOURCE_SCOPE", "X_SOURCE_CAPABILITIES", "X_SOURCE_SCHEMA"} and self.session["active_operation"]["state"] != "unknown":
                    with self._guard:
                        for key, amount in self._source_amounts(scope).items():
                            _change(self.session["accounting"]["source"][key], "reserved", -amount)
                        self.session["active_operation"] = None
                elif self.session["active_operation"]["state"] != "unknown":
                    with self._guard:
                        for key, amount in self._source_amounts(scope).items():
                            _change(self.session["accounting"]["source"][key], "reserved", -amount)
                            _change(self.session["accounting"]["source"][key], "unknown", amount)
                        self.session["active_operation"]["state"] = "unknown"
                self.session["state"], self.session["stop_reason"] = "blocked", exc.code
                self.checkpoint(pid=os.getpid())
            return
        except Exception:
            with self._guard:
                active = self.session["active_operation"]
                if active and active["state"] != "unknown":
                    for key, amount in self._source_amounts(scope).items():
                        _change(self.session["accounting"]["source"][key], "reserved", -amount)
                        _change(self.session["accounting"]["source"][key], "unknown", amount)
                    active["state"] = "unknown"
                self.session["state"], self.session["stop_reason"] = "blocked", "native_executor_failure"
                self.checkpoint(pid=os.getpid())
            raise
        self._source_result(result)
        if cancelled:
            raise asyncio.CancelledError
        if self.session["active_operation"] is None and self.session["state"] == "running":
            await self._observations(result.get("capture_refs", []))

    def _observation_received(self, ref: dict) -> None:
        from hyperresearch.models.x_evidence import validate_definition
        raw = validate_definition("observation-evidence", json.loads(self.store.read_blob(ref)))
        self.store.read_blob(raw["raw_response_ref"])
        admission = json.loads(self.store.read_blob(raw["admission_ref"]))
        identity = admission["request_id"]
        with self._guard:
            reserved = self._observation_reservations.get(identity)
        if reserved is None or reserved["grant_digest"] != admission["grant_digest"]:
            raise ApprovalError("observation_response_not_owned")
        with self._grant_lock(reserved) as ledger, self._guard:
            if self._observation_reservations.pop(identity, None) is None:
                raise ApprovalError("observation_response_already_settled")
            ledger.change("observations", "requests", "unknown", -1)
            ledger.change("observations", "requests", "actual", 1)
            ledger.state["observation_request_ids"].remove(identity)
            ledger.save()
            _change(self.session["accounting"]["observations"]["requests"], "unknown", -1)
            _change(self.session["accounting"]["observations"]["requests"], "actual", 1)
            self._owned_observation_proofs.add((ref["path"], ref["sha256"]))
            _add_refs(self._owned_observation_refs, [ref])
            self._snapshot()
            self.checkpoint(pid=os.getpid())

    def _observation_undispatched(self, identity: str) -> None:
        with self._guard:
            reserved = self._observation_reservations.get(identity)
        if reserved is None:
            return
        with self._grant_lock(reserved) as ledger, self._guard:
            if self._observation_reservations.pop(identity, None) is None:
                return
            ledger.change("observations", "requests", "unknown", -1)
            ledger.state["observation_request_ids"].remove(identity)
            ledger.save()
            _change(self.session["accounting"]["observations"]["requests"], "unknown", -1)
            self.checkpoint(pid=os.getpid())

    def _revalidate_observation(self, request: dict, admission: dict) -> None:
        if self._stopping() or self.clock() >= parse_time(admission["deadline_at"]):
            raise ApprovalError("observation_emission_deadline_or_stop")
        with self._guard:
            if admission["request_id"] not in self._observation_reservations:
                raise ApprovalError("observation_reservation_missing")
        actual = copy.deepcopy(request)
        self._resolve_observation_inputs(actual)
        refreshed = resolve_approval(self.vault, self.plan, "observations.read",
                      approval_ref=admission["approval_ref"], request=actual, now=self.clock())
        if refreshed["grant_digest"] != admission["grant_digest"]:
            raise ApprovalError("observation_grant_changed_before_emission")


    async def _observations(self, refs: list[dict]) -> None:
        sources = self.plan["profile"].get("observation_sources", [])
        if not sources or self._stopping():
            return
        network = any(binding["id"] != "local-artifact" for binding in sources)
        if network and self.vault.config.x.max_observation_requests == 0:
            return
        from hyperresearch.core.x_observations import ObservationCollectionError
        cancelled = False
        try:
            future = asyncio.create_task(asyncio.to_thread(self._analytics_engine().observe, self.plan, refs,
                        authorize=self.authorize_request, on_evidence=self._observation_received,
                        revalidate=self._revalidate_observation, on_undispatched=self._observation_undispatched))
            while not future.done():
                try:
                    await asyncio.sleep(0.05)
                except asyncio.CancelledError:
                    self._cancel.set()
                    cancelled = True
            result = await asyncio.shield(future)
        except ObservationCollectionError as exc:
            result = exc.observation_refs
            self.session["stop_reason"] = "observation_collection_partial: " + exc.reason
        with self._guard:
            _add_refs(self.session["observation_frontier"], result)
            for ref in result:
                observation = self.store.get_record(ref, "verified-observation")
                proof_refs = observation["source"]["evidence_refs"]
                if proof_refs and all((proof["path"], proof["sha256"]) in self._owned_observation_proofs for proof in proof_refs):
                    _add_refs(self._live_observation_refs, [ref])
            self._snapshot()
            self.publish()
        if cancelled:
            raise asyncio.CancelledError

    def _analysis_complete(self, event: dict) -> None:
        identity = event.get("request_id")
        outcome = event.get("reservation") or {}
        with self._guard:
            reserved = self._model_reservations.get(identity)
        context = self._grant_lock(reserved["grant"]) if reserved is not None else contextlib.nullcontext()
        with context as ledger, self._guard:
            reservation = self._model_reservations.pop(identity, None)
            if reservation is not None:
                usage = event.get("usage") or {}
                counts = [usage.get("input_tokens"), usage.get("output_tokens")]
                tokens = sum(counts) if all(type(count) is int and count >= 0 for count in counts) else None
                attempts = outcome.get("attempts")
                for key, amount in reservation["amounts"].items():
                    cell = self.session["accounting"]["analysis"][key]
                    _change(cell, "reserved", -Decimal(str(amount)))
                    ledger.change("analysis", key, "reserved", -Decimal(str(amount)))
                    actual = {"requests": attempts, "tokens": tokens, "cost_usd": usage.get("cost_usd")}.get(key)
                    if attempts == 0 and outcome.get("state") == "released":
                        actual = 0
                    bucket, amount_used = ("unknown", amount) if actual is None else ("actual", actual)
                    _change(cell, bucket, amount_used)
                    ledger.change("analysis", key, bucket, amount_used)
                    if actual is not None and Decimal(str(actual)) > Decimal(str(amount)):
                        self.session["state"], self.session["stop_reason"] = "blocked", "model_usage_exceeded_attested_reserve"
                        self._cancel.set()
                if attempts == 0 and outcome.get("state") == "released":
                    ledger.state["model_request_ids"].remove(identity)
                    self.session["model_request_ids"] = [item for item in self.session.get("model_request_ids", []) if item != identity]
                ledger.save()
            if event.get("annotation_ref"):
                _add_refs(self.session["analysis_frontier"], [event["annotation_ref"]])
            self.publish()


    async def _analysis_worker(self, classifier) -> None:
        while True:
            identity = await self._queue.get()
            try:
                if identity is None:
                    return
                work = next(item for item in self.session["deferred_work"] if item["id"] == identity)
                if self._stopping() or self.clock() >= parse_time(self.session["expires_at"]):
                    continue
                job = json.loads(self.store.read_blob(work["ref"]))
                deadline = min(parse_time(self.session["expires_at"]), self.clock() + timedelta(seconds=self.plan["limits"]["analysis"]["max_elapsed_s"]))
                reserve = {"reservation_id": identity, "request_id": identity, "model_requests": 1,
                           "model_tokens": self.plan["limits"]["analysis"].get("request_tokens", 0),
                           "model_cost_usd": self.plan["limits"]["analysis"].get("request_cost_usd", "0"),
                           "deadline_at": timestamp(deadline)}
                job["reservation"] = reserve
                with self._guard:
                    work["ref"] = self.store.put_blob(canonical_bytes(job))
                    work["state"] = "running"
                    self.checkpoint(pid=os.getpid())
                ref = await classifier.classify(job["capture_ref"], job["context_refs"], reservation=reserve, deadline_at=deadline)
                for event in classifier.drain_events():
                    self._analysis_complete(event)
                with self._guard:
                    _add_refs(self.session["analysis_frontier"], [ref])
                    annotation = self.store.get_record(ref, "analysis-annotation")
                    if annotation["reservation"]["attempts"] == 0 and annotation["status"] not in {"available", "abstained", "insufficient-context"}:
                        pending = next((item for item in self.session["deferred_work"] if item["id"] == identity), None)
                        if pending:
                            pending["state"] = "queued"
                    else:
                        self.session["deferred_work"] = [item for item in self.session["deferred_work"] if item["id"] != identity]
                        self.session.setdefault("completed_job_ids", []).append(identity)
                    self._queued.add(identity)
                    self.publish()
            except asyncio.CancelledError:
                raise
            except (ApprovalError, ValueError, RuntimeError) as exc:
                with self._guard:
                    work = next((item for item in self.session["deferred_work"] if item["id"] == identity), None)
                    if work:
                        work["state"] = "unknown" if identity in self._model_reservations else "queued"
                    self.session["stop_reason"] = getattr(exc, "code", "analysis_failure")
                    self.checkpoint(pid=os.getpid())
            finally:
                self._queue.task_done()
                self._refill_queue()

    async def run(self, *, resume: bool = False) -> dict:
        lock = _monitor_path(self.store, self.session["monitor_id"], "writer.lock")
        with _file_lock(lock, blocking=False):
            stop_path = _monitor_path(self.store, self.session["monitor_id"], "stop.json")
            if resume and stop_path.is_file():
                validate_record("monitor-control", json.loads(stop_path.read_bytes()))
                stop_path.unlink()
            self._loop = asyncio.get_running_loop()
            workers, classifier = [], None
            try:
                if self.session.get("stop_reason") == "offline-replay":
                    raise MonitorError("replay_session_cannot_dispatch")
                # Recovery is allowed after expiry. It cannot renew the native scope.
                if self.session["active_operation"]:
                    active = self.session["active_operation"]
                    scope = json.loads(self.store.read_blob(active["scope_ref"]))
                    await self._operation(scope, resume_ref=active["receipt_ref"])
                    if self.session["active_operation"]:
                        return self.result()
                if self.clock() >= parse_time(self.session["expires_at"]):
                    self.session["state"], self.session["stop_reason"] = "expired", "immutable_session_deadline"
                    self.publish()
                    return self.result()
                if not self.vault.config.x.enabled:
                    raise ApprovalError("native_x_disabled")
                admission = resolve_approval(self.vault, self.plan, "source.search", approval_ref=self.approval_ref, now=self.clock())
                self._admit(admission)
                self._snapshot()
                self.session["state"], self.session["stop_reason"] = "running", None
                # Previously running/unknown model work stays unknown after restart;
                # only known queued work may be newly admitted.
                for work in self.session["deferred_work"]:
                    if work["kind"] == "annotation" and work["state"] == "running":
                        work["state"] = "unknown"
                self.checkpoint(pid=os.getpid())
                if self.plan["analysis"]["enabled"] and self.vault.config.x.analysis_enabled:
                    from hyperresearch.core.x_classifier import XClassifier
                    captures = [item["ref"] for item in self.store.resolve_closure(self.session["source_frontier"]) if item["kind"] == "source-capture"]
                    self._queue_captures(captures)
                    self._queue = asyncio.Queue(maxsize=max(1, self.plan["limits"]["analysis"]["max_queue"]))
                    classifier = (self._classifier_factory or XClassifier)(self.store, self.plan, self.authorize_request)
                    await classifier.__aenter__()
                    count = min(4, self.plan["limits"]["analysis"]["max_workers"], self.vault.config.x.analysis_workers)
                    workers = [asyncio.create_task(self._analysis_worker(classifier)) for _ in range(count)]
                    self._refill_queue()
                while not self._stopping() and self.clock() < parse_time(self.session["expires_at"]):
                    if self.session["state"] != "running":
                        break
                    pending = sum(work["kind"] == "annotation" and work["state"] in {"queued", "running"} for work in self.session["deferred_work"])
                    if self.plan["analysis"]["enabled"] and pending >= self.plan["limits"]["analysis"]["max_queue"]:
                        await asyncio.sleep(0.05)
                        continue
                    index = self._next_query()
                    if index is None:
                        await asyncio.sleep(0.05)
                        continue
                    with self._guard:
                        scope = self._scope(index)
                        self._reserve_source(scope)
                        query_state = self.session["query_state"][index]
                        query_state.update(last_operation_id=scope["operation_id"], last_started_at=scope["started_at"],
                              next_due_at=timestamp(parse_time(scope["started_at"]) + timedelta(seconds=self.plan["schedule"]["poll_interval_s"])))
                        # Persist fairness before dispatch: restart after Q1 chooses Q2.
                        self.session["next_query_index"] = (index + 1) % len(self.plan["queries"])
                        self.checkpoint(pid=os.getpid())
                    await self._operation(scope)
                if self.session["state"] == "running":
                    self.session["state"] = "stopped" if self._stopping() else "expired"
                    self.session["stop_reason"] = "user-request" if self._stopping() else "immutable_session_deadline"
            except (ApprovalError, MonitorError, ValueError, RuntimeError) as exc:
                code = getattr(exc, "code", "monitor_runtime_failure")
                self.session["state"] = "completed" if code in {"source_session_budget_exhausted", "configured_source_session_budget_exhausted"} else "blocked"
                self.session["stop_reason"] = code
            finally:
                self._cancel.set()
                for worker in workers:
                    worker.cancel()
                await asyncio.gather(*workers, return_exceptions=True)
                if classifier is not None:
                    await classifier.__aexit__(None, None, None)
                    for event in classifier.drain_events():
                        self._analysis_complete(event)
                self._hold_unknown_model_reservations()
                self.session["stopped_at"] = timestamp(self.clock())
                self.publish()
            return self.result()

    def _hold_unknown_model_reservations(self) -> None:
        for identity, reservation in list(self._model_reservations.items()):
            with self._grant_lock(reservation["grant"]) as ledger, self._guard:
                if self._model_reservations.pop(identity, None) is None:
                    continue
                for key, amount in reservation["amounts"].items():
                    _change(self.session["accounting"]["analysis"][key], "reserved", -Decimal(str(amount)))
                    _change(self.session["accounting"]["analysis"][key], "unknown", amount)
                    ledger.change("analysis", key, "reserved", -Decimal(str(amount)))
                    ledger.change("analysis", key, "unknown", amount)
                ledger.save()

    def result(self) -> dict:
        return {"monitor_id": self.session["monitor_id"], "session_ref": self._session_ref,
                "state": self.session["state"], "stop_reason": self.session.get("stop_reason"),
                "accounting": self.session["accounting"], "output_refs": self.session["output_refs"],
                "source_frontier": self.session["source_frontier"], "analysis_frontier": self.session["analysis_frontier"],
                "observation_frontier": self.session["observation_frontier"], "deferred_work": self.session["deferred_work"],
                "materialization": list(self._materialization_results.values()), "projection_refs": self._projection_refs,
                "active_operation": self.session["active_operation"], "observational_only": True}


def frozen_evaluation_time(store: EvidenceStore, session: dict) -> str:
    if session["output_refs"]:
        return max(store.get_record(ref, "analytics-event")["evaluation_time"] for ref in session["output_refs"])
    times = [session.get("stopped_at") or session["started_at"]]
    for item in store.resolve_closure(session["source_frontier"]):
        if item.get("kind") == "source-capture":
            times.append(item["payload"]["captured_at"])
    return timestamp(max(parse_time(value) for value in times))


def reduce_monitor(vault, monitor_id: str, *, window_s: int, evaluation_time: str | None = None,
                   policy: dict | None = None) -> dict:
    store = EvidenceStore(vault.root)
    session, session_ref = load_session(store, monitor_id)
    plan, _ = session_plan(store, session)
    runner = MonitorRunner(vault, plan, session)
    evaluation = evaluation_time or frozen_evaluation_time(store, session)
    refs = runner._analytics_engine().reduce(plan, session, window_s=window_s, evaluation_time=evaluation, policy=policy)
    return {"monitor_id": monitor_id, "session_ref": session_ref, "evaluation_time": evaluation,
            "window_s": window_s, "event_refs": refs, "events": [store.get_record(ref, "analytics-event") for ref in refs],
            "external_calls": 0, "observational_only": True}


def replay_monitor(vault, monitor_id: str, *, policy: dict | None = None,
                   evaluation_time: str | None = None) -> dict:
    store = EvidenceStore(vault.root)
    source, source_ref = load_session(store, monitor_id)
    plan, _ = session_plan(store, source)
    evaluation = evaluation_time or frozen_evaluation_time(store, source)
    replay = copy.deepcopy(source)
    policy_ref = store.put_blob(canonical_bytes(validate_record("analysis-policy", policy))) if policy else None
    try:
        trust_digest = read_host_trust(vault.config.x.trust_store)["trust_store_digest"]
    except (ApprovalError, ValueError):
        trust_digest = None
    identity = record_digest({"source_session_ref": source_ref, "evaluation_time": evaluation,
                              "policy_ref": policy_ref, "host_trust_digest": trust_digest})
    replay.update(monitor_id=f"replay-{identity[:32]}", session_id=f"replay-session-{identity[:32]}",
                  revision=1, state="completed", active_operation=None, deferred_work=[], output_refs=[],
                  stopped_at=evaluation, stop_reason="offline-replay")
    if policy:
        from hyperresearch.core.x_classifier import replay_annotation
        replay["analysis_frontier"] = [replay_annotation(store, ref, policy) for ref in source["analysis_frontier"]]
        _add_refs(replay["policy_refs"], [policy_ref])
    runner = MonitorRunner(vault, plan, replay)
    try:
        previous, previous_ref = load_session(store, replay["monitor_id"])
    except MonitorError as exc:
        if exc.code != "monitor_not_found":
            raise
    else:
        if previous["state"] != "completed" or previous["stop_reason"] != "offline-replay" or previous["plan_ref"] != replay["plan_ref"]:
            raise MonitorError("replay_identity_conflict")
        runner = MonitorRunner(vault, plan, previous)
        runner._session_ref = previous_ref
        return {**runner.result(), "source_session_ref": source_ref, "evaluation_time": evaluation,
                "external_calls": 0, "new_model_requests": 0, "new_source_requests": 0}
    runner.publish(evaluation_time=evaluation, policy=policy)
    return {**runner.result(), "source_session_ref": source_ref, "evaluation_time": evaluation,
            "external_calls": 0, "new_model_requests": 0, "new_source_requests": 0}


def _operation_session(store: EvidenceStore, operation_id: str) -> dict | None:
    for session in _latest_sessions(store):
        active = session["active_operation"]
        if active and active["operation_id"] == operation_id:
            return session
        for item in store.resolve_closure(session["source_frontier"]):
            if item["kind"] == "source-receipt" and item["payload"]["operation_id"] == operation_id:
                return session
    return None


async def collect_scope(vault, plan: dict, scope: dict, *, resume_ref: dict | None = None) -> dict:
    """One exact operation, preserving its original reservation on local recovery."""
    store = EvidenceStore(vault.root)
    scope = validate_record("source-scope", scope)
    plan = validate_plan(plan)
    if scope["plan_ref"]["digest"] != plan_digest(plan):
        raise MonitorError("source_scope_plan_mismatch")
    session = _operation_session(store, scope["operation_id"])
    if session is not None:
        bound_plan, _ = session_plan(store, session)
        if plan_digest(bound_plan) != plan_digest(plan):
            raise MonitorError("source_operation_plan_changed")
        if session["active_operation"] is None:
            runner = MonitorRunner(vault, plan, session)
            _, runner._session_ref = load_session(store, session["monitor_id"])
            return {**runner.result(), "recovery_only": True, "new_source_requests": 0}
    else:
        session = new_session(store, plan, monitor_id="collect-" + record_digest(scope["operation_id"])[:32],
                              now=parse_time(scope["started_at"]))
    runner = MonitorRunner(vault, plan, session, approval_ref=scope["approval_ref"])
    with _file_lock(_monitor_path(store, session["monitor_id"], "writer.lock"), blocking=False):
        try:
            if runner.session["active_operation"] is None:
                runner._reserve_source(scope)
                for query in runner.session["query_state"]:
                    if scope["query_ref"] and query["query_id"] == scope["query_ref"]["query_id"]:
                        query.update(last_operation_id=scope["operation_id"], last_started_at=scope["started_at"])
            runner.session["state"], runner.session["stop_reason"] = "running", None
            runner.checkpoint(pid=os.getpid())
            await runner._operation(scope, resume_ref=resume_ref)
            if runner.session["active_operation"] is None and runner.session["state"] == "running":
                runner.session["state"] = "completed"
        except (ApprovalError, MonitorError, ValueError, RuntimeError) as exc:
            runner.session["state"], runner.session["stop_reason"] = "blocked", getattr(exc, "code", "source_operation_failed")
        finally:
            runner.session["stopped_at"] = timestamp(runner.clock())
            runner.publish()
        return runner.result()


async def resume_receipt(vault, receipt_ref: dict) -> dict:
    store = EvidenceStore(vault.root)
    receipt = store.get_record(receipt_ref, "source-receipt")
    existing = _operation_session(store, receipt["operation_id"])
    if existing:
        plan, _ = session_plan(store, existing)
    else:
        scope_plan = store.resolve_ref(receipt["scope"]["plan_ref"]["artifact_ref"], origin_ref=receipt_ref)
        plan = store.get_record(scope_plan, "monitor-plan")
    return await collect_scope(vault, plan, receipt["scope"], resume_ref=receipt_ref)


async def classify_captures(vault, plan: dict, refs: list[dict], *, stop_after_s: int | None = None) -> dict:
    """Analyze an existing bounded capture set without source or observation dispatch."""
    from hyperresearch.core.x_classifier import XClassifier

    plan = validate_plan(plan)
    if not plan["analysis"]["enabled"]:
        raise ApprovalError("plan_model_analysis_disabled")
    store = EvidenceStore(vault.root)
    if len(refs) > plan["limits"]["session"]["max_captures"]:
        raise MonitorError("capture_set_exceeds_session_limit")
    for ref in refs:
        store.get_record(ref, "source-capture")
    session = new_session(store, plan, stop_after=stop_after_s)
    _add_refs(session["source_frontier"], refs)
    runner = MonitorRunner(vault, plan, session)
    with _file_lock(_monitor_path(store, session["monitor_id"], "writer.lock"), blocking=False):
        workers, classifier = [], None
        runner._loop = asyncio.get_running_loop()
        try:
            if not vault.config.x.analysis_enabled:
                raise ApprovalError("configured_model_analysis_disabled")
            runner.session["state"] = "running"
            runner._queue_captures(refs)
            runner._queue = asyncio.Queue(maxsize=max(1, plan["limits"]["analysis"]["max_queue"]))
            classifier = XClassifier(store, plan, runner.authorize_request)
            await classifier.__aenter__()
            count = min(4, plan["limits"]["analysis"]["max_workers"], vault.config.x.analysis_workers)
            workers = [asyncio.create_task(runner._analysis_worker(classifier)) for _ in range(count)]
            runner.checkpoint(pid=os.getpid())
            runner._refill_queue()
            await runner._queue.join()
            runner.session["state"] = "blocked" if runner.session["deferred_work"] else "completed"
            runner.session["stop_reason"] = "analysis_deferred" if runner.session["deferred_work"] else None
        except (ApprovalError, MonitorError, ValueError, RuntimeError) as exc:
            runner.session["state"], runner.session["stop_reason"] = "blocked", getattr(exc, "code", "analysis_failure")
        finally:
            runner._cancel.set()
            for worker in workers:
                worker.cancel()
            await asyncio.gather(*workers, return_exceptions=True)
            if classifier is not None:
                await classifier.__aexit__(None, None, None)
                for event in classifier.drain_events():
                    runner._analysis_complete(event)
            runner._hold_unknown_model_reservations()
            runner.session["stopped_at"] = timestamp(runner.clock())
            runner.publish()
        return {**runner.result(), "new_source_requests": 0, "new_observation_requests": 0}
