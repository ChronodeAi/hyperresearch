"""Synchronous native X intake with incremental canonical persistence, never reader fallback."""

from __future__ import annotations

import os
import re
import subprocess
import tempfile
import uuid
from datetime import UTC, datetime, timedelta
from urllib.parse import urlsplit

from hyperresearch.core.x_artifacts import artifact_path, atomic_write, decode_json
from hyperresearch.core.x_evidence import EvidenceStore
from hyperresearch.core.x_projection import is_x_url, unknown_evidence
from hyperresearch.models.x_evidence import canonical_bytes, plan_digest, validate_record
from hyperresearch.web.base import SERVED_BY_KEY, WebResult


class NativeSourceError(RuntimeError):
    """Explicit source/policy/schema outcome, optionally carrying committed partial evidence."""

    def __init__(self, message: str, code: str = "X_SOURCE_REFUSED", result: dict | None = None):
        super().__init__(message)
        self.code, self.result = code, result


class OpenCLIProvider:
    name = "opencli"

    def __init__(self, vault, *, command=None, source_authorizer=None):
        self.vault, self.store = vault, EvidenceStore(vault.root)
        self.command = tuple(command or getattr(vault.config.x, "command", ("opencli",)))
        self.source_authorizer = source_authorizer
        self.last_operation = None

    def capabilities(self) -> dict:
        try:
            completed = subprocess.run([*self.command, "research-capabilities", "--json"], capture_output=True, timeout=10)
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise NativeSourceError("Native source capability probe unavailable", "X_SOURCE_CAPABILITIES") from exc
        if completed.returncode:
            raise NativeSourceError("Native source capability probe failed", "X_SOURCE_CAPABILITIES")
        try:
            return validate_record("source-capabilities", decode_json(completed.stdout))
        except (ValueError, TypeError) as exc:
            raise NativeSourceError("Incompatible native source contract", "X_SOURCE_SCHEMA") from exc

    def _scope(self, *, url=None, query=None, max_results=None) -> dict:
        settings = self.vault.config.x
        if not settings.enabled or not settings.plan_ref:
            raise NativeSourceError("Native X intake is disabled or lacks a configured governed plan")
        plan_ref = self.store.ref_from_path(settings.plan_ref)
        plan = self.store.get_record(plan_ref, "monitor-plan")
        limits = dict(plan["limits"]["poll"])
        for field, ceiling in (("max_pages", settings.max_pages), ("max_captures", settings.max_total_captures),
                               ("max_requests", settings.max_source_requests), ("max_elapsed_s", settings.operation_timeout_s)):
            limits[field] = min(limits[field], ceiling)
        limits["max_primary"] = min(limits.get("max_primary", limits["max_captures"]), settings.max_primary)
        if max_results is not None:
            limits["max_primary"] = min(limits["max_primary"], max_results)
        now = datetime.now(UTC)
        scope = {"schema_version": 1, "operation_id": f"hpr-{uuid.uuid4().hex}",
                 "scope_id": plan["plan_id"], "operation": "search" if query is not None else "post",
                 "plan_ref": {"plan_id": plan["plan_id"], "revision": plan["revision"], "digest": plan_digest(plan), "artifact_ref": plan_ref},
                 "query_ref": None, "owner": plan["source"]["owner"], "profile": plan["source"]["profile"],
                 "allowed_hosts": plan["source"]["allowed_hosts"], "product": "Latest" if query is not None else None,
                 "expression": query, "target": None, "started_at": now.isoformat().replace("+00:00", "Z"),
                 "deadline": (now + timedelta(seconds=limits["max_elapsed_s"])).isoformat().replace("+00:00", "Z"), "limits": limits}
        if query is not None:
            match = next((item for item in plan["queries"] if item["expression"] == query), None)
            if match is None:
                raise NativeSourceError("Search expression is outside the configured plan", "X_SOURCE_SCOPE")
            scope["query_ref"] = {"query_id": match["id"], "revision": match["revision"]}
        else:
            parsed = urlsplit(url)
            try:
                port = parsed.port
            except ValueError as exc:
                raise NativeSourceError("Invalid public post URL port", "X_SOURCE_SCOPE") from exc
            if parsed.username is not None or parsed.password is not None or port not in {None, 443 if parsed.scheme == "https" else 80}:
                raise NativeSourceError("Credentialed or nonstandard public post URL refused", "X_SOURCE_SCOPE")
            match = re.fullmatch(r"/((?:[A-Za-z0-9_]{1,15}|i/web)/status/[1-9][0-9]{0,24})(?:/(?:photo|video)/[0-9]+)?/?", parsed.path)
            if not is_x_url(url) or match is None:
                raise NativeSourceError("Native URL intake requires an exact public post URL", "X_SOURCE_SCOPE")
            host = parsed.hostname.removeprefix("mobile.")
            if host not in scope["allowed_hosts"]:
                raise NativeSourceError("Post host is outside the configured plan", "X_SOURCE_SCOPE")
            scope["target"] = f"https://{host}/{match[1]}"
        return validate_record("source-scope", scope)

    def _authorize(self, scope):
        if self.source_authorizer:
            return validate_record("source-scope", self.source_authorizer(scope))
        from hyperresearch.core.x_authority import authorize_source_scope

        return validate_record("source-scope", authorize_source_scope(self.vault, scope))

    def execute_scope(self, scope: dict, resume_ref: dict | None = None, on_page=None, cancel_event=None) -> dict:
        """Expose typed refusals while retaining any already committed source outcome."""
        try:
            return self._execute_scope(scope, resume_ref, on_page, cancel_event)
        except NativeSourceError:
            raise
        except (ValueError, TypeError, OSError) as exc:
            raise NativeSourceError(str(exc), "X_SOURCE_SCHEMA", self.last_operation) from exc

    def _execute_scope(self, scope: dict, resume_ref=None, on_page=None, cancel_event=None) -> dict:
        """Persist pages while running; return partial nonzero exits without claiming settlement."""
        import hashlib
        import signal

        self.last_operation = None
        scope = validate_record("source-scope", scope)
        if resume_ref is not None:
            receipt = self.store.get_record(resume_ref, "source-receipt")
            if canonical_bytes(receipt["scope"]) != canonical_bytes(scope):
                raise NativeSourceError("Resume scope differs from the original immutable request", "X_SOURCE_SCOPE")
        deadline = datetime.fromisoformat(scope["deadline"].replace("Z", "+00:00"))
        stopped = cancel_event is not None and cancel_event.is_set()
        if datetime.now(UTC) >= deadline or stopped:
            operation = artifact_path(self.store.root, f"operations/{hashlib.sha256(scope['operation_id'].encode()).hexdigest()}")
            if not (operation / "scope.json").is_file():
                code = "X_SOURCE_STOPPED" if stopped else "X_SOURCE_SCOPE"
                raise NativeSourceError("No dispatched native operation to recover", code, {"scope": scope, "execution_unknown": False})
            self.store.create_operation(scope)
            result = self.store.import_operation(operation)
            final = result["final_receipt_ref"]
            unknown = final is None or self.store.get_record(final, "source-receipt")["execution"]["state"] in {"running", "unknown"}
            self.last_operation = {**result, "returncode": None, "recovery_only": True, "execution_unknown": unknown}
            return self.last_operation
        if not self.vault.config.x.enabled:
            raise NativeSourceError("Native X intake is disabled")
        import copy

        canonical_scope = copy.deepcopy(scope)
        plan_ref = (canonical_scope.get("plan_ref") or {}).get("artifact_ref")
        if plan_ref is not None and resume_ref is not None:
            canonical_scope["plan_ref"]["artifact_ref"] = self.store.resolve_ref(plan_ref, origin_ref=resume_ref)
        try:
            authorized = self._authorize(canonical_scope)
        except (ValueError, RuntimeError, PermissionError) as exc:
            raise NativeSourceError(str(exc), "X_SOURCE_POLICY") from exc
        # The full plan asset may be attached/relocated; signed logical scope is immutable.
        if {k: v for k, v in authorized.items() if k not in {"approval_ref", "plan_ref"}} != {
            k: v for k, v in canonical_scope.items() if k not in {"approval_ref", "plan_ref"}
        }:
            raise NativeSourceError("Authorizer changed immutable source scope", "X_SOURCE_SCOPE")
        admitted_plan = canonical_scope.get("plan_ref")
        checked_plan = authorized.get("plan_ref")
        if (admitted_plan is None) != (checked_plan is None):
            raise NativeSourceError("Authorizer changed the admitted plan", "X_SOURCE_SCOPE")
        if admitted_plan is not None:
            if {k: v for k, v in admitted_plan.items() if k != "artifact_ref"} != {
                k: v for k, v in checked_plan.items() if k != "artifact_ref"
            }:
                raise NativeSourceError("Authorizer changed signed plan identity", "X_SOURCE_SCOPE")
            original_asset, checked_asset = admitted_plan.get("artifact_ref"), checked_plan.get("artifact_ref")
            if original_asset is not None and (
                checked_asset is None or original_asset["sha256"] != checked_asset["sha256"]
            ):
                raise NativeSourceError("Authorizer changed admitted plan bytes", "X_SOURCE_SCOPE")
        plan_ref = (authorized.get("plan_ref") or {}).get("artifact_ref")
        plan_bytes = None
        scope = copy.deepcopy(authorized)
        if plan_ref is not None:
            plan = self.store.get_record(plan_ref, "monitor-plan")
            summary = scope["plan_ref"]
            if (summary["plan_id"], summary["revision"], summary["digest"]) != (
                plan["plan_id"], plan["revision"], plan_digest(plan)
            ):
                raise NativeSourceError("Canonical plan identity differs from admitted scope", "X_SOURCE_SCOPE")
            plan_bytes = self.store.read_blob(plan_ref)
            scope["plan_ref"]["artifact_ref"] = {**plan_ref, "path": "plan.json"}
        if resume_ref is not None and canonical_bytes(scope) != canonical_bytes(receipt["scope"]):
            raise NativeSourceError("Reauthorization changed the original native scope", "X_SOURCE_SCOPE")
        operation = self.store.create_operation(scope)
        if plan_bytes is not None:
            for artifact in self.store.export_closure([plan_ref])["artifacts"]:
                ref = artifact["ref"]
                if not ref["path"].startswith("manifests/"):
                    atomic_write(artifact_path(operation, ref["path"]), self.store.read_blob(ref), immutable=True)
            atomic_write(operation / "plan.json", plan_bytes, immutable=True)
        self.capabilities()
        if datetime.now(UTC) >= deadline or (cancel_event is not None and cancel_event.is_set()):
            result = self.store.import_operation(operation)
            final = result["final_receipt_ref"]
            unknown = final is None or self.store.get_record(final, "source-receipt")["execution"]["state"] in {"running", "unknown"}
            self.last_operation = {**result, "returncode": None, "recovery_only": True, "execution_unknown": unknown}
            return self.last_operation
        argv = [*self.command, "twitter", "capture", "--scope-file", str(operation / "scope.json"), "--output-dir", str(operation)]
        if resume_ref is not None:
            resume_path = operation / "resume-receipt.json"
            atomic_write(resume_path, canonical_bytes(self.store.get_record(resume_ref, "source-receipt")))
            argv.extend(["--resume", str(resume_path)])
        seen = set()
        environment = os.environ.copy()
        environment["OPENCLI_X_TRUST_STORE"] = self.vault.config.x.trust_store
        with tempfile.TemporaryFile() as stdout, tempfile.TemporaryFile() as stderr:
            if datetime.now(UTC) >= deadline or (cancel_event is not None and cancel_event.is_set()):
                result = self.store.import_operation(operation)
                final = result["final_receipt_ref"]
                unknown = final is None or self.store.get_record(final, "source-receipt")["execution"]["state"] in {"running", "unknown"}
                self.last_operation = {**result, "returncode": None, "recovery_only": True, "execution_unknown": unknown}
                return self.last_operation
            process = subprocess.Popen(argv, stdout=stdout, stderr=stderr, env=environment)
            stop_sent = False
            while True:
                if cancel_event is not None and cancel_event.is_set() and not stop_sent:
                    stop_sent = True
                    try:
                        process.send_signal(signal.SIGINT)
                    except ProcessLookupError:
                        pass
                try:
                    imported = self.store.import_operation(operation)
                except (ValueError, OSError) as exc:
                    retained = self.last_operation or {"operation_id": scope["operation_id"], "scope": scope}
                    self.last_operation = {**retained, "operation_dir": operation.relative_to(self.store.root).as_posix(),
                                           "returncode": process.poll(), "execution_unknown": True}
                    raise NativeSourceError(str(exc), "X_SOURCE_SCHEMA", self.last_operation) from exc
                self.last_operation = {**imported, "returncode": None, "recovery_only": False, "execution_unknown": True}
                fresh = [ref for ref in imported["page_refs"] if ref["sha256"] not in seen]
                for page_ref in fresh:
                    seen.add(page_ref["sha256"])
                    if on_page:
                        on_page({**imported, "page_ref": page_ref})
                remaining = (deadline - datetime.now(UTC)).total_seconds()
                if remaining <= 0:
                    # A local timeout cannot settle Chrome or release native source ownership.
                    self.last_operation = {**imported, "returncode": None, "process_id": process.pid, "execution_unknown": True}
                    raise NativeSourceError("Native source execution is not settled; committed evidence remains recoverable", "X_SOURCE_EXECUTION_UNKNOWN", self.last_operation)
                try:
                    code = process.wait(timeout=min(0.1, remaining))
                    break
                except subprocess.TimeoutExpired:
                    continue
            try:
                imported = self.store.import_operation(operation)
            except (ValueError, OSError) as exc:
                self.last_operation = {**self.last_operation, "returncode": code, "execution_unknown": True}
                raise NativeSourceError(str(exc), "X_SOURCE_SCHEMA", self.last_operation) from exc
        final = imported["final_receipt_ref"]
        unknown = final is None or self.store.get_record(final, "source-receipt")["execution"]["state"] in {"running", "unknown"}
        self.last_operation = {**imported, "returncode": code, "recovery_only": False, "execution_unknown": unknown}
        if imported["final_receipt_ref"] is None:
            raise NativeSourceError("Native process exited without a final source receipt", "X_SOURCE_UNSETTLED", self.last_operation)
        return self.last_operation

    def _results(self, operation: dict) -> list[WebResult]:
        results = []
        for ref in operation["capture_refs"]:
            capture = self.store.get_record(ref, "source-capture")
            refs = unknown_evidence()
            refs.update(capture_refs=[ref], receipt_refs=operation["receipt_refs"], producer=capture["producer"])
            refs["receipt_state"] = "recorded" if refs["receipt_refs"] else "unknown"
            results.append(WebResult(
                url=capture["url"], title=f"X post {capture['post_id']}", content=capture["text"],
                fetched_at=datetime.fromisoformat(capture["captured_at"].replace("Z", "+00:00")),
                metadata={SERVED_BY_KEY: capture["producer"]["product"], "fetch_route": self.name,
                          "x_evidence": refs, "x_capture": capture, "x_operation": operation},
            ))
        return results

    def fetch(self, url: str) -> WebResult:
        operation = self.execute_scope(self._scope(url=url))
        results = self._results(operation)
        post_id = urlsplit(url).path.split("/status/")[-1].split("/")[0]
        primary = next((result for result in results if result.metadata["x_capture"]["post_id"] == post_id), None)
        if primary is None:
            raise NativeSourceError("Native operation returned no matching public post", "X_SOURCE_EMPTY", operation)
        return primary

    def search(self, query: str, max_results: int = 5) -> list[WebResult]:
        results = self._results(self.execute_scope(self._scope(query=query, max_results=max_results)))
        return [result for result in results if result.metadata["x_capture"]["role"] == "primary"][:max_results]


class XDispatchProvider:
    """Keep generic providers synchronous and lazily route exact public X hosts."""

    def __init__(self, vault, name: str, article_factory):
        self.vault, self.name, self.article_factory = vault, name, article_factory
        self._article, self._native = None, None

    def _article_provider(self):
        if self._article is None:
            self._article = self.article_factory()
        return self._article

    def _native_provider(self):
        if self._native is None:
            self._native = OpenCLIProvider(self.vault)
        return self._native

    def fetch(self, url: str) -> WebResult:
        if is_x_url(url):
            result = self._native_provider().fetch(url)
            result.metadata["fetch_route"] = self.name
            return result
        result = self._article_provider().fetch(url)
        if is_x_url(result.url):
            result = self._native_provider().fetch(result.url)
            result.metadata["fetch_route"] = self.name
        return result

    def search(self, query: str, max_results: int = 5) -> list[WebResult]:
        if self.name == "opencli":
            return self._native_provider().search(query, max_results)
        return self._article_provider().search(query, max_results=max_results)

    def fetch_many(self, urls: list[str]) -> list[WebResult]:
        if any(is_x_url(url) for url in urls):
            # Callers partition X from article batches to retain per-input outcomes.
            raise NativeSourceError("X URLs must be fetched individually, never in generic article batches", "X_SOURCE_SCOPE")
        provider = self._article_provider()
        if hasattr(provider, "fetch_many"):
            results = provider.fetch_many(urls)
        else:
            results = [provider.fetch(url) for url in urls]
        for index, result in enumerate(results):
            if is_x_url(result.url):
                native = self._native_provider().fetch(result.url)
                native.metadata["fetch_route"] = self.name
                results[index] = native
        return results
