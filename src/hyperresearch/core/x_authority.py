"""Host-controlled X research approvals; proposals and source text are never authority.

Only verification lives here. Real approval signing keys and signing endpoints do not.
The protected trust store and grants are read through non-symlink root-owned directory
handles. Replay verifies recorded admissions against an independently admitted public
anchor, at the recorded admission time, without consulting current grant expiry.
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
import re
import stat
from datetime import UTC, datetime
from pathlib import Path, PurePosixPath
from urllib.parse import urlsplit

from hyperresearch.models.x_evidence import (
    plan_digest,
    record_digest,
    validate_artifact_path,
    validate_record,
)


class ApprovalError(PermissionError):
    """A public refusal code; never include credentials or request content in it."""

    def __init__(self, code: str):
        self.code = code
        super().__init__(code)


def utc_now() -> datetime:
    return datetime.now(UTC)


def timestamp(value: datetime) -> str:
    return value.astimezone(UTC).isoformat().replace("+00:00", "Z")


def parse_time(value: str) -> datetime:
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except (ValueError, AttributeError) as exc:
        raise ApprovalError("invalid_utc_time") from exc
    if parsed.tzinfo is None or parsed.utcoffset().total_seconds() != 0:
        raise ApprovalError("invalid_utc_time")
    return parsed.astimezone(UTC)


def _json(data: bytes) -> dict:
    def object_pairs(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ApprovalError("duplicate_json_member")
            result[key] = value
        return result

    def constant(_value):
        raise ApprovalError("nonfinite_json_value")

    try:
        value = json.loads(data.decode("utf-8"), object_pairs_hook=object_pairs, parse_constant=constant)
    except (ValueError, UnicodeDecodeError) as exc:
        raise ApprovalError("invalid_approval_json") from exc
    if not isinstance(value, dict):
        raise ApprovalError("invalid_approval_json")
    return value


def _check_protected(fd: int, *, directory: bool) -> None:
    info = os.fstat(fd)
    kind_ok = stat.S_ISDIR(info.st_mode) if directory else stat.S_ISREG(info.st_mode)
    if not kind_ok or info.st_uid != 0 or info.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
        raise ApprovalError("unprotected_host_authority")


def _protected_read(path: str | Path, *, limit: int = 262144) -> bytes:
    """Open each component relative to an already checked directory descriptor."""
    text = os.fspath(path)
    if not text.startswith("/") or ".." in PurePosixPath(text).parts:
        raise ApprovalError("authority_path_must_be_absolute")
    parts = PurePosixPath(text).parts[1:]
    if not parts:
        raise ApprovalError("authority_path_is_directory")
    flags = os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW
    parent = os.open("/", flags | os.O_DIRECTORY)
    try:
        _check_protected(parent, directory=True)
        for part in parts[:-1]:
            child = os.open(part, flags | os.O_DIRECTORY, dir_fd=parent)
            try:
                _check_protected(child, directory=True)
            except BaseException:
                os.close(child)
                raise
            os.close(parent)
            parent = child
        fd = os.open(parts[-1], flags, dir_fd=parent)
        try:
            _check_protected(fd, directory=False)
            if os.fstat(fd).st_size > limit:
                raise ApprovalError("authority_artifact_too_large")
            result = bytearray()
            while len(result) <= limit:
                chunk = os.read(fd, min(65536, limit + 1 - len(result)))
                if not chunk:
                    return bytes(result)
                result.extend(chunk)
            raise ApprovalError("authority_artifact_too_large")
        finally:
            os.close(fd)
    except OSError as exc:
        raise ApprovalError("host_authority_unavailable") from exc
    finally:
        os.close(parent)


def read_host_trust(path: str | Path) -> dict:
    if not path:
        raise ApprovalError("host_trust_not_configured")
    raw = _protected_read(path)
    try:
        trust = validate_record("trust-store", _json(raw))
    except ValueError as exc:
        raise ApprovalError("invalid_host_trust_contract") from exc
    return {**trust, "trust_store_digest": hashlib.sha256(raw).hexdigest()}


def _verify_envelope(envelope: dict, trusted_keys: dict) -> tuple[dict, bytes]:
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

    try:
        envelope = validate_record("approval-envelope", envelope)
        public = base64.b64decode(trusted_keys[envelope["key_id"]], validate=True)
        payload_bytes = base64.b64decode(envelope["payload_b64"], validate=True)
        signature = base64.b64decode(envelope["signature_b64"], validate=True)
        if len(public) != 32 or len(signature) != 64 or len(payload_bytes) > 262144:
            raise ApprovalError("invalid_approval_encoding")
        Ed25519PublicKey.from_public_bytes(public).verify(signature, payload_bytes)
        payload = validate_record("approval-payload", _json(payload_bytes))
    except (KeyError, ValueError, InvalidSignature) as exc:
        raise ApprovalError("untrusted_or_invalid_approval") from exc
    return payload, payload_bytes


def _require_subset(actual, admitted, code: str) -> None:
    if not set(actual).issubset(admitted):
        raise ApprovalError(code)


def _bind_plan(payload: dict, plan: dict) -> None:
    digest = plan_digest(plan)
    if payload["plan_id"] != plan["plan_id"]:
        raise ApprovalError("approval_plan_identity_mismatch")
    if payload["source_owner"] != plan["source"]["owner"] or payload["source_profile"] != plan["source"]["profile"]:
        raise ApprovalError("approval_source_identity_mismatch")
    if payload["plan_digest"] is not None:
        if payload["plan_digest"] != digest or payload["plan_revision"] != plan["revision"]:
            raise ApprovalError("approval_plan_revision_mismatch")
        return
    envelope = payload["envelope"]
    if envelope["criteria_digest"] != record_digest(plan["profile"]) or envelope["analysis_digest"] != record_digest(plan["analysis"]):
        raise ApprovalError("approval_envelope_policy_mismatch")
    if plan["profile"]["id"] not in envelope["profile_ids"] or plan["profile"]["revision"] not in envelope["profile_revisions"]:
        raise ApprovalError("approval_profile_outside_envelope")
    for query in plan["queries"]:
        if query["expression"] not in envelope["query_expressions"] or query["product"] not in envelope["products"]:
            raise ApprovalError("approval_query_outside_envelope")
    for operation, targets in plan["source"].get("allowed_targets", {}).items():
        _require_subset(targets, envelope.get("allowed_targets", {}).get(operation, []), "approval_target_outside_envelope")


def _endpoint(value: str) -> str:
    parsed = urlsplit(value)
    if parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password or parsed.query or parsed.fragment:
        raise ApprovalError("endpoint_must_be_public_https")
    if parsed.port not in (None, 443):
        raise ApprovalError("endpoint_port_not_admitted")
    # API credentials embedded in commonly used provider paths are not public evidence.
    if "/v3/" in parsed.path or "/api-key/" in parsed.path or "/apikey/" in parsed.path:
        raise ApprovalError("credential_endpoint_not_supported")
    return parsed.hostname.lower()


def _integer(value, code: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        raise ApprovalError(code)
    return value


def _check_model_request(payload: dict, plan: dict, request: dict) -> None:
    from decimal import Decimal

    analysis = plan["analysis"]
    if not analysis["enabled"]:
        raise ApprovalError("model_analysis_disabled")
    policy = analysis["export_policy"]
    if payload["export_policy"] != policy or request.get("export_policy") != policy:
        raise ApprovalError("export_policy_mismatch")
    if request.get("model") != analysis["model"] or analysis["model"] not in payload["allowed_models"] or analysis["model"] not in policy["model_ids"]:
        raise ApprovalError("model_not_admitted")
    if request.get("endpoint") != policy["endpoint"] or request.get("provider") != policy["provider"] or request.get("region") != policy["region"] or request.get("retention") != policy["retention"]:
        raise ApprovalError("provider_policy_not_admitted")
    if not policy["region"] or policy["region"].lower() in {"unknown", "unspecified"}:
        raise ApprovalError("provider_region_unknown")
    if _endpoint(policy["endpoint"]) not in payload["allowed_hosts"]:
        raise ApprovalError("model_host_not_admitted")
    _require_subset(request.get("allowed_fields", []), policy["payload_fields"], "model_fields_not_admitted")
    if set(request.get("redactions", [])) != set(policy["redactions"]):
        raise ApprovalError("model_redactions_mismatch")
    limits = plan["limits"]["analysis"]
    ceilings = payload["budget_ceilings"]
    if limits["max_requests"] > ceilings["model_requests"] or limits["max_tokens"] > ceilings["model_tokens"] or Decimal(limits["max_cost_usd"]) > Decimal(ceilings["model_cost_usd"]):
        raise ApprovalError("analysis_limits_exceed_approval")
    reserve = request.get("reservation") or {}
    if _integer(reserve.get("model_requests"), "invalid_model_reservation") != 1:
        raise ApprovalError("invalid_model_reservation")
    if _integer(reserve.get("model_tokens"), "invalid_token_reservation") < limits.get("request_tokens", 0):
        raise ApprovalError("under_reserved_model_tokens")
    if Decimal(str(reserve.get("model_cost_usd", "-1"))) < Decimal(limits.get("request_cost_usd", "0")):
        raise ApprovalError("under_reserved_model_cost")
    if not limits.get("provider_bounds_ref") or request.get("bounds_ref") != limits["provider_bounds_ref"]:
        raise ApprovalError("billing_bounds_not_admitted")
    if payload["envelope"] is not None and payload["envelope"].get("provider_bounds_ref") != limits["provider_bounds_ref"]:
        raise ApprovalError("billing_bounds_not_envelope_bound")


def _observation_binding(plan: dict, request: dict) -> dict:
    matches = [binding for binding in plan["profile"].get("observation_sources", []) if binding["binding_id"] == request.get("binding_id")]
    if len(matches) != 1:
        raise ApprovalError("observation_binding_not_declared")
    return matches[0]


def _check_observation_request(payload: dict, plan: dict, request: dict) -> None:
    binding = _observation_binding(plan, request)
    if binding not in payload.get("observation_bindings", []):
        raise ApprovalError("observation_binding_not_admitted")
    if request.get("adapter") != binding["id"]:
        raise ApprovalError("observation_adapter_mismatch")
    entity = request.get("entity") or {}
    if entity.get("chain_id") != binding["chain_id"]:
        raise ApprovalError("observation_chain_mismatch")
    if request.get("plan_digest") not in (None, plan_digest(plan)) or request.get("plan_revision") not in (None, plan["revision"]):
        raise ApprovalError("observation_plan_mismatch")
    if binding["id"] == "local-artifact":
        if (request.get("endpoint") != binding["endpoint"] or request.get("method") != "ARTIFACT"
                or request.get("rpc_method") is not None or request.get("params", [])
                or request.get("requests") != 0 or request.get("timeout_s") != 0):
            raise ApprovalError("local_artifact_scope_not_admitted")
        return
    addresses = {value.lower() for value in binding["contract_addresses"] + binding["pool_addresses"]
                 + binding.get("excluded_supply_addresses", [])}
    if binding.get("factory_address"):
        addresses.add(binding["factory_address"].lower())
    for token in (binding.get("token0"), binding.get("token1")):
        if token and token.get("address"):
            addresses.add(token["address"].lower())
    if binding.get("entity_scope", "explicit") == "captured-leads":
        from hyperresearch.core.x_observations import check_captured_lead
        from hyperresearch.models.x_evidence import validate_record

        capture_ref = request.get("lead_capture_ref")
        capture = validate_record("source-capture", request.get("lead_capture"))

        class FrozenCapture:
            def get_record(self, ref, kind):
                if ref != capture_ref or kind != "source-capture":
                    raise ApprovalError("lead_capture_scope_mismatch")
                return capture

        lead = check_captured_lead(FrozenCapture(), request)
        if lead["entity"]["chain_id"] != binding["chain_id"]:
            raise ApprovalError("lead_chain_not_admitted")
        addresses.add(lead["entity"]["contract_address"].lower())
    for key in ("contract_address", "pool_address"):
        if entity.get(key) and entity[key].lower() not in addresses:
            raise ApprovalError("observation_entity_not_admitted")
    expected_endpoint = binding["endpoint"]
    if binding["id"] == "dexscreener-pair":
        from hyperresearch.core.x_observations import dex_endpoint

        expected_endpoint = dex_endpoint(binding, entity)
    if request.get("endpoint") != expected_endpoint:
        raise ApprovalError("observation_endpoint_mismatch")
    host = _endpoint(request["endpoint"])
    if host not in binding["allowed_hosts"] or host not in payload["allowed_hosts"]:
        raise ApprovalError("observation_host_not_admitted")
    ceilings = payload["budget_ceilings"]
    if _integer(request.get("requests"), "invalid_observation_reservation") != 1 or ceilings.get("observation_requests", 0) < 1:
        raise ApprovalError("observation_budget_not_admitted")
    timeout = request.get("timeout_s", 0)
    if not isinstance(timeout, (int, float)) or isinstance(timeout, bool) or not 0 < timeout <= ceilings.get("observation_timeout_s", 0):
        raise ApprovalError("observation_timeout_not_admitted")
    if not 0 < _integer(request.get("max_bytes"), "invalid_observation_byte_cap") <= 10485760:
        raise ApprovalError("observation_byte_cap_not_admitted")
    if binding["id"] == "dexscreener-pair":
        if request.get("method") != "GET" or request.get("rpc_method") is not None or request.get("params"):
            raise ApprovalError("market_request_not_admitted")
        return
    method, params = request.get("rpc_method"), request.get("params")
    if request.get("method") != "POST" or method not in binding["rpc_methods"] or not isinstance(params, list):
        raise ApprovalError("rpc_method_not_admitted")
    proofs = request.get("proof_rows", [])
    if not isinstance(proofs, list) or len(proofs) > 256:
        raise ApprovalError("observation_proof_cap_exceeded")

    def results(rpc_method):
        for row in proofs:
            prior, response = row.get("request", {}), row.get("response", {})
            if (prior.get("rpc_method") == rpc_method and prior.get("binding_id") == binding["binding_id"]
                    and prior.get("endpoint") == binding["endpoint"]
                    and isinstance(response, dict) and response.get("error") is None):
                yield prior.get("params", []), response.get("result")

    policy = binding.get("block_policy", "pinned")
    tag = {"rolling-latest": "latest", "rolling-finalized": "finalized"}.get(policy)
    if tag is not None and (binding["block_hash"] is not None or binding["block_number"] is not None):
        raise ApprovalError("rolling_binding_has_static_pins")
    pinned_hash, pinned_height = binding["block_hash"], binding["block_number"]
    historical_heights, candidates = set(), []
    for header_method in ("eth_getBlockByNumber", "eth_getBlockByHash"):
        for row in proofs:
            prior, response = row.get("request", {}), row.get("response", {})
            if (prior.get("rpc_method") != header_method or prior.get("binding_id") != binding["binding_id"]
                    or prior.get("endpoint") != binding["endpoint"] or response.get("error") is not None):
                continue
            prior_params, header = prior.get("params", []), response.get("result")
            if not isinstance(header, dict) or not prior_params:
                continue
            bound = (header_method == "eth_getBlockByNumber" and tag is not None and prior_params == [tag, False]) or (
                     header_method == "eth_getBlockByNumber" and binding["block_number"] is not None
                     and prior_params == [hex(binding["block_number"]), False]) or (
                     header_method == "eth_getBlockByHash" and binding["block_hash"] is not None
                     and prior_params == [binding["block_hash"], False])
            if not bound:
                continue
            try:
                height = int(header["number"], 16)
            except (ValueError, KeyError, TypeError) as exc:
                raise ApprovalError("observation_anchor_height_invalid") from exc
            digest = header.get("hash")
            if height < 0 or not isinstance(digest, str) or not re.fullmatch(r"0x[0-9a-fA-F]{64}", digest):
                raise ApprovalError("observation_anchor_hash_invalid")
            if tag is not None:
                historical_heights.add(height)
                admitted_at = parse_time(row.get("admission", {}).get("admitted_at", ""))
                candidates.append((admitted_at, digest, height))
            else:
                if pinned_hash is not None and digest != pinned_hash:
                    raise ApprovalError("observation_anchor_hash_mismatch")
                if pinned_height is not None and height != pinned_height:
                    raise ApprovalError("observation_anchor_height_mismatch")
                pinned_hash, pinned_height = digest, height
    if candidates:
        _, pinned_hash, pinned_height = max(candidates)
    if method == "eth_chainId":
        if params:
            raise ApprovalError("rpc_params_not_admitted")
    elif method in {"eth_getBlockByNumber", "eth_getBlockByHash"}:
        if len(params) != 2 or params[1] is not False:
            raise ApprovalError("rpc_params_not_admitted")
        expected = pinned_hash if method.endswith("Hash") else (hex(pinned_height) if pinned_height is not None else None)
        allowed = expected is not None and params[0] == expected
        if tag is not None and method == "eth_getBlockByNumber":
            allowed |= params[0] == tag or params[0] in {hex(height) for height in historical_heights}
        if binding.get("header_read_scope") == "admitted-receipt-ancestors":
            for _, receipt in results("eth_getTransactionReceipt"):
                if not isinstance(receipt, dict):
                    continue
                try:
                    height = int(receipt["blockNumber"], 16)
                except (ValueError, KeyError, TypeError):
                    continue
                coordinate = receipt.get("blockHash") if method.endswith("Hash") else receipt.get("blockNumber")
                allowed |= params[0] == coordinate and pinned_height is not None and 0 <= height <= pinned_height
        if not allowed:
            raise ApprovalError("rpc_block_not_admitted")
    elif method == "eth_getTransactionReceipt":
        allowed_transactions = {value for value in (binding["deployment_tx_hash"], binding.get("pool_creation_tx_hash")) if value}
        if binding.get("receipt_read_scope") == "admitted-pool-events":
            for prior_params, logs in results("eth_getLogs"):
                if not isinstance(logs, list) or len(prior_params) != 1:
                    continue
                if prior_params[0].get("blockHash") != pinned_hash or prior_params[0].get("address", "").lower() not in {value.lower() for value in binding["pool_addresses"]}:
                    continue
                for log in logs:
                    if (isinstance(log, dict) and log.get("removed") is False
                            and log.get("blockHash") == pinned_hash
                            and log.get("address", "").lower() in {value.lower() for value in binding["pool_addresses"]}):
                        allowed_transactions.add(log.get("transactionHash"))
        if len(params) != 1 or params[0] not in allowed_transactions:
            raise ApprovalError("rpc_receipt_not_admitted")
    elif method == "eth_getCode":
        if len(params) != 2 or str(params[0]).lower() not in addresses:
            raise ApprovalError("rpc_address_not_admitted")
    elif method == "eth_call":
        if len(params) != 2 or not isinstance(params[0], dict) or set(params[0]) != {"to", "data"}:
            raise ApprovalError("rpc_call_not_admitted")
        call, data = params[0], params[0].get("data", "")
        if (str(call.get("to", "")).lower() not in addresses or not isinstance(data, str)
                or not re.fullmatch(r"0x[0-9a-fA-F]+", data) or data[:10] not in binding["call_selectors"]):
            raise ApprovalError("rpc_call_not_admitted")
        if data[:10] == "0x70a08231":
            if len(data) != 74 or data[10:34] != "0" * 24 or "0x" + data[-40:].lower() not in addresses:
                raise ApprovalError("rpc_balance_scope_not_admitted")
        elif data[:10] == "0xe6a43905":
            if (len(data) != 138 or data[10:34] != "0" * 24 or data[74:98] != "0" * 24
                    or {"0x" + data[34:74].lower(), "0x" + data[-40:].lower()} - addresses
                    or call["to"].lower() != str(binding.get("factory_address", "")).lower()):
                raise ApprovalError("rpc_pair_scope_not_admitted")
        elif len(data) != 10:
            raise ApprovalError("rpc_selector_arguments_not_admitted")
    elif method == "eth_getLogs":
        if len(params) != 1 or not isinstance(params[0], dict):
            raise ApprovalError("rpc_logs_not_admitted")
        scope = params[0]
        if (set(scope) - {"address", "topics", "blockHash"} or scope.get("blockHash") != pinned_hash
                or str(scope.get("address", "")).lower() not in {value.lower() for value in binding["pool_addresses"]}):
            raise ApprovalError("rpc_logs_not_admitted")
    if method in {"eth_call", "eth_getCode"} and (
        not pinned_hash or params[-1] != {"blockHash": pinned_hash, "requireCanonical": True}
    ):
        raise ApprovalError("rpc_block_not_admitted")



def _check_payload(payload: dict, plan: dict, action: str, when: datetime, request: dict | None = None) -> None:
    _bind_plan(payload, plan)
    if action not in payload["operations"]:
        raise ApprovalError("operation_not_admitted")
    if not parse_time(payload["not_before"]) <= when < parse_time(payload["expires_at"]):
        raise ApprovalError("approval_outside_time_window")
    if action.startswith("source."):
        _require_subset(plan["source"]["allowed_hosts"], payload["allowed_hosts"], "source_hosts_not_admitted")
        budgets, session = payload["budget_ceilings"], plan["limits"]["session"]
        for key, ceiling in (("max_requests", "source_requests"), ("max_pages", "source_pages"), ("max_captures", "total_captures"), ("max_elapsed_s", "session_duration_s")):
            if session[key] > budgets[ceiling]:
                raise ApprovalError("source_session_limits_exceed_approval")
        if request is not None:
            _check_source_scope(request, plan, payload, when)
    elif action == "model.classify":
        _check_model_request(payload, plan, request or {})
    elif action == "observations.read":
        _check_observation_request(payload, plan, request or {})


def _check_source_scope(scope: dict, plan: dict, payload: dict, when: datetime) -> None:
    if scope["owner"] != plan["source"]["owner"] or scope["profile"] != plan["source"]["profile"]:
        raise ApprovalError("scope_owner_mismatch")
    _require_subset(scope["allowed_hosts"], plan["source"]["allowed_hosts"], "scope_host_mismatch")
    reference = scope.get("plan_ref")
    if reference and "plan_id" in reference and (
        reference["plan_id"] != plan["plan_id"]
        or reference["revision"] != plan["revision"]
        or reference["digest"] != plan_digest(plan)
    ):
        raise ApprovalError("scope_plan_mismatch")
    started, deadline = parse_time(scope["started_at"]), parse_time(scope["deadline"])
    if deadline <= started or when >= deadline or started > when:
        raise ApprovalError("scope_deadline_expired_or_invalid")
    if deadline > parse_time(payload["expires_at"]):
        raise ApprovalError("scope_deadline_exceeds_approval")
    elapsed = (deadline - started).total_seconds()
    if elapsed > scope["limits"]["max_elapsed_s"]:
        raise ApprovalError("scope_deadline_exceeds_operation_limit")
    poll = plan["limits"]["poll"]
    for key, value in scope["limits"].items():
        ceiling = poll.get(key, poll["max_captures"] if key == "max_primary" else 0)
        if value > ceiling:
            raise ApprovalError("scope_limits_exceed_plan")
    ceilings = payload["budget_ceilings"]
    for key, ceiling in (("max_requests", "source_requests"), ("max_pages", "source_pages"), ("max_captures", "total_captures"), ("max_elapsed_s", "operation_timeout_s")):
        if scope["limits"][key] > ceilings[ceiling]:
            raise ApprovalError("scope_limits_exceed_approval")
    if payload["envelope"] and scope["limits"]["max_context"] and not payload["envelope"]["allow_related_context"]:
        raise ApprovalError("related_context_not_admitted")
    if scope["operation"] == "search":
        reference = scope["query_ref"] or {}
        matches = [query for query in plan["queries"] if query["id"] == reference.get("query_id") and query["revision"] == reference.get("revision")]
        if len(matches) != 1 or scope["expression"] != matches[0]["expression"] or scope["product"] != matches[0]["product"]:
            raise ApprovalError("scope_query_mismatch")
    elif scope["target"] not in plan["source"].get("allowed_targets", {}).get(scope["operation"], []):
        raise ApprovalError("scope_target_not_admitted")
    start, end = scope.get("interval_start"), scope.get("interval_end")
    if (start is None) != (end is None) or (start and (parse_time(start) > parse_time(end) or parse_time(end) > deadline)):
        raise ApprovalError("scope_interval_invalid")


def resolve_approval(vault, plan: dict, action: str, *, approval_ref: str | None = None, request: dict | None = None, now: datetime | None = None) -> dict:
    """Resolve a signed host grant; runtime accounting must reserve before dispatch."""
    plan = validate_record("monitor-plan", plan)
    plan_digest(plan)
    trust = read_host_trust(vault.config.x.trust_store)
    candidates = [approval_ref] if approval_ref else list(dict.fromkeys([vault.config.x.approval_ref, *plan["authority_refs"]]))
    candidates = [ref for ref in candidates if ref]
    if not candidates:
        raise ApprovalError("approval_not_configured")
    when, refusals = now or utc_now(), []
    for ref in candidates:
        try:
            validate_artifact_path(ref)
            envelope = _json(_protected_read(Path(trust["grant_root"]) / PurePosixPath(ref)))
            payload, raw = _verify_envelope(envelope, trust["keys"])
            if payload["approval_id"] in trust["revoked_approval_ids"]:
                raise ApprovalError("approval_revoked")
            _check_payload(payload, plan, action, when, request)
            return {
                "approval_ref": ref, "approval_id": payload["approval_id"],
                "grant_digest": hashlib.sha256(raw).hexdigest(), "admitted_at": timestamp(when),
                "request_id": (request or {}).get("request_id") or (request or {}).get("reservation", {}).get("request_id"),
                "budget_ceilings": payload["budget_ceilings"], "export_policy": payload["export_policy"],
                "payload": payload, "approval_envelope": envelope,
                "trust": {"key_id": envelope["key_id"], "public_key_b64": trust["keys"][envelope["key_id"]], "trust_store_digest": trust["trust_store_digest"]},
            }
        except (ApprovalError, ValueError) as exc:
            refusals.append(getattr(exc, "code", "invalid_approval_contract"))
    raise ApprovalError(refusals[0] if len(refusals) == 1 else "no_applicable_approval")


def configured_plan(vault) -> tuple[dict, dict]:
    from hyperresearch.core.x_evidence import EvidenceStore

    if not vault.config.x.plan_ref:
        raise ApprovalError("governed_plan_not_configured")
    store = EvidenceStore(vault.root)
    ref = store.ref_from_path(vault.config.x.plan_ref)
    plan = store.get_record(ref, "monitor-plan")
    plan_digest(plan)
    return plan, ref


def authorize_source_scope(vault, scope: dict, *, plan: dict | None = None, approval_ref: str | None = None) -> dict:
    """Provider seam: enrich a governed scope only after protected host admission."""
    if not vault.config.x.enabled:
        raise ApprovalError("native_x_disabled")
    scope = validate_record("source-scope", scope)
    if plan is None:
        plan, ref = configured_plan(vault)
    else:
        from hyperresearch.core.x_evidence import EvidenceStore
        plan = validate_record("monitor-plan", plan)
        ref = EvidenceStore(vault.root).put_record("monitor-plan", plan)
    action = "source." + scope["operation"]
    admitted = resolve_approval(vault, plan, action, approval_ref=approval_ref or scope.get("approval_ref"), request=scope)
    config = vault.config.x
    if (config.source_owner and config.source_owner != scope["owner"]) or (config.source_profile and config.source_profile != scope["profile"]):
        raise ApprovalError("configured_source_identity_mismatch")
    limits = scope["limits"]
    if limits["max_requests"] > config.max_source_requests or limits["max_pages"] > config.max_pages or limits["max_captures"] > config.max_total_captures or limits.get("max_primary", limits["max_captures"]) > config.max_primary or limits["max_elapsed_s"] > config.operation_timeout_s:
        raise ApprovalError("scope_exceeds_configured_limits")
    return validate_record("source-scope", {
        **scope, "approval_ref": admitted["approval_ref"],
        "plan_ref": {"plan_id": plan["plan_id"], "revision": plan["revision"], "digest": plan_digest(plan), "artifact_ref": ref},
    })


def authority_snapshot(vault, admissions: list[dict], *, evidence_refs: list[dict] | None = None) -> dict:
    trust = read_host_trust(vault.config.x.trust_store)
    for admission in admissions:
        if admission["trust"]["trust_store_digest"] != trust["trust_store_digest"]:
            raise ApprovalError("authority_changed_during_admission")
    snapshot = {
        "schema_version": 1, "purpose": "x-research-authority-snapshot",
        "trust_store_digest": trust["trust_store_digest"], "trusted_keys": trust["keys"],
        "admitted_grants": [{key: admission[key] for key in ("approval_id", "grant_digest", "approval_ref")} for admission in admissions],
        "captured_at": timestamp(utc_now()),
        "evidence_refs": list(evidence_refs or []),
    }
    return validate_record("authority-snapshot", snapshot)


def validate_snapshot_anchor(vault, snapshot: dict) -> dict:
    """Production import requires independent protected host keys, not self-attestation."""
    value = validate_record("authority-snapshot", snapshot)
    trust = read_host_trust(vault.config.x.trust_store)
    for key, public in value["trusted_keys"].items():
        if trust["keys"].get(key) != public:
            raise ApprovalError("snapshot_key_not_host_trusted")
    return value


def verify_observation_admission(plan: dict, request: dict, admission: dict, *, trusted_digest: str, trusted_keys: dict) -> dict:
    """Pure historical verification; caller supplies its admitted frozen trust anchor."""
    if not trusted_keys or admission.get("trust", {}).get("trust_store_digest") != trusted_digest:
        raise ApprovalError("observation_anchor_mismatch")
    payload, raw = _verify_envelope(admission.get("approval_envelope", {}), trusted_keys)
    if admission.get("grant_digest") != hashlib.sha256(raw).hexdigest() or admission.get("approval_id") != payload["approval_id"] or admission.get("payload") != payload:
        raise ApprovalError("observation_admission_digest_mismatch")
    _check_payload(payload, validate_record("monitor-plan", plan), "observations.read", parse_time(admission["admitted_at"]), request)
    return payload
