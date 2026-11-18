"""Small read-only observation registry and reproducible, versioned evidence predicates.

Only ``observe`` performs I/O. Predicate/decoder functions read frozen artifacts, never
resolve DNS, refresh a measurement, load a model, or accept a ``verified`` input flag.
The supported EVM decoder is deliberately Uniswap-v2, not an arbitrary ABI/plugin.
Public API references (researched through Agent Reach's web route):
https://ethereum.org/en/developers/docs/apis/json-rpc/
https://docs.dexscreener.com/api/reference
https://github.com/Uniswap/v2-core/blob/master/contracts/interfaces/IUniswapV2Pair.sol
"""

from __future__ import annotations

import json
import re
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from decimal import Decimal, InvalidOperation, localcontext
from types import MappingProxyType
from typing import Any
from urllib.parse import urlsplit

import httpx

from hyperresearch.models.x_evidence import (
    canonical_bytes,
    plan_digest,
    record_digest,
    validate_record,
)
from hyperresearch.web.safe_http import SafeHTTPError, check_url

CRYPTO_RULE = {"id": "hpr.crypto-evidence", "revision": 1}
FLOW_RULE = {"id": "hpr.market-flow", "revision": 1}
ACTOR_RULE = {"id": "hpr.actor-association", "revision": 1}
COHERENCE_RULE = {"id": "hpr.snapshot-coherence", "revision": 1}
MAX_OBSERVATION_BYTES = 2 * 1024 * 1024
_DEX_CHAINS = {"eip155:1": "ethereum", "eip155:56": "bsc", "eip155:137": "polygon",
               "eip155:42161": "arbitrum", "eip155:10": "optimism", "eip155:8453": "base"}
_DEX_PAIR_BASE = "https://api.dexscreener.com/latest/dex/pairs"
_DEX_LEAD_BASE = "https://api.dexscreener.com/token-pairs/v1"

# Keccak event hashes for the exact canonical v2 ABI (not hashlib.sha3_256).
V2_TOPICS = {
    "swap": "0xd78ad95fa46c994b6551d0da85fc275fe613ce37657fb8d5e3d130840159d822",
    "liquidity-add": "0x4c209b5fc8ad50758f13e2e1088ba56a560dff690a1c6fef26394f4c03821c4f",
    "liquidity-remove": "0xdccd412f0b1252819cb1fd330b93224ca42612892bb3f4f789976e6d81936496",
    "reserves": "0x1c411e9a96e071241c2f21f7726b17ae89e3cab4c78be50e062b03a9fffbbad1",
}
CALL_SELECTORS = {
    "token0": "0x0dfe1681", "token1": "0xd21220a7", "decimals": "0x313ce567",
    "totalSupply": "0x18160ddd", "getReserves": "0x0902f1ac",
    "balanceOf": "0x70a08231",
    "factory": "0xc45a0155", "getPair": "0xe6a43905",
}
EVM_ADDRESS = re.compile(r"0x[0-9a-fA-F]{40}\Z")
EVM_HASH = re.compile(r"0x[0-9a-fA-F]{64}\Z")
DECIMAL = re.compile(r"-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?\Z")
HEX_QUANTITY = re.compile(r"0x(?:0|[1-9a-fA-F][0-9a-fA-F]*)\Z")


@dataclass(frozen=True)
class EvidenceResult:
    """Ephemeral reducer result; the governed observation/event remains the wire authority."""

    known: bool
    reasons: tuple[str, ...] = ()
    facts: dict[str, Any] | None = None


def instant(value: str | datetime) -> datetime:
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00")) if isinstance(value, str) else value
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ValueError("An explicit timezone is required")
    return parsed.astimezone(UTC)


def timestamp(value: datetime) -> str:
    return instant(value).isoformat().replace("+00:00", "Z")


def decimal(value: Any, *, nonnegative: bool = False) -> Decimal:
    """Reject floats/exponents/NaN rather than silently round a measured quantity."""
    if not isinstance(value, str) or len(value) > 2048 or not DECIMAL.fullmatch(value):
        raise ValueError("A finite decimal-string quantity is required")
    try:
        result = Decimal(value)
    except InvalidOperation as exc:
        raise ValueError("Invalid decimal quantity") from exc
    if not result.is_finite() or (nonnegative and result < 0):
        raise ValueError("Invalid decimal sign or magnitude")
    return result


def decimal_text(value: Decimal) -> str:
    text = format(value, "f")
    if "." in text:
        text = text.rstrip("0").rstrip(".")
    return "0" if value == 0 else text


def raw_units(value: int, decimals: int) -> str:
    if isinstance(decimals, bool) or not isinstance(decimals, int) or not 0 <= decimals <= 255:
        raise ValueError("Invalid on-chain decimals")
    if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value < 2**256:
        raise ValueError("Invalid uint256 amount")
    with localcontext() as context:
        context.prec = 600
        return decimal_text(Decimal(value).scaleb(-decimals))


def address(value: Any) -> str:
    if not isinstance(value, str) or not EVM_ADDRESS.fullmatch(value):
        raise ValueError("An exact EVM contract/wallet address is required")
    return value.lower()


def block_hash(value: Any) -> str:
    if not isinstance(value, str) or not EVM_HASH.fullmatch(value):
        raise ValueError("An exact block/transaction hash is required")
    return value.lower()


def hex_quantity(value: Any) -> int:
    if not isinstance(value, str) or not HEX_QUANTITY.fullmatch(value):
        raise ValueError("Invalid JSON-RPC hex quantity")
    return int(value, 16)


def abi_words(value: Any, count: int) -> list[int]:
    if not isinstance(value, str) or not re.fullmatch(rf"0x[0-9a-fA-F]{{{64 * count}}}", value):
        raise ValueError("Incorrect ABI data width")
    return [int(value[2 + offset * 64:2 + (offset + 1) * 64], 16) for offset in range(count)]


def abi_address(value: Any) -> str:
    words = abi_words(value, 1)
    if words[0] >= 2**160:
        raise ValueError("Nonzero address ABI padding")
    return "0x" + format(words[0], "040x")


def decode_v2_log(log: dict, *, pool: str, token0: str, token1: str,
                  decimals0: int, decimals1: int) -> dict:
    """Decode a pinned v2 log; transfers are deliberately not accepted as flows.

    Amounts are pool-perspective changes. A token's customer net purchase is
    ``amount_out - amount_in``. Sender/recipient are observed addresses, NOT a
    verified human, a market maker, or necessarily the end-user of a router.
    """
    if address(log.get("address")) != address(pool):
        raise ValueError("Log belongs to another pool")
    topics = log.get("topics")
    if not isinstance(topics, list) or not topics:
        raise ValueError("Missing event signature")
    reverse = {value: key for key, value in V2_TOPICS.items()}
    event = reverse.get(str(topics[0]).lower())
    if event is None:
        raise ValueError("Not an admitted decoded swap/liquidity event")
    widths = {"swap": (3, 4), "liquidity-add": (2, 2),
              "liquidity-remove": (3, 2), "reserves": (1, 2)}
    topic_count, word_count = widths[event]
    if len(topics) != topic_count:
        raise ValueError("Incorrect indexed event fields")
    words = abi_words(log.get("data"), word_count)
    sender = abi_address(topics[1]) if topic_count > 1 else None
    recipient = abi_address(topics[2]) if topic_count > 2 else None
    if event == "swap":
        legs = [(words[0], words[2]), (words[1], words[3])]
        if not any(leg[0] for leg in legs) or not any(leg[1] for leg in legs):
            raise ValueError("Invalid swap input/output")
    elif event == "liquidity-add":
        legs = [(words[0], 0), (words[1], 0)]
    elif event == "liquidity-remove":
        legs = [(0, words[0]), (0, words[1])]
    else:
        if any(word >= 2**112 for word in words):
            raise ValueError("Invalid uint112 reserve")
        legs = [(words[0], 0), (words[1], 0)]
    if type(log.get("removed")) is not bool:
        raise ValueError("Log removal state is unknown")
    return {
        "kind": event, "chain_event": {
            "block_hash": block_hash(log.get("blockHash")),
            "block_number": hex_quantity(log.get("blockNumber")),
            "transaction_hash": block_hash(log.get("transactionHash")),
            "log_index": hex_quantity(log.get("logIndex")),
        },
        "removed": log["removed"], "sender": sender, "recipient": recipient,
        "legs": [
            {"contract_address": address(token), "decimals": places,
             "amount_in_raw": str(amount_in), "amount_out_raw": str(amount_out),
             "amount_in": raw_units(amount_in, places),
             "amount_out": raw_units(amount_out, places)}
            for token, places, (amount_in, amount_out) in zip(
                (token0, token1), (decimals0, decimals1), legs, strict=True
            )
        ],
    }


def _https_endpoint(url: str, allowed_hosts: list[str]) -> str:
    parsed = urlsplit(url)
    if (parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password
            or parsed.query or parsed.fragment or parsed.port not in (None, 443)
            or parsed.hostname.lower() not in {host.lower() for host in allowed_hosts}):
        raise ValueError("Observation endpoint is outside exact HTTPS host scope")
    return url


def _http_json(url: str, *, method: str, payload: dict | None, max_bytes: int,
               timeout_s: float, before_emit: Callable[[], None] | None = None,
               deadline: datetime | None = None) -> tuple[Any, bytes]:
    """Bounded TLS/SSRF-checked reads, with admission rechecked at emission."""
    if method not in {"GET", "POST"}:
        raise ValueError("Unsupported read-only HTTP method")
    check_url(url)
    with httpx.Client(follow_redirects=False, timeout=timeout_s,
                      verify=True, trust_env=False) as client:
        if before_emit is not None:
            before_emit()
        if deadline is not None and datetime.now(UTC) >= deadline:
            raise TimeoutError("Observation emission deadline expired")
        kwargs = {"json": payload} if method == "POST" else {}
        with client.stream(method, url, headers={"Accept": "application/json"}, **kwargs) as response:
            if response.status_code != 200:
                raise SafeHTTPError(f"Observation HTTP status {response.status_code}")
            declared = response.headers.get("content-length", "")
            if declared.isdigit() and int(declared) > max_bytes:
                raise SafeHTTPError("Observation response exceeds byte cap")
            buffer = bytearray()
            for chunk in response.iter_bytes():
                if deadline is not None and datetime.now(UTC) >= deadline:
                    raise TimeoutError("Observation response deadline expired")
                if len(buffer) + len(chunk) > max_bytes:
                    raise SafeHTTPError("Observation response exceeds byte cap")
                buffer.extend(chunk)
            data = bytes(buffer)
    result = json.loads(data, parse_float=Decimal,
                        parse_constant=lambda value: (_ for _ in ()).throw(ValueError(value)))
    if not isinstance(result, (dict, list)):
        raise ValueError("Observation response must be a JSON object or array")
    return _json_decimals(result), data



def _json_decimals(value: Any) -> Any:
    if isinstance(value, Decimal):
        return decimal_text(value)
    if isinstance(value, list):
        return [_json_decimals(item) for item in value]
    if isinstance(value, dict):
        return {key: _json_decimals(item) for key, item in value.items()}
    return value


def _entity(binding: dict, *, contract: str | None = None, pool: str | None = None) -> dict:
    chain = binding["chain_id"]
    namespace = "chain-pool" if pool else "chain-contract"
    identifier = pool or contract
    return {
        "namespace": namespace, "entity_id": f"{chain}:{identifier}",
        "chain_id": chain, "contract_address": contract,
        "pool_address": pool, "venue": binding["venue"],
    }


def _request(store: Any, plan: dict, binding: dict, *, entity: dict,
             method: str, endpoint: str, rpc_method: str | None = None,
             params: list | None = None, proof_refs: list[dict] | None = None,
             authorize: Callable[[dict], dict],
             on_evidence: Callable[[dict], None] | None = None,
             revalidate: Callable[[dict, dict], None] | None = None,
             on_undispatched: Callable[[str], None] | None = None) -> tuple[Any, dict]:
    """Admission happens before DNS/network and is durable in the raw evidence closure."""
    from hyperresearch.models.x_evidence import validate_definition

    _https_endpoint(endpoint, binding["allowed_hosts"])
    if rpc_method is not None:
        if rpc_method not in binding["rpc_methods"]:
            raise ValueError("RPC method is outside the declared binding")
        if rpc_method == "eth_call":
            call = (params or [])[0]
            selector = str(call.get("data", ""))[:10]
            if selector not in binding["call_selectors"]:
                raise ValueError("RPC call selector is outside the declared binding")
            destinations = binding["contract_addresses"] + binding["pool_addresses"]
            if binding.get("factory_address"):
                destinations = [*destinations, binding["factory_address"]]
            if address(call.get("to")) not in {address(value) for value in destinations}:
                raise ValueError("RPC call target is outside the declared binding")
    request = {
        "action": "observations.read", "plan_id": plan["plan_id"],
        "plan_digest": plan["digest"], "plan_revision": plan["revision"],
        "binding_id": binding["binding_id"], "adapter": binding["id"],
        "endpoint": endpoint, "entity": entity, "method": method,
        "rpc_method": rpc_method, "params": params or [],
        "requests": 1, "timeout_s": 30, "max_bytes": MAX_OBSERVATION_BYTES,
    }
    proof_refs = proof_refs or []
    request["proof_refs"] = proof_refs
    request["proof_rows"] = []
    for ref in proof_refs:
        proof = validate_definition("observation-evidence", json.loads(store.read_blob(ref)))
        if not proof["admission_ref"]:
            raise PermissionError("Descendant scope needs an independently admitted parent")
        request["proof_rows"].append({
            "request": proof["request"], "response": proof["response"],
            "admission": json.loads(store.read_blob(proof["admission_ref"])),
        })
    if binding.get("_lead_capture_ref"):
        request.update({
            "lead_capture_ref": binding["_lead_capture_ref"],
            "lead_source_span": binding["_lead_source_span"],
            "lead_capture": binding["_lead_capture"],
        })
    admission = authorize(request)
    required = {"approval_ref", "approval_id", "grant_digest", "admitted_at", "request_id",
                "budget_ceilings", "payload", "approval_envelope", "trust"}
    if not isinstance(admission, dict) or not required.issubset(admission):
        raise PermissionError("Observation admission must be an independently resolved grant")
    ceilings = admission["budget_ceilings"]
    if ceilings.get("observation_requests", 0) < 1 or ceilings.get("observation_timeout_s", 0) < 1:
        raise PermissionError("Observation grant has no request/time budget")
    from hyperresearch.core.x_authority import parse_time
    deadline = parse_time(admission.get("deadline_at", admission["payload"]["expires_at"]))
    remaining = (deadline - datetime.now(UTC)).total_seconds()
    timeout_s = min(request["timeout_s"], ceilings["observation_timeout_s"], remaining)
    emitted = False

    def before_emit() -> None:
        nonlocal emitted
        if revalidate is not None:
            revalidate(request, admission)
        if timeout_s <= 0 or datetime.now(UTC) >= deadline:
            raise TimeoutError("Observation admission deadline expired")
        # From this point any transport failure may have dispatched; keep its reservation.
        emitted = True

    try:
        if timeout_s <= 0:
            raise TimeoutError("Observation admission deadline expired")
        admission_ref = store.put_blob(canonical_bytes(admission), category="support")
        rpc_payload = ({"jsonrpc": "2.0", "id": 1, "method": rpc_method, "params": params or []}
                       if rpc_method is not None else None)
        response, raw_body = _http_json(endpoint, method=method, payload=rpc_payload,
                            max_bytes=MAX_OBSERVATION_BYTES, timeout_s=timeout_s,
                            before_emit=before_emit, deadline=deadline)
    except Exception:
        if not emitted and on_undispatched is not None:
            on_undispatched(admission["request_id"])
        raise
    raw_response_ref = store.put_blob(raw_body, category="source")
    envelope = validate_definition("observation-evidence", {
        "schema_version": 1, "adapter": binding["id"], "binding_id": binding["binding_id"],
        "endpoint": endpoint, "entity": entity,
        "request": request, "response": response,
        "raw_response_ref": raw_response_ref,
        "observed_at": timestamp(datetime.now(UTC)), "admission_ref": admission_ref,
    })
    ref = store.put_blob(canonical_bytes(envelope), category="support")
    if on_evidence is not None:
        # The observer, not an imported label or admission, owns these returned bytes.
        # Notify after both blobs are durable, including genuine error replies.
        on_evidence(ref)
    if rpc_method is not None:
        if not isinstance(response, dict) or response.get("jsonrpc") != "2.0" or response.get("id") != 1 or "error" in response:
            raise ValueError("JSON-RPC observation returned an error or mismatched request")
        if "result" not in response:
            raise ValueError("JSON-RPC result is missing")
    return response, ref


def _observation(store: Any, binding: dict, *, entity: dict, metric: str,
                 as_of: str, evidence_refs: list[dict], quantity: str | None = None,
                 units: str | None = None, cap_kind: str | None = None,
                 basis: str, event: dict | None = None,
                 constituents: list[dict] | None = None,
                 block_identity: str | None = None) -> dict:
    from hyperresearch import __version__

    first = json.loads(store.read_blob(evidence_refs[0]))
    observed_at = max(json.loads(store.read_blob(ref))["observed_at"] for ref in evidence_refs)
    identity = {"binding": binding["binding_id"], "entity": entity, "metric": metric,
                "cap_kind": cap_kind, "basis": basis,
                "as_of": as_of, "block": block_identity or binding["block_hash"],
                "event": {"block_hash": event["block_hash"],
                          "transaction_hash": event["transaction_hash"],
                          "log_index": event["log_index"],
                          "venue_sequence": event["venue_sequence"]} if event else None}
    observation_id = "obs-" + record_digest(identity)
    previous = []
    for ref in store.list_records("verified-observation"):
        old = store.get_record(ref, "verified-observation")
        if old["observation_id"] == observation_id:
            previous.append((old["revision"], ref))
    previous.sort(key=lambda item: (item[0], item[1]["sha256"]))
    prior = previous[-1][1] if previous else None
    removed = event is not None and event["removed"]
    payload = {
        "schema_version": 1, "observation_id": observation_id,
        "revision": previous[-1][0] + 1 if previous else 1,
        "domain": "market" if metric in {"swap", "liquidity-add", "liquidity-remove", "reserves"}
        else "crypto",
        "entity": entity, "metric": metric, "quantity": quantity, "units": units,
        "cap_kind": cap_kind, "observed_at": observed_at, "as_of": as_of,
        "evaluation_time": observed_at,
        "measurement_scope": {
            "scope_id": entity["entity_id"],
            "aggregation": "pool" if entity["pool_address"] else "contract",
            "chain_id": entity["chain_id"],
            "pool_refs": [entity] if entity["pool_address"] else [],
            "venue": entity["venue"], "constituent_refs": constituents or [],
        },
        "source": {"method": binding["id"], "binding_id": binding["binding_id"],
                   "basis": basis, "evidence_refs": evidence_refs,
                   "admission_ref": first["admission_ref"], "endpoint": binding["endpoint"]},
        # These are truthful producer states. The reducer independently reruns the predicates.
        "verification": {"rule_id": binding["verification_rule"]["id"],
                         "revision": binding["verification_rule"]["revision"],
                         "state": "unverified", "reasons": ["awaiting-deterministic-reduction"],
                         "input_refs": evidence_refs},
        "coherence": {
            **binding["coherence"], "state": "unknown", "as_of_basis": None,
            "input_refs": evidence_refs, "reasons": ["awaiting-cross-evidence-join"],
        },
        "association": {"assertion": "unknown", "observed": "present" if event else "unknown",
                        "verified": "unknown", "attribution_refs": []},
        "event": event,
        "correction": {"state": "reorg" if removed else "corrected" if prior else "original",
                       "supersedes": prior, "retracts": [prior] if removed and prior else [],
                       "reason": "removed-log" if removed else None},
        "producer": {"product": "hyperresearch", "version": __version__, "runtime": "python",
                     "extension_version": None, "owner": None, "profile": None},
    }
    return store.put_record("verified-observation", validate_record("verified-observation", payload))


def _collect_evm(store: Any, plan: dict, binding: dict,
                 authorize: Callable[[dict], dict],
                 on_evidence: Callable[[dict], None] | None = None,
                 prior_observation_refs: list[dict] | None = None,
                 revalidate: Callable[[dict, dict], None] | None = None,
                 on_undispatched: Callable[[str], None] | None = None) -> list[dict]:
    """Collect admitted pinned/tagged snapshots, not continuous chain coverage."""
    if binding["verification_rule"] not in (CRYPTO_RULE, FLOW_RULE):
        raise ValueError("Unsupported EVM observation predicate version")
    crypto = binding["verification_rule"] == CRYPTO_RULE
    endpoint = binding["endpoint"]
    if not endpoint or not re.fullmatch(r"eip155:[1-9][0-9]*", binding["chain_id"] or ""):
        raise ValueError("EVM observations need an exact endpoint and chain")
    contracts = [address(value) for value in binding["contract_addresses"]]
    pools = [address(value) for value in binding["pool_addresses"]]
    anchor_entity = _entity(binding, contract=contracts[0] if contracts else None,
                            pool=pools[0] if pools else None)
    if not contracts and not pools:
        raise ValueError("EVM observations need explicitly scoped contracts or pools")

    common: list[dict] = []

    def rpc(method: str, params: list, entity: dict, *,
            proof_refs: list[dict] | None = None) -> tuple[Any, dict]:
        response, ref = _request(store, plan, binding, entity=entity, method="POST",
                                 endpoint=endpoint, rpc_method=method, params=params,
                                 proof_refs=common + (proof_refs or []), authorize=authorize,
                                 on_evidence=on_evidence, revalidate=revalidate,
                                 on_undispatched=on_undispatched)
        return response["result"], ref

    chain, chain_ref = rpc("eth_chainId", [], anchor_entity)
    if hex_quantity(chain) != int(binding["chain_id"].split(":")[1]):
        raise ValueError("RPC returned another chain")
    block_policy = binding.get("block_policy", "pinned")
    if block_policy in {"rolling-latest", "rolling-finalized"}:
        if binding["block_number"] is not None or binding["block_hash"] is not None:
            raise ValueError("Rolling snapshots require null static block pins")
        tag = "latest" if block_policy == "rolling-latest" else "finalized"
        header, header_ref = rpc("eth_getBlockByNumber", [tag, False], anchor_entity)
    elif block_policy != "pinned":
        raise ValueError("Unsupported block sampling policy")
    elif binding["block_number"] is not None:
        header, header_ref = rpc("eth_getBlockByNumber", [hex(binding["block_number"]), False], anchor_entity)
    elif binding["block_hash"]:
        header, header_ref = rpc("eth_getBlockByHash", [binding["block_hash"], False], anchor_entity)
    else:
        raise ValueError("An explicit frozen block is required")
    if not isinstance(header, dict):
        raise ValueError("Admitted block is unavailable")
    height, digest = hex_quantity(header.get("number")), block_hash(header.get("hash"))
    if binding["block_hash"] and digest != binding["block_hash"].lower():
        return _record_reorg(store, binding, [chain_ref, header_ref], header,
                             previous_refs=prior_observation_refs)
    as_of = timestamp(datetime.fromtimestamp(hex_quantity(header.get("timestamp")), UTC))
    pinned = {"blockHash": digest, "requireCanonical": True}
    common = [chain_ref, header_ref]
    if block_policy == "pinned" and binding["block_number"] is None:
        canonical, canonical_ref = rpc("eth_getBlockByNumber", [hex(height), False], anchor_entity)
        if not isinstance(canonical, dict) or canonical.get("hash") != digest:
            return _record_reorg(store, binding, [chain_ref, canonical_ref], canonical,
                                 previous_refs=prior_observation_refs)
        common.append(canonical_ref)
    outputs = []
    if block_policy != "pinned":
        # Only independently qualified prior snapshots are eligible. A foreign
        # imported record cannot manufacture a historical network read.
        sampled = {}
        verifier = ObservationVerifier(store, plan)
        for old_ref in prior_observation_refs or []:
            old = store.get_record(old_ref, "verified-observation")
            if (old["source"]["binding_id"] != binding["binding_id"]
                    or old["correction"]["state"] in {"reorg", "retracted"}):
                continue
            old_rows = [json.loads(store.read_blob(ref)) for ref in old["source"]["evidence_refs"]]
            if any(row["request"].get("plan_digest") != plan["digest"] for row in old_rows):
                continue
            snapshot = verifier._chain(binding, old_rows)
            sampled.setdefault(snapshot["block_number"], []).append(
                (snapshot["block_hash"], old_ref, old["source"]["evidence_refs"]))
        for old_height, snapshots in sorted(sampled.items()):
            if old_height == height:
                canonical, canonical_ref = header, header_ref
            else:
                proof_refs = list({ref_key(ref): ref for _, _, refs in snapshots for ref in refs}.values())
                canonical, canonical_ref = rpc("eth_getBlockByNumber", [hex(old_height), False],
                                               anchor_entity, proof_refs=proof_refs)
            if not isinstance(canonical, dict) or hex_quantity(canonical.get("number")) != old_height:
                raise ValueError("Previously sampled canonical header is unavailable")
            canonical_hash = block_hash(canonical.get("hash"))
            changed = [ref for old_hash, ref, _ in snapshots if old_hash != canonical_hash]
            if changed:
                # A tag read is not a by-number proof; freeze that exact query.
                if old_height == height:
                    canonical, canonical_ref = rpc("eth_getBlockByNumber", [hex(old_height), False],
                                                   anchor_entity)
                outputs.extend(_record_reorg(store, binding, [chain_ref, canonical_ref], canonical,
                                              previous_refs=changed))
    token_proofs: dict[str, tuple[int, list[dict]]] = {}

    def call(target: str, name: str, entity: dict, argument: str = "") -> tuple[Any, dict]:
        return rpc("eth_call", [{"to": target, "data": CALL_SELECTORS[name] + argument}, pinned],
                   entity)

    for contract in contracts:
        entity = _entity(binding, contract=contract)
        code, code_ref = rpc("eth_getCode", [contract, pinned], entity)
        evidence = [*common, code_ref]
        if not isinstance(code, str) or not re.fullmatch(r"0x(?:[0-9a-fA-F]{2})+", code):
            raise ValueError("Scoped contract has no deployed bytecode")
        raw_decimals, decimals_ref = call(contract, "decimals", entity)
        places = abi_words(raw_decimals, 1)[0]
        if not 0 <= places <= 255:
            raise ValueError("Token decimals exceed the supported exact-unit range")
        token_proofs[contract] = (places, [*evidence, decimals_ref])
        if not crypto:
            continue
        raw_supply, supply_ref = call(contract, "totalSupply", entity)
        supply = abi_words(raw_supply, 1)[0]
        outputs.append(_observation(
            store, binding, entity=entity, metric="total-supply", as_of=as_of,
            evidence_refs=[*evidence, decimals_ref, supply_ref],
            quantity=raw_units(supply, places), units=f"token:{binding['chain_id']}:{contract}",
            basis="erc20-totalSupply-at-canonical-block", block_identity=digest,
        ))
        exclusions = binding.get("excluded_supply_addresses", [])
        if exclusions:
            excluded = 0
            excluded_refs = []
            for wallet in sorted({address(value) for value in exclusions}):
                raw_balance, balance_ref = call(contract, "balanceOf", entity,
                                                 address(wallet)[2:].rjust(64, "0"))
                excluded += abi_words(raw_balance, 1)[0]
                excluded_refs.append(balance_ref)
            if excluded > supply:
                raise ValueError("Excluded balances exceed total supply")
            outputs.append(_observation(
                store, binding, entity=entity, metric="circulating-supply", as_of=as_of,
                evidence_refs=[*evidence, decimals_ref, supply_ref, *excluded_refs],
                quantity=raw_units(supply - excluded, places),
                units=f"token:{binding['chain_id']}:{contract}",
                basis="declared-totalSupply-minus-excluded-balances-v1", block_identity=digest,
            ))
    if crypto and binding["deployment_tx_hash"]:
        receipt, receipt_ref = rpc("eth_getTransactionReceipt",
                                   [binding["deployment_tx_hash"]], anchor_entity)
        if (not isinstance(receipt, dict) or receipt.get("contractAddress") is None
                or hex_quantity(receipt.get("status")) != 1):
            raise ValueError("Creation receipt does not establish a successful deployment")
        deployed = address(receipt["contractAddress"])
        if deployed not in token_proofs:
            raise ValueError("Creation receipt targets an unscoped contract")
        entity = _entity(binding, contract=deployed)
        creation, creation_ref = rpc("eth_getBlockByNumber", [receipt["blockNumber"], False], entity,
                                     proof_refs=[receipt_ref])
        if not isinstance(creation, dict) or creation.get("hash") != receipt["blockHash"]:
            raise ValueError("Creation receipt is not on the canonical chain")
        outputs.append(_observation(
            store, binding, entity=entity, metric="deployment", as_of=as_of,
            evidence_refs=[*token_proofs[deployed][1], receipt_ref, creation_ref],
            basis="successful-creation-receipt-and-runtime-code", block_identity=digest,
        ))

    for pool in pools:
        if not binding["token0"] or not binding["token1"]:
            raise ValueError("A v2 pool requires explicit constituent tokens/decimals")
        token0, token1 = address(binding["token0"]["address"]), address(binding["token1"]["address"])
        if token0 not in token_proofs or token1 not in token_proofs:
            raise ValueError("Both pool constituent contracts must be in the scoped contract list")
        places0, proof0 = token_proofs[token0]
        places1, proof1 = token_proofs[token1]
        if places0 != binding["token0"]["decimals"] or places1 != binding["token1"]["decimals"]:
            raise ValueError("Configured token units disagree with on-chain decimals")
        entity = _entity(binding, pool=pool)
        code, code_ref = rpc("eth_getCode", [pool, pinned], entity)
        returned0, token0_ref = call(pool, "token0", entity)
        returned1, token1_ref = call(pool, "token1", entity)
        if abi_address(returned0) != token0 or abi_address(returned1) != token1:
            raise ValueError("Pool constituents differ from declared identity")
        evidence = [*common, code_ref, token0_ref, token1_ref, *proof0, *proof1]
        if binding.get("factory_address"):
            factory = address(binding["factory_address"])
            returned_factory, factory_ref = call(pool, "factory", entity)
            if abi_address(returned_factory) != factory:
                raise ValueError("Pool belongs to another factory")
            _factory_code, factory_code_ref = rpc("eth_getCode", [factory, pinned], entity)
            returned_pair, pair_ref = call(factory, "getPair", entity,
                                            token0[2:].rjust(64, "0") + token1[2:].rjust(64, "0"))
            if abi_address(returned_pair) != pool:
                raise ValueError("Factory does not map constituents to the declared pool")
            evidence.extend((factory_ref, factory_code_ref, pair_ref))
        if crypto:
            token_entity = _entity(binding, contract=token0, pool=pool)
            raw_reserves, reserves_ref = call(pool, "getReserves", entity)
            reserve0, reserve1, reserve_time = abi_words(raw_reserves, 3)
            if reserve0 >= 2**112 or reserve1 >= 2**112 or reserve_time >= 2**32:
                raise ValueError("Pool reserves violate the canonical ABI")
            base_amount, quote_amount = decimal(raw_units(reserve0, places0)), decimal(raw_units(reserve1, places1))
            if base_amount > 0 and quote_amount > 0:
                quote_units = f"token:{binding['chain_id']}:{token1}"
                with localcontext() as context:
                    context.prec = 600
                    price_value = quote_amount / base_amount
                    liquidity_value = 2 * quote_amount
                outputs.append(_observation(
                    store, binding, entity=token_entity, metric="price", as_of=as_of,
                    evidence_refs=[*evidence, reserves_ref], quantity=decimal_text(price_value),
                    units=f"{quote_units}/token:{binding['chain_id']}:{token0}",
                    basis="v2-spot-reserve-ratio-v1", block_identity=digest,
                ))
                outputs.append(_observation(
                    store, binding, entity=token_entity, metric="liquidity", as_of=as_of,
                    evidence_refs=[*evidence, reserves_ref], quantity=decimal_text(liquidity_value),
                    units=quote_units, basis="v2-two-sided-quote-token-reserves-v1", block_identity=digest,
                ))
            if binding.get("pool_creation_tx_hash"):
                creation_receipt, creation_receipt_ref = rpc(
                    "eth_getTransactionReceipt", [binding["pool_creation_tx_hash"]], entity
                )
                prove_pair_creation(creation_receipt, factory=binding.get("factory_address"),
                                    pool=pool, token0=token0, token1=token1)
                creation_header, creation_header_ref = rpc(
                    "eth_getBlockByNumber", [creation_receipt["blockNumber"], False], entity,
                    proof_refs=[creation_receipt_ref],
                )
                if not isinstance(creation_header, dict) or creation_header.get("hash") != creation_receipt["blockHash"]:
                    raise ValueError("Pool creation is not on the canonical chain")
                outputs.append(_observation(
                    store, binding, entity=token_entity, metric="pool-creation", as_of=as_of,
                    evidence_refs=[*evidence, creation_receipt_ref, creation_header_ref],
                    basis="canonical-v2-factory-PairCreated-and-runtime-v1", block_identity=digest,
                ))
            continue
        logs, logs_ref = rpc("eth_getLogs", [{"blockHash": digest, "address": pool,
                                             "topics": [list(V2_TOPICS.values())]}], entity)
        if not isinstance(logs, list):
            raise ValueError("Malformed pool log response")
        for log in logs:
            decoded = decode_v2_log(log, pool=pool, token0=token0, token1=token1,
                                    decimals0=places0, decimals1=places1)
            if decoded["chain_event"]["block_hash"] != digest:
                raise ValueError("Log is outside the pinned block")
            receipt, receipt_ref = rpc("eth_getTransactionReceipt",
                                       [decoded["chain_event"]["transaction_hash"]], entity,
                                       proof_refs=[logs_ref])
            if (not isinstance(receipt, dict) or receipt.get("blockHash") != digest
                    or hex_quantity(receipt.get("status")) != 1
                    or log not in receipt.get("logs", [])):
                raise ValueError("Log lacks a successful same-block transaction receipt")
            event = {
                **decoded["chain_event"], "chain_id": binding["chain_id"],
                "venue_sequence": None, "kind": decoded["kind"], "legs": decoded["legs"],
                "sender": decoded["sender"], "recipient": decoded["recipient"],
                "removed": decoded["removed"], "actor_id": None,
                "block_timestamp": as_of, "evidence_refs": [logs_ref, receipt_ref],
            }
            outputs.append(_observation(
                store, binding, entity=entity, metric=decoded["kind"], as_of=as_of,
                evidence_refs=[*evidence, logs_ref, receipt_ref], event=event,
                basis="uniswap-v2-exact-ABI-log-and-transaction-receipt", block_identity=digest,
            ))
    return outputs


def _collect_dexscreener(store: Any, plan: dict, binding: dict,
                        authorize: Callable[[dict], dict],
                        on_evidence: Callable[[dict], None] | None = None,
                        prior_observation_refs: list[dict] | None = None,
                        revalidate: Callable[[dict, dict], None] | None = None,
                        on_undispatched: Callable[[str], None] | None = None) -> list[dict]:
    """Exact pair or explicitly scoped captured-token discovery; never a supply proof."""
    del prior_observation_refs
    dynamic = binding.get("entity_scope", "explicit") == "captured-leads"
    contract = address(binding["contract_addresses"][-1]) if dynamic else None
    pool = address(binding["pool_addresses"][0]) if not dynamic and len(binding["pool_addresses"]) == 1 else None
    entity = _entity(binding, contract=contract, pool=pool)
    endpoint = dex_endpoint(binding, entity)
    response, raw_ref = _request(store, plan, binding, entity=entity, method="GET",
                                 endpoint=endpoint, authorize=authorize, on_evidence=on_evidence,
                                 revalidate=revalidate, on_undispatched=on_undispatched)
    pairs = response if dynamic else response.get("pairs") if isinstance(response, dict) else None
    if not isinstance(pairs, list):
        raise ValueError("DEX Screener pair measurement is unavailable")
    selected = []
    for pair in pairs:
        if not isinstance(pair, dict) or pair.get("chainId") != _DEX_CHAINS[binding["chain_id"]]:
            continue
        pair_address = address(pair.get("pairAddress"))
        base = address(pair.get("baseToken", {}).get("address"))
        quote = address(pair.get("quoteToken", {}).get("address"))
        if dynamic:
            if base != contract:
                continue
            if binding["pool_addresses"] and pair_address not in {address(value) for value in binding["pool_addresses"]}:
                continue
        elif pair_address != pool:
            continue
        if base not in {address(value) for value in binding["contract_addresses"]}:
            raise ValueError("DEX Screener base token is outside source scope")
        if binding["token0"] and binding["token1"] and {
                base, quote} != {address(binding["token0"]["address"]), address(binding["token1"]["address"])}:
            raise ValueError("DEX Screener pair constituents do not match the declared pair")
        selected.append((pair_address, base, pair))
    if not dynamic and len(selected) != 1:
        raise ValueError("DEX Screener response must contain one exact declared pair")
    if len({pair for pair, base, row in selected}) != len(selected):
        raise ValueError("DEX Screener response contains conflicting duplicate pools")
    observed = json.loads(store.read_blob(raw_ref))["observed_at"]
    outputs = []
    for pair_address, base, pair in sorted(selected):
        token_entity = _entity(binding, contract=base, pool=pair_address)
        # The API publishes no measurement timestamp/block. Capture time remains
        # explicitly distinct from provider as-of, even under a bounded-skew rule.
        measurements = [
            ("price", pair.get("priceUsd"), "USD/token", None, "provider-reported-pair-price-capture-time"),
            ("liquidity", pair.get("liquidity", {}).get("usd"), "USD", None,
             "provider-reported-pool-liquidity-capture-time"),
            ("market-cap", pair.get("marketCap"), "USD", "circulating-market-cap",
             "provider-reported-market-cap-unknown-circulation"),
            ("market-cap", pair.get("fdv"), "USD", "fdv", "provider-reported-fdv-unknown-supply"),
            ("pool-creation", pair.get("pairCreatedAt"), "unix-ms", None,
             "provider-reported-pair-creation-not-token-deployment"),
        ]
        for metric, value, units, cap_kind, basis in measurements:
            if value is None:
                continue
            value = str(value) if isinstance(value, int) and not isinstance(value, bool) else value
            outputs.append(_observation(
                store, binding, entity=token_entity, metric=metric, as_of=observed,
                evidence_refs=[raw_ref], quantity=decimal_text(decimal(value, nonnegative=True)),
                units=units, cap_kind=cap_kind, basis=basis,
            ))
    return outputs


def _ingest_local(store: Any, plan: dict, binding: dict,
                  authorize: Callable[[dict], dict],
                  on_evidence: Callable[[dict], None] | None = None,
                  prior_observation_refs: list[dict] | None = None,
                  revalidate: Callable[[dict, dict], None] | None = None,
                  on_undispatched: Callable[[str], None] | None = None) -> list[dict]:
    """Ingest canonical immutable observations with a closed existing evidence graph."""
    del plan, authorize, on_evidence, prior_observation_refs, revalidate, on_undispatched
    outputs = []
    roots = []
    for ref in binding["artifact_refs"]:
        try:
            store.get_record(ref, "verified-observation")
            roots.append(ref)
        except ValueError:
            data = store.read_blob(ref)
            record = validate_record("verified-observation", json.loads(data))
            if data != canonical_bytes(record):
                raise ValueError("Local observation artifact must contain exact canonical JSON bytes")
            roots.append(store.put_record("verified-observation", record))
    for item in store.resolve_closure(roots):
        if item["kind"] != "verified-observation":
            continue
        observation = item["payload"]
        entity = observation["entity"]
        if entity["chain_id"] != binding["chain_id"]:
            raise ValueError("Local observation chain is outside binding scope")
        if ((entity["contract_address"] and entity["contract_address"] not in binding["contract_addresses"])
                or (entity["pool_address"] and entity["pool_address"] not in binding["pool_addresses"])
                or (entity["venue"] and entity["venue"] != binding["venue"])):
            raise ValueError("Local observation entity is outside binding scope")
        # get_record validates every artifact/hash in the closure. Semantic
        # verification is still required at reduction, regardless of input flags.
        store.get_record(item["ref"], "verified-observation")
        outputs.append(item["ref"])
    return outputs


# Actual, deliberately small implementations. No eval/importlib, dynamic ABI,
# arbitrary URL discovery, mutable plugin registration, or trading/write method.
OBSERVATION_REGISTRY = MappingProxyType({
    "local-artifact": _ingest_local,
    "evm-json-rpc": _collect_evm,
    "dexscreener-pair": _collect_dexscreener,
})


class ObservationCollectionError(RuntimeError):
    """A bounded collection failed; already durable observations remain recoverable."""

    def __init__(self, binding_id: str, observation_refs: list[dict], reason: str):
        self.binding_id = binding_id
        self.observation_refs = observation_refs
        self.reason = reason
        super().__init__(f"Observation collection refused/failed for {binding_id}: {reason}")


def observe(store: Any, plan: dict, capture_refs: list[dict], *,
            authorize: Callable[[dict], dict],
            on_evidence: Callable[[dict], None] | None = None,
            prior_observation_refs: list[dict] | None = None,
            revalidate: Callable[[dict, dict], None] | None = None,
            on_undispatched: Callable[[str], None] | None = None) -> list[dict]:
    """Explicit live/local collection seam. Replay never calls this function."""
    plan = validate_record("monitor-plan", plan)
    plan_digest(plan)
    for ref in capture_refs:
        store.get_record(ref, "source-capture")
    outputs = []
    for binding in plan["profile"].get("observation_sources", []):
        collector = OBSERVATION_REGISTRY[binding["id"]]
        before = {ref_key(ref) for ref in store.list_records("verified-observation")}
        try:
            bindings = [binding]
            if binding.get("entity_scope", "explicit") == "captured-leads":
                if binding["id"] == "local-artifact":
                    raise ValueError("Local artifacts require explicit imported entity scope")
                bindings = []
                seen = set()
                for lead in captured_leads(store, capture_refs):
                    if lead["entity"]["chain_id"] != binding["chain_id"] or lead["entity"]["entity_id"] in seen:
                        continue
                    seen.add(lead["entity"]["entity_id"])
                    contracts = [lead["entity"]["contract_address"]]
                    if binding["id"] == "evm-json-rpc":
                        contracts = sorted(set(binding["contract_addresses"] + contracts))
                    bindings.append({
                        **binding, "contract_addresses": contracts,
                        "_lead_capture_ref": lead["capture_ref"],
                        "_lead_source_span": lead["source_span"],
                        "_lead_capture": store.get_record(lead["capture_ref"], "source-capture"),
                    })
            for active in bindings:
                outputs.extend(collector(store, plan, active, authorize, on_evidence,
                                         prior_observation_refs, revalidate, on_undispatched))
        except (PermissionError, ValueError, SafeHTTPError, httpx.HTTPError, TimeoutError) as exc:
            partial = outputs + [ref for ref in store.list_records("verified-observation")
                                 if ref_key(ref) not in before]
            raise ObservationCollectionError(
                binding["binding_id"], sorted({ref_key(ref): ref for ref in partial}.values(), key=ref_key),
                type(exc).__name__,
            ) from exc
    return sorted({(ref["path"], ref["sha256"]): ref for ref in outputs}.values(),
                  key=lambda ref: (ref["path"], ref["sha256"]))


def ref_key(ref: dict) -> tuple[str, str]:
    return ref["path"], ref["sha256"]


class ObservationVerifier:
    """Verify frozen bytes, independent admissions, and cross-method measurement facts.

    A structural contract pass, producer ``verification.state``, an actor label,
    or a recognized adapter name never establishes a fact. The returned facts
    retain source basis/time/units even when a missing authority anchor prevents
    promotion to independently admitted evidence.
    """

    def __init__(self, store: Any, plan: dict, authority_snapshot: dict | None = None, *,
                 trusted_observation_refs: frozenset[tuple[str, str]] | None = None):
        self.store = store
        self.plan = plan
        self.authority_snapshot = authority_snapshot
        self.trusted_observation_refs = trusted_observation_refs or frozenset()
        self.bindings = {
            binding["binding_id"]: binding
            for binding in plan["profile"].get("observation_sources", [])
        }
        self._raw_cache: dict[tuple[str, str], dict] = {}

    def _raw(self, ref: dict) -> dict:
        from hyperresearch.models.x_evidence import validate_definition

        key = ref_key(ref)
        if key not in self._raw_cache:
            value = json.loads(self.store.read_blob(ref))
            value = validate_definition("observation-evidence", value)
            if value.get("raw_response_ref"):
                original = json.loads(self.store.read_blob(value["raw_response_ref"]), parse_float=Decimal)
                if _json_decimals(original) != value["response"]:
                    raise ValueError("normalized-response-does-not-match-original-bytes")
            self._raw_cache[key] = value
        return self._raw_cache[key]

    def _admitted(self, raw: dict, binding: dict) -> bool:
        if not raw["admission_ref"] or not self.authority_snapshot:
            return False
        admission = json.loads(self.store.read_blob(raw["admission_ref"]))
        proof_refs, proof_rows = raw["request"].get("proof_refs", []), raw["request"].get("proof_rows", [])
        if len(proof_refs) != len(proof_rows):
            raise ValueError("independent-proof-closure-does-not-match")
        for ref, supplied in zip(proof_refs, proof_rows, strict=True):
            proof = self._raw(ref)
            actual = {"request": proof["request"], "response": proof["response"],
                      "admission": json.loads(self.store.read_blob(proof["admission_ref"]))}
            if actual != supplied:
                raise ValueError("independent-proof-bytes-do-not-match")
        # This helper is the parent's common authority implementation, not an
        # embedded key taken from the observation's own untrusted assertions.
        from hyperresearch.core.x_authority import verify_observation_admission

        verify_observation_admission(
            self.plan, raw["request"], admission,
            trusted_digest=self.authority_snapshot["trust_store_digest"],
            trusted_keys=self.authority_snapshot["trusted_keys"],
        )
        if not any(all(admission.get(key) == grant.get(key) for key in
                       ("approval_id", "grant_digest", "approval_ref"))
                   for grant in self.authority_snapshot["admitted_grants"]):
            return False
        return (binding in admission["payload"].get("observation_bindings", [])
                and raw["binding_id"] == binding["binding_id"])

    def _rows(self, observation: dict) -> tuple[dict, list[dict], bool]:
        binding = self.bindings.get(observation["source"]["binding_id"])
        if binding is None:
            raise ValueError("missing-source-binding")
        entity = observation["entity"]
        if entity["chain_id"] != binding["chain_id"]:
            raise ValueError("chain-identity-mismatch")
        dynamic = binding.get("entity_scope", "explicit") == "captured-leads"
        if (
            entity["contract_address"]
            and entity["contract_address"].lower() not in {
                value.lower() for value in binding["contract_addresses"]
            }
            and not dynamic
        ):
            raise ValueError("contract-outside-source-binding")
        if (
            entity["pool_address"]
            and entity["pool_address"].lower() not in {
                value.lower() for value in binding["pool_addresses"]
            }
            and not (dynamic and binding["id"] == "dexscreener-pair")
        ):
            raise ValueError("pool-outside-source-binding")
        if entity["venue"] and entity["venue"] != binding["venue"]:
            raise ValueError("venue-outside-source-binding")
        # Labels are not chain/contract proof. A decoded pool cannot be
        # reclassified as an aggregate by producer-supplied scope metadata.
        scope = observation["measurement_scope"]
        expected_aggregation = "venue" if entity["venue"] else "pool" if entity["pool_address"] else "contract"
        if (scope["chain_id"] != entity["chain_id"] or scope["venue"] != entity["venue"]
                or scope["aggregation"] != expected_aggregation):
            raise ValueError("measurement-scope-is-not-decoded-entity-scope")
        actual_pools = {(pool["chain_id"], pool["pool_address"], pool["venue"]) for pool in scope["pool_refs"]}
        expected_pools = {(entity["chain_id"], entity["pool_address"], entity["venue"])} if entity["pool_address"] else set()
        if actual_pools != expected_pools or len(scope["pool_refs"]) != len(expected_pools):
            raise ValueError("measurement-scope-pool-constituents-mismatch")
        refs = observation["source"]["evidence_refs"]
        if not refs:
            raise ValueError("missing-independent-evidence")
        rows = [self._raw(ref) for ref in refs]
        admitted = True
        for raw in rows:
            if raw["binding_id"] != binding["binding_id"]:
                raise ValueError("evidence-binding-mismatch")
            if raw["adapter"] != binding["id"]:
                raise ValueError("evidence-adapter-mismatch")
            expected_endpoint = dex_endpoint(binding, raw["entity"]) if dynamic and binding["id"] == "dexscreener-pair" else binding["endpoint"]
            if raw["endpoint"] != expected_endpoint:
                raise ValueError("evidence-endpoint-mismatch")
            if dynamic:
                lead = check_captured_lead(self.store, raw["request"])
                if (lead["entity"]["chain_id"] != entity["chain_id"]
                        or (entity["contract_address"] not in binding["contract_addresses"]
                        and lead["entity"]["contract_address"] != entity["contract_address"])):
                    raise ValueError("observation-is-not-bound-to-captured-lead")
            if raw["entity"]["chain_id"] != entity["chain_id"]:
                raise ValueError("evidence-chain-mismatch")
            if binding["endpoint"]:
                _https_endpoint(binding["endpoint"], binding["allowed_hosts"])
            admitted = self._admitted(raw, binding) and admitted
        return binding, rows, admitted

    @staticmethod
    def _rpc(rows: list[dict], method: str, params: list) -> Any:
        matched = []
        for row in rows:
            request, response = row["request"], row["response"]
            if request.get("rpc_method") != method or request.get("params") != params:
                continue
            if request.get("method") != "POST" or response.get("jsonrpc") != "2.0":
                raise ValueError("malformed-rpc-evidence")
            if response.get("id") != 1 or "error" in response or "result" not in response:
                raise ValueError("unavailable-rpc-evidence")
            matched.append(response["result"])
        if not matched:
            raise ValueError(f"missing-independent-{method}-evidence")
        if len({record_digest(value) for value in matched}) != 1:
            raise ValueError("conflicting-same-request-evidence")
        return matched[0]

    def _chain(self, binding: dict, rows: list[dict]) -> dict:
        chain = binding["chain_id"]
        if not re.fullmatch(r"eip155:[1-9][0-9]*", chain or ""):
            raise ValueError("unsupported-chain-verification")
        if hex_quantity(self._rpc(rows, "eth_chainId", [])) != int(chain.split(":")[1]):
            raise ValueError("chain-id-cross-evidence-mismatch")
        policy = binding.get("block_policy", "pinned")
        if policy in {"rolling-latest", "rolling-finalized"}:
            if binding["block_number"] is not None or binding["block_hash"] is not None:
                raise ValueError("rolling-snapshot-has-conflicting-static-pins")
            tag = "latest" if policy == "rolling-latest" else "finalized"
            header = self._rpc(rows, "eth_getBlockByNumber", [tag, False])
        elif policy != "pinned":
            raise ValueError("unsupported-block-sampling-policy")
        elif binding["block_number"] is not None:
            header = self._rpc(rows, "eth_getBlockByNumber", [hex(binding["block_number"]), False])
        elif binding["block_hash"]:
            header = self._rpc(rows, "eth_getBlockByHash", [binding["block_hash"], False])
        else:
            raise ValueError("missing-common-block-basis")
        if not isinstance(header, dict):
            raise ValueError("missing-canonical-block")
        height, digest = hex_quantity(header.get("number")), block_hash(header.get("hash"))
        if binding["block_number"] is not None and height != binding["block_number"]:
            raise ValueError("block-number-mismatch")
        if binding["block_hash"] and digest != binding["block_hash"].lower():
            raise ValueError("block-hash-mismatch")
        if policy == "pinned" and binding["block_number"] is None:
            canonical = self._rpc(rows, "eth_getBlockByNumber", [hex(height), False])
            if not isinstance(canonical, dict) or canonical.get("hash") != digest:
                raise ValueError("hash-only-block-is-not-demonstrated-canonical")
        as_of = timestamp(datetime.fromtimestamp(hex_quantity(header.get("timestamp")), UTC))
        return {"chain_id": chain, "block_number": height, "block_hash": digest,
                "as_of": as_of, "as_of_known": True,
                "block_policy": policy, "pinned": {"blockHash": digest, "requireCanonical": True}}

    def _code(self, binding: dict, rows: list[dict], contract: str, pinned: dict) -> str:
        code = self._rpc(rows, "eth_getCode", [address(contract), pinned])
        if not isinstance(code, str) or not re.fullmatch(r"0x(?:[0-9a-fA-F]{2})+", code):
            raise ValueError("missing-runtime-bytecode")
        return code

    def _call(self, rows: list[dict], target: str, selector: str, pinned: dict,
              argument: str = "") -> Any:
        return self._rpc(rows, "eth_call", [{"to": address(target), "data": selector + argument}, pinned])

    def _pool(self, binding: dict, rows: list[dict], chain: dict, pool: str) -> dict:
        import hashlib

        pinned = chain["pinned"]
        if not binding["token0"] or not binding["token1"]:
            raise ValueError("missing-pool-constituent-references")
        token0, token1 = address(binding["token0"]["address"]), address(binding["token1"]["address"])
        if (abi_address(self._call(rows, pool, CALL_SELECTORS["token0"], pinned)) != token0
                or abi_address(self._call(rows, pool, CALL_SELECTORS["token1"], pinned)) != token1):
            raise ValueError("pool-constituent-cross-evidence-mismatch")
        places = []
        for token, configured in ((token0, binding["token0"]), (token1, binding["token1"])):
            self._code(binding, rows, token, pinned)
            places.append(abi_words(self._call(rows, token, CALL_SELECTORS["decimals"], pinned), 1)[0])
            if places[-1] != configured["decimals"]:
                raise ValueError("decimal-unit-mismatch")
        pool_code = self._code(binding, rows, pool, pinned)
        if (not binding.get("pool_code_sha256")
                or hashlib.sha256(bytes.fromhex(pool_code[2:])).hexdigest() != binding["pool_code_sha256"]):
            raise ValueError("unverified-pool-runtime-provenance")
        factory = binding.get("factory_address")
        if not factory or not binding.get("factory_code_sha256"):
            raise ValueError("missing-independent-factory-provenance")
        factory = address(factory)
        if abi_address(self._call(rows, pool, CALL_SELECTORS["factory"], pinned)) != factory:
            raise ValueError("factory-identity-mismatch")
        factory_code = self._code(binding, rows, factory, pinned)
        if hashlib.sha256(bytes.fromhex(factory_code[2:])).hexdigest() != binding["factory_code_sha256"]:
            raise ValueError("factory-runtime-provenance-mismatch")
        pair = self._call(rows, factory, CALL_SELECTORS["getPair"], pinned,
                          token0[2:].rjust(64, "0") + token1[2:].rjust(64, "0"))
        if abi_address(pair) != address(pool):
            raise ValueError("factory-constituent-mapping-mismatch")
        return {"pool_address": address(pool), "token0": token0, "token1": token1,
                "decimals0": places[0], "decimals1": places[1], "pool_identity_verified": True}

    def _evm(self, observation: dict, binding: dict, rows: list[dict]) -> dict:
        chain = self._chain(binding, rows)
        if observation["as_of"] != chain["as_of"]:
            raise ValueError("observation-as-of-does-not-match-canonical-block")
        entity, metric, pinned = observation["entity"], observation["metric"], chain["pinned"]
        facts = {**chain, "basis": observation["source"]["basis"],
                 "units": observation["units"], "metric": metric,
                 "scope": observation["measurement_scope"], "entity": entity}
        contract = entity["contract_address"]
        pool = entity["pool_address"]
        if metric in {"deployment", "total-supply", "circulating-supply", "token-decimals"}:
            if not contract:
                raise ValueError("missing-chain-contract-identity")
            self._code(binding, rows, contract, pinned)
            if metric == "deployment":
                tx = binding["deployment_tx_hash"]
                if not tx:
                    raise ValueError("missing-deployment-transaction")
                receipt = self._rpc(rows, "eth_getTransactionReceipt", [tx])
                if (not isinstance(receipt, dict) or receipt.get("contractAddress") is None
                        or address(receipt["contractAddress"]) != address(contract)
                        or block_hash(receipt.get("transactionHash")) != block_hash(tx)
                        or hex_quantity(receipt.get("status")) != 1 or receipt.get("to") is not None):
                    raise ValueError("invalid-creation-receipt")
                header = self._rpc(rows, "eth_getBlockByNumber", [receipt["blockNumber"], False])
                if (not isinstance(header, dict) or header.get("hash") != receipt.get("blockHash")
                        or hex_quantity(header.get("number")) > chain["block_number"]):
                    raise ValueError("deployment-not-on-canonical-chain")
                facts["deployed_at"] = timestamp(datetime.fromtimestamp(hex_quantity(header["timestamp"]), UTC))
                facts["deployment_block_hash"] = block_hash(header["hash"])
            else:
                places = abi_words(self._call(rows, contract, CALL_SELECTORS["decimals"], pinned), 1)[0]
                if not 0 <= places <= 255:
                    raise ValueError("invalid-token-decimals")
                expected_units = f"token:{chain['chain_id']}:{address(contract)}"
                facts["decimals"] = places
                if metric == "token-decimals":
                    amount = str(places)
                else:
                    amount_raw = abi_words(self._call(rows, contract, CALL_SELECTORS["totalSupply"], pinned), 1)[0]
                    if metric == "circulating-supply":
                        excluded = binding.get("excluded_supply_addresses", [])
                        if not excluded or facts["basis"] != "declared-totalSupply-minus-excluded-balances-v1":
                            raise ValueError("circulation-methodology-not-declared")
                        exclusion_raw = sum(abi_words(self._call(
                            rows, contract, CALL_SELECTORS["balanceOf"], pinned,
                            address(wallet)[2:].rjust(64, "0")
                        ), 1)[0] for wallet in excluded)
                        if exclusion_raw > amount_raw:
                            raise ValueError("excluded-balances-exceed-total-supply")
                        amount_raw -= exclusion_raw
                        facts["excluded_supply_addresses"] = list(excluded)
                    amount = raw_units(amount_raw, places)
                if decimal(observation["quantity"], nonnegative=True) != decimal(amount):
                    raise ValueError("quantity-does-not-reproduce-from-raw-units")
                if observation["units"] != expected_units:
                    raise ValueError("supply-unit-mismatch")
                facts["quantity"] = amount
            return facts
        if metric in {"swap", "liquidity-add", "liquidity-remove", "reserves", "price", "liquidity", "pool-creation"}:
            if not pool:
                raise ValueError("missing-chain-pool-identity")
            pool_facts = self._pool(binding, rows, chain, pool)
            facts.update(pool_facts)
            facts["target_contract"] = pool_facts["token0"]
            if metric == "pool-creation":
                tx = binding.get("pool_creation_tx_hash")
                if not tx:
                    raise ValueError("missing-pool-creation-transaction")
                receipt = self._rpc(rows, "eth_getTransactionReceipt", [tx])
                prove_pair_creation(receipt, factory=binding.get("factory_address"), pool=pool,
                                    token0=pool_facts["token0"], token1=pool_facts["token1"])
                if block_hash(receipt.get("transactionHash")) != block_hash(tx):
                    raise ValueError("pool-creation-transaction-mismatch")
                header = self._rpc(rows, "eth_getBlockByNumber", [receipt["blockNumber"], False])
                if not isinstance(header, dict) or header.get("hash") != receipt["blockHash"]:
                    raise ValueError("pool-creation-not-on-canonical-chain")
                facts["created_at"] = timestamp(datetime.fromtimestamp(hex_quantity(header["timestamp"]), UTC))
                return facts
            event = observation["event"]
            if event is not None:
                logs = self._rpc(rows, "eth_getLogs", [{
                    "blockHash": chain["block_hash"], "address": address(pool),
                    "topics": [list(V2_TOPICS.values())],
                }])
                if not isinstance(logs, list):
                    raise ValueError("malformed-log-evidence")
                matching = [log for log in logs
                            if hex_quantity(log.get("logIndex")) == event["log_index"]
                            and log.get("transactionHash") == event["transaction_hash"]]
                if len(matching) != 1:
                    raise ValueError("missing-unique-chain-event")
                log = matching[0]
                decoded = decode_v2_log(log, pool=pool, token0=pool_facts["token0"],
                                        token1=pool_facts["token1"],
                                        decimals0=pool_facts["decimals0"],
                                        decimals1=pool_facts["decimals1"])
                if decoded["kind"] != metric or decoded["legs"] != event["legs"]:
                    raise ValueError("decoded-event-or-decimal-mismatch")
                if (event["block_hash"] != chain["block_hash"]
                        or event["chain_id"] != chain["chain_id"]
                        or event["block_number"] != chain["block_number"]
                        or event["sender"] != decoded["sender"]
                        or event["recipient"] != decoded["recipient"]
                        or event["removed"] != decoded["removed"]):
                    raise ValueError("event-identity-mismatch")
                if event.get("block_timestamp") not in {None, chain["as_of"]}:
                    raise ValueError("event-block-clock-mismatch")
                receipt = self._rpc(rows, "eth_getTransactionReceipt", [event["transaction_hash"]])
                if (not isinstance(receipt, dict) or receipt.get("blockHash") != chain["block_hash"]
                        or hex_quantity(receipt.get("status")) != 1 or log not in receipt.get("logs", [])):
                    raise ValueError("missing-independent-receipt-log-evidence")
                if decoded["removed"]:
                    raise ValueError("reorged-chain-event")
                facts["event"] = event
                return facts
            reserves = abi_words(self._call(rows, pool, CALL_SELECTORS["getReserves"], pinned), 3)
            if reserves[0] >= 2**112 or reserves[1] >= 2**112 or reserves[2] >= 2**32:
                raise ValueError("invalid-reserves-ABI")
            base = decimal(raw_units(reserves[0], pool_facts["decimals0"]))
            quote = decimal(raw_units(reserves[1], pool_facts["decimals1"]))
            if base <= 0 or quote <= 0:
                raise ValueError("zero-reserves-do-not-establish-market-measurement")
            expected_basis = ("v2-spot-reserve-ratio-v1" if metric == "price" else
                              "v2-two-sided-quote-token-reserves-v1")
            if facts["basis"] != expected_basis:
                raise ValueError("undeclared-price-or-liquidity-measurement-method")
            quote_units = f"token:{chain['chain_id']}:{pool_facts['token1']}"
            with localcontext() as context:
                context.prec = 600
                amount = quote / base if metric == "price" else 2 * quote
            expected_units = f"{quote_units}/token:{chain['chain_id']}:{pool_facts['token0']}" if metric == "price" else quote_units
            if observation["units"] != expected_units:
                raise ValueError("price-or-liquidity-unit-mismatch")
            if decimal(observation["quantity"], nonnegative=True) != amount:
                raise ValueError("market-measurement-does-not-reproduce-from-reserves")
            facts.update(quantity=decimal_text(amount), currency=quote_units,
                         liquidity_measure="pool-liquidity", target_contract=pool_facts["token0"])
            return facts
        raise ValueError("unsupported-evm-fact-predicate")

    def _dexscreener(self, observation: dict, binding: dict, rows: list[dict]) -> dict:
        dynamic = binding.get("entity_scope", "explicit") == "captured-leads"
        if len(rows) != 1 or (not dynamic and len(binding["pool_addresses"]) != 1):
            raise ValueError("invalid-declared-pair-measurement")
        raw = rows[0]
        if raw["request"].get("method") != "GET":
            raise ValueError("market-measurement-request-mismatch")
        chain = _DEX_CHAINS.get(binding["chain_id"])
        pool = address(observation["entity"]["pool_address"]) if dynamic else address(binding["pool_addresses"][0])
        if raw["endpoint"] != dex_endpoint(binding, raw["entity"]):
            raise ValueError("market-source-not-exact-scoped-endpoint")
        pairs = raw["response"] if dynamic else raw["response"].get("pairs")
        if not isinstance(pairs, list):
            raise ValueError("missing-pair-measurement")
        matched = [pair for pair in pairs if pair.get("chainId") == chain
                   and address(pair.get("pairAddress")) == pool]
        if len(matched) != 1:
            raise ValueError("ambiguous-pair-measurement")
        pair = matched[0]
        base, quote = address(pair["baseToken"]["address"]), address(pair["quoteToken"]["address"])
        if base != address(observation["entity"]["contract_address"]):
            raise ValueError("market-base-token-mismatch")
        if binding["token0"] and binding["token1"] and (
            {base, quote} != {address(binding["token0"]["address"]), address(binding["token1"]["address"])}
        ):
            raise ValueError("market-constituent-mismatch")
        metric = observation["metric"]
        if metric == "price":
            amount, units = pair.get("priceUsd"), "USD/token"
        elif metric == "liquidity":
            amount, units = pair.get("liquidity", {}).get("usd"), "USD"
        elif metric == "market-cap":
            amount = pair.get("fdv" if observation["cap_kind"] == "fdv" else "marketCap")
            units = "USD"
        elif metric == "pool-creation":
            amount, units = pair.get("pairCreatedAt"), "unix-ms"
        else:
            raise ValueError("unsupported-provider-measurement")
        if isinstance(amount, int) and not isinstance(amount, bool):
            amount = str(amount)
        if (decimal(amount, nonnegative=True) != decimal(observation["quantity"], nonnegative=True)
                or observation["units"] != units):
            raise ValueError("provider-measurement-quantity-or-unit-mismatch")
        return {
            "quantity": observation["quantity"], "units": units, "currency": "USD",
            "entity": observation["entity"], "metric": metric,
            "scope": observation["measurement_scope"], "basis": observation["source"]["basis"],
            "as_of": observation["as_of"], "as_of_known": False,
            "time_basis": "capture-time-not-provider-measurement-time",
            "pool_address": pool, "target_contract": base,
            "liquidity_measure": "pool-liquidity",
            "supply_independently_verified": False,
        }

    def verify(self, observation: dict, *, observation_ref: dict | None = None) -> EvidenceResult:
        """Deterministic evidence truth, independent of adapter/state labels."""
        try:
            expected_rule = (ACTOR_RULE if observation["metric"] == "actor-association" else
                             FLOW_RULE if observation["domain"] == "market" else CRYPTO_RULE)
            if (observation["verification"]["rule_id"] != expected_rule["id"]
                    or observation["verification"]["revision"] != expected_rule["revision"]):
                return EvidenceResult(False, ("unsupported-verification-rule",))
            if observation["correction"]["state"] in {"retracted", "reorg"}:
                return EvidenceResult(False, ("retracted-or-reorged-observation",))
            if observation["metric"] == "liquidity" and observation["measurement_scope"]["aggregation"] == "aggregate":
                return self._aggregate(observation)
            binding, rows, admitted = self._rows(observation)
            if binding["id"] == "evm-json-rpc":
                facts = self._evm(observation, binding, rows)
            elif binding["id"] == "dexscreener-pair":
                facts = self._dexscreener(observation, binding, rows)
            else:
                return self._local(observation, binding, rows, admitted)
            reasons = [] if admitted else ["missing-independent-admission-anchor"]
            if observation_ref is None or ref_key(observation_ref) not in self.trusted_observation_refs:
                reasons.append("observation-origin-not-independently-admitted")
            if observation["metric"] == "market-cap" and binding["id"] == "dexscreener-pair":
                reasons.append("provider-cap-does-not-independently-verify-supply")
            if not facts.get("as_of_known", False):
                reasons.append("provider-measurement-as-of-unknown")
            return EvidenceResult(not reasons, tuple(reasons), facts)
        except (ValueError, KeyError, TypeError, PermissionError, InvalidOperation, ImportError) as exc:
            return EvidenceResult(False, (str(exc),))

    def _local(self, observation: dict, binding: dict, rows: list[dict],
               admitted: bool) -> EvidenceResult:
        """Verify local signed venue/association evidence, not a freeform value flag."""
        if observation["metric"] not in {"orderbook-depth", "orderbook-change", "actor-association"}:
            return EvidenceResult(False, ("local-artifact-needs-reproducible-source-proof",))
        statements = self._signed_statements(binding, rows)
        if not statements:
            return EvidenceResult(False, ("missing-independently-signed-local-evidence",))
        if observation["metric"] == "actor-association":
            issuers = {issuer for issuer, statement in statements}
            identities = {record_digest(statement) for issuer, statement in statements}
            signing_keys = {key["key_id"]: key["public_key_b64"] for key in binding.get("actor_keys", [])}
            independent_keys = {signing_keys[raw["response"]["statement_envelope"]["key_id"]]
                                for raw in rows}
            if len(issuers) < 2 or len(independent_keys) < 2 or len(identities) != 1:
                return EvidenceResult(False, ("actor-association-needs-two-independent-issuers",))
            statement = statements[0][1]
            if (statement.get("chain_id") != observation["entity"]["chain_id"]
                    or statement.get("wallet") != observation["entity"]["contract_address"]
                    or not statement.get("actor_id") or statement.get("role") != "market-maker"):
                return EvidenceResult(False, ("actor-binding-identity-mismatch",))
            if not instant(statement["valid_from"]) <= instant(observation["as_of"]) <= instant(statement["valid_to"]):
                return EvidenceResult(False, ("actor-binding-outside-effective-interval",))
            facts = {"actor_id": statement["actor_id"], "wallet": statement["wallet"],
                     "chain_id": statement["chain_id"], "role": statement["role"],
                     "valid_from": statement["valid_from"], "valid_to": statement["valid_to"],
                     "basis": "two-independent-signed-issuer-bindings-v1"}
            return EvidenceResult(admitted, () if admitted else ("missing-independent-admission-anchor",), facts)
        if len(statements) != 1:
            return EvidenceResult(False, ("ambiguous-venue-snapshot",))
        statement = statements[0][1]
        event = observation["event"]
        if (not event or event["venue_sequence"] is None or not observation["entity"]["venue"]
                or statement.get("venue") != observation["entity"]["venue"]
                or statement.get("sequence") != event["venue_sequence"]
                or statement.get("as_of") != observation["as_of"]
                or statement.get("scope_id") != observation["measurement_scope"]["scope_id"]
                or statement.get("units") != observation["units"]
                or statement.get("entity_id") != observation["entity"]["entity_id"]):
            return EvidenceResult(False, ("venue-sequence-time-or-scope-mismatch",))
        levels = statement.get("levels")
        if not isinstance(levels, list):
            return EvidenceResult(False, ("decoded-orderbook-levels-missing",))
        with localcontext() as context:
            context.prec = 600
            depth = Decimal(0)
            measure = statement.get("depth_measure")
            if measure not in {"base-quantity", "quote-notional"}:
                return EvidenceResult(False, ("orderbook-measure-not-declared",))
            for level in levels:
                if level.get("side") not in {"bid", "ask"}:
                    return EvidenceResult(False, ("orderbook-side-is-not-decoded",))
                quantity = decimal(level["quantity"], nonnegative=True)
                price = decimal(level["price"], nonnegative=True)
                base_units, quote_units = level["quantity_units"], level["quote_units"]
                if price <= 0 or level["price_units"] != f"{quote_units}/{base_units}":
                    return EvidenceResult(False, ("orderbook-price-unit-mismatch",))
                expected_units = base_units if measure == "base-quantity" else quote_units
                if expected_units != observation["units"]:
                    return EvidenceResult(False, ("orderbook-depth-unit-mismatch",))
                depth += quantity if measure == "base-quantity" else quantity * price
        if decimal(observation["quantity"], nonnegative=True) != depth:
            return EvidenceResult(False, ("orderbook-depth-unit-or-aggregation-mismatch",))
        facts = {"event": event, "quantity": decimal_text(depth), "units": observation["units"],
                 "as_of": observation["as_of"], "as_of_known": True,
                 "scope": observation["measurement_scope"], "metric": observation["metric"],
                 "basis": "signed-sequenced-orderbook-level-sum-v1",
                 "liquidity_measure": "orderbook-depth",
                 "entity": observation["entity"]}
        return EvidenceResult(admitted, () if admitted else ("missing-independent-admission-anchor",), facts)

    @staticmethod
    def _signed_statements(binding: dict, rows: list[dict]) -> list[tuple[str, dict]]:
        import base64

        from cryptography.exceptions import InvalidSignature
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

        keys = {key["key_id"]: key for key in binding.get("actor_keys", [])}
        statements = []
        for raw in rows:
            envelope = raw["response"].get("statement_envelope")
            if not isinstance(envelope, dict) or envelope.get("key_id") not in keys:
                raise ValueError("untrusted-local-statement-signer")
            key = keys[envelope["key_id"]]
            payload = base64.b64decode(envelope["payload_b64"], validate=True)
            signature = base64.b64decode(envelope["signature_b64"], validate=True)
            try:
                Ed25519PublicKey.from_public_bytes(
                    base64.b64decode(key["public_key_b64"], validate=True)
                ).verify(signature, payload)
            except (InvalidSignature, ValueError) as exc:
                raise ValueError("invalid-local-statement-signature") from exc
            statement = json.loads(payload)
            if not isinstance(statement, dict) or canonical_bytes(statement) != payload:
                raise ValueError("local-statement-is-not-canonical-exact-bytes")
            statements.append((key["issuer"], statement))
        return statements

    def _aggregate(self, observation: dict) -> EvidenceResult:
        scope = observation["measurement_scope"]
        if (observation["source"]["method"] != "local-artifact"
                or observation["source"]["basis"] != "sum-compatible-pool-liquidity-v1"
                or observation["source"]["binding_id"] not in self.bindings):
            return EvidenceResult(False, ("unsupported-aggregate-derivation",))
        refs = scope["constituent_refs"]
        if not refs or len({ref_key(ref) for ref in refs}) != len(refs):
            return EvidenceResult(False, ("missing-or-duplicate-aggregate-constituents",))
        constituents = [self.store.get_record(ref, "verified-observation") for ref in refs]
        verified = [self.verify(item, observation_ref=ref) for ref, item in zip(refs, constituents, strict=True)]
        if any(not result.known for result in verified):
            return EvidenceResult(False, ("aggregate-constituent-needs-verification",))
        facts = [result.facts for result in verified]
        pools = [fact.get("pool_address") for fact in facts]
        if None in pools or len(set(pools)) != len(pools):
            return EvidenceResult(False, ("overlapping-aggregate-pool-scope",))
        expected_pools = {pool["pool_address"] for pool in scope["pool_refs"]}
        if set(pools) != expected_pools:
            return EvidenceResult(False, ("aggregate-pool-references-do-not-close",))
        if any(item["metric"] != "liquidity" or item["measurement_scope"]["aggregation"] != "pool"
               or item["units"] != observation["units"]
               or item["entity"]["chain_id"] != observation["entity"]["chain_id"]
               or fact.get("target_contract") != observation["entity"]["contract_address"]
               for item, fact in zip(constituents, facts, strict=True)):
            return EvidenceResult(False, ("incompatible-aggregate-measurement-units-or-scope",))
        clocks = [instant(fact["as_of"]) for fact in facts]
        coherence = observation["coherence"]
        if (coherence["rule_id"] != COHERENCE_RULE["id"]
                or coherence["revision"] != COHERENCE_RULE["revision"]
                or (max(clocks) - min(clocks)).total_seconds() > coherence["max_skew_s"]):
            return EvidenceResult(False, ("incoherent-aggregate-as-of",))
        blocks = {fact.get("block_hash") for fact in facts}
        if coherence["require_same_block"] and (None in blocks or len(blocks) != 1):
            return EvidenceResult(False, ("incoherent-aggregate-block",))
        with localcontext() as context:
            context.prec = 600
            amount = sum((decimal(fact["quantity"], nonnegative=True) for fact in facts), Decimal(0))
        if decimal(observation["quantity"], nonnegative=True) != amount:
            return EvidenceResult(False, ("aggregate-quantity-does-not-reproduce",))
        as_of = timestamp(min(clocks))
        if observation["as_of"] != as_of:
            return EvidenceResult(False, ("aggregate-as-of-does-not-reproduce",))
        return EvidenceResult(True, (), {
            "quantity": decimal_text(amount), "units": observation["units"], "as_of": as_of,
            "as_of_known": True, "block_hash": next(iter(blocks)) if len(blocks) == 1 else None,
            "chain_id": observation["entity"]["chain_id"], "entity": observation["entity"],
            "scope": scope, "target_contract": observation["entity"]["contract_address"],
            "pool_addresses": pools, "basis": observation["source"]["basis"],
            "liquidity_measure": "aggregate-liquidity",
        })

    def verify_correction(self, observation: dict, previous: dict, *,
                          observation_ref: dict | None = None, previous_ref: dict | None = None) -> EvidenceResult:
        """Independent evidence of a correction/reorg; flags cannot invalidate another entity."""
        try:
            if (observation["entity"] != previous["entity"]
                    or observation["metric"] != previous["metric"]
                    or (observation["revision"] <= previous["revision"]
                    and observation["observation_id"] == previous["observation_id"])):
                return EvidenceResult(False, ("correction-identity-or-revision-mismatch",))
            if observation["correction"]["state"] == "corrected":
                return self.verify(observation, observation_ref=observation_ref)
            if observation["correction"]["state"] not in {"reorg", "retracted"}:
                return EvidenceResult(False, ("not-an-evidence-correction",))
            expected = FLOW_RULE if observation["domain"] == "market" else CRYPTO_RULE
            if ({"id": observation["verification"]["rule_id"], "revision": observation["verification"]["revision"]} != expected
                    or observation["coherence"]["rule_id"] != COHERENCE_RULE["id"]
                    or observation["coherence"]["revision"] != COHERENCE_RULE["revision"]):
                return EvidenceResult(False, ("unsupported-correction-predicate-version",))
            binding, rows, admitted = self._rows(observation)
            if (observation_ref is None or previous_ref is None
                    or ref_key(observation_ref) not in self.trusted_observation_refs
                    or ref_key(previous_ref) not in self.trusted_observation_refs):
                return EvidenceResult(False, ("correction-origin-not-independently-admitted",))
            if binding["id"] != "evm-json-rpc" or not admitted:
                return EvidenceResult(False, ("correction-needs-independent-admission",))
            if observation["source"]["basis"] != "canonical-block-hash-changed-v1":
                return EvidenceResult(False, ("unsupported-retraction-evidence-predicate",))
            old_event = previous["event"]
            old_height = old_event["block_number"] if old_event else binding["block_number"]
            old_hash = old_event["block_hash"] if old_event else binding["block_hash"]
            if old_hash is None:
                previous_rows = [self._raw(ref) for ref in previous["source"]["evidence_refs"]]
                old_snapshot = self._chain(binding, previous_rows)
                old_height, old_hash = old_snapshot["block_number"], old_snapshot["block_hash"]
            if old_height is None or old_hash is None:
                return EvidenceResult(False, ("reorg-needs-original-block-identity",))
            chain = self._rpc(rows, "eth_chainId", [])
            if not binding["chain_id"].startswith("eip155:") or hex_quantity(chain) != int(binding["chain_id"].split(":")[1]):
                return EvidenceResult(False, ("reorg-chain-identity-mismatch",))
            canonical = self._rpc(rows, "eth_getBlockByNumber", [hex(old_height), False])
            if (not isinstance(canonical, dict) or hex_quantity(canonical.get("number")) != old_height
                    or block_hash(canonical.get("hash")) == old_hash):
                return EvidenceResult(False, ("reorg-not-established-by-canonical-header",))
            return EvidenceResult(True, (), {"invalidated_block_hash": old_hash,
                                            "canonical_block_hash": canonical["hash"]})
        except (ValueError, KeyError, TypeError, PermissionError, ImportError) as exc:
            return EvidenceResult(False, (str(exc),))


PAIR_CREATED_TOPIC = "0x0d3648bd0f6ba80134a33ba9275ac585d9d315f0ad8355cddefde31afa28d0e9"


def prove_pair_creation(receipt: dict, *, factory: str | None, pool: str,
                        token0: str, token1: str) -> None:
    """Exact canonical v2 factory event plus a successful same-block receipt."""
    if not factory or not isinstance(receipt, dict) or hex_quantity(receipt.get("status")) != 1:
        raise ValueError("missing-successful-factory-creation-receipt")
    matched = []
    for log in receipt.get("logs", []):
        topics = log.get("topics", [])
        if address(log.get("address")) != address(factory) or not topics or topics[0] != PAIR_CREATED_TOPIC:
            continue
        if len(topics) != 3 or abi_address(topics[1]) != address(token0) or abi_address(topics[2]) != address(token1):
            continue
        words = abi_words(log.get("data"), 2)
        if words[0] >= 2**160 or "0x" + format(words[0], "040x") != address(pool) or words[1] < 1:
            continue
        if (log.get("blockHash") != receipt.get("blockHash") or log.get("removed") is not False
                or log.get("transactionHash") != receipt.get("transactionHash")):
            continue
        matched.append(log)
    if len(matched) != 1:
        raise ValueError("pool-creation-not-established-by-unique-factory-event")


def _record_reorg(store: Any, binding: dict, evidence_refs: list[dict], header: dict, *,
                  previous_refs: list[dict] | None = None) -> list[dict]:
    """Persist invalidations only for independently qualified previously sampled inputs."""
    if not isinstance(header, dict):
        raise ValueError("Canonical replacement block is unavailable")
    height, digest = hex_quantity(header.get("number")), block_hash(header.get("hash"))
    as_of = timestamp(datetime.fromtimestamp(hex_quantity(header.get("timestamp")), UTC))
    rows = [json.loads(store.read_blob(ref)) for ref in evidence_refs]
    observed_at = max(row["observed_at"] for row in rows)
    outputs = []
    previous = previous_refs or []
    for ref in previous:
        old = store.get_record(ref, "verified-observation")
        if old["source"]["binding_id"] != binding["binding_id"] or old["correction"]["state"] in {"reorg", "retracted"}:
            continue
        event = old["event"]
        old_height = event["block_number"] if event else binding["block_number"]
        old_hash = event["block_hash"] if event else binding["block_hash"]
        if old_hash is None:
            old_rows = [json.loads(store.read_blob(item)) for item in old["source"]["evidence_refs"]]
            snapshot = ObservationVerifier(store, {"profile": {"observation_sources": [binding]}})._chain(binding, old_rows)
            old_height, old_hash = snapshot["block_number"], snapshot["block_hash"]
        if old_height != height or old_hash is None or old_hash == digest:
            continue
        revised = {
            **old, "revision": old["revision"] + 1, "quantity": None,
            "observed_at": observed_at, "as_of": as_of, "evaluation_time": observed_at,
            "source": {**old["source"], "basis": "canonical-block-hash-changed-v1",
                       "evidence_refs": evidence_refs, "admission_ref": rows[0]["admission_ref"]},
            "verification": {**old["verification"], "state": "invalidated",
                             "input_refs": evidence_refs, "reasons": ["canonical-block-hash-changed"]},
            "coherence": {**old["coherence"], "state": "incoherent",
                          "input_refs": evidence_refs, "reasons": ["canonical-block-hash-changed"]},
            "event": {**event, "removed": True} if event else None,
            "correction": {"state": "reorg", "supersedes": ref, "retracts": [ref],
                           "reason": "canonical-block-hash-changed"},
        }
        outputs.append(store.put_record("verified-observation", revised))
    return outputs


_CHAIN_NAMES = {
    "ethereum": "eip155:1", "bsc": "eip155:56", "polygon": "eip155:137",
    "arbitrum": "eip155:42161", "optimism": "eip155:10", "base chain": "eip155:8453",
    "on base": "eip155:8453", "solana": "solana:mainnet",
}
_EXPLICIT_CHAIN = re.compile(r"(?<![A-Za-z0-9_])(?:eip155:[1-9][0-9]*|solana:mainnet)(?![A-Za-z0-9_])")


def chains_for_span(text: str, start: int, end: int) -> list[str]:
    # Only attributed sentence-local explicit chain claims. The allowed-chain
    # list constrains verification; it is not evidence that a bare address is on it.
    left = max(text.rfind("\n", 0, start), text.rfind(". ", 0, start)) + 1
    stops = [index for index in (text.find("\n", end), text.find(". ", end)) if index >= 0]
    right = min(stops) if stops else len(text)
    sentence = text[left:right].casefold()
    chains = set(match.group() for match in _EXPLICIT_CHAIN.finditer(sentence))
    for name, chain in _CHAIN_NAMES.items():
        if re.search(r"(?<!\w)" + re.escape(name) + r"(?!\w)", sentence):
            chains.add(chain)
    return sorted(chains)


def dex_endpoint(binding: dict, entity: dict) -> str:
    """A finite official-public API grammar, never an arbitrary URL template."""
    chain = _DEX_CHAINS.get(binding["chain_id"])
    if not chain or binding["allowed_hosts"] != ["api.dexscreener.com"]:
        raise ValueError("Unsupported or unapproved DEX Screener source")
    if binding.get("entity_scope", "explicit") == "captured-leads":
        if binding["endpoint"] != _DEX_LEAD_BASE:
            raise ValueError("Captured-lead discovery must pin the exact official token-pairs base")
        return f"{_DEX_LEAD_BASE}/{chain}/{address(entity['contract_address'])}"
    if len(binding["pool_addresses"]) != 1:
        raise ValueError("Explicit DEX Screener source must pin one pair")
    pool = address(binding["pool_addresses"][0])
    endpoint = f"{_DEX_PAIR_BASE}/{chain}/{pool}"
    if binding["endpoint"] != endpoint or address(entity["pool_address"]) != pool:
        raise ValueError("Explicit DEX Screener endpoint/pair does not match")
    return endpoint


def captured_leads(store: Any, capture_refs: list[dict]) -> list[dict]:
    """Deterministic, chain-attributed focal spans. Ambiguity never broadens authority."""
    from hyperresearch.core.x_classifier import extract_candidates

    groups: dict[str, list[tuple[dict, dict]]] = {}
    for ref in capture_refs:
        capture = store.get_record(ref, "source-capture")
        groups.setdefault(capture["post_id"], []).append((ref, capture))
    outputs = []
    for _post, captures in sorted(groups.items()):
        revision = max(capture["revision"] for ref, capture in captures)
        latest = [(ref, capture) for ref, capture in captures if capture["revision"] == revision]
        if len({record_digest({key: capture[key] for key in
                              ("post_id", "revision", "author", "text", "url", "posted_at")})
                for ref, capture in latest}) != 1:
            continue
        ref, capture = min(latest, key=lambda item: ref_key(item[0]))
        if capture["role"] != "primary":
            continue
        spans, candidates = extract_candidates([(ref, capture)])
        for candidate in candidates:
            if not candidate["address"] or not EVM_ADDRESS.fullmatch(candidate["address"]):
                continue
            span = spans[candidate["source_span_indexes"][0]]
            chains = chains_for_span(capture["text"], span["start"], span["end"])
            if len(chains) != 1 or not chains[0].startswith("eip155:"):
                continue
            entity = {"namespace": "chain-contract",
                      "entity_id": f"{chains[0]}:{address(candidate['address'])}",
                      "chain_id": chains[0], "contract_address": address(candidate["address"]),
                      "pool_address": None, "venue": None}
            outputs.append({"capture_ref": ref, "source_span": span, "entity": entity})
    return sorted(outputs, key=lambda lead: (
        lead["entity"]["entity_id"], ref_key(lead["capture_ref"]), lead["source_span"]["start"]))


def check_captured_lead(store: Any, request: dict) -> dict:
    ref, span = request.get("lead_capture_ref"), request.get("lead_source_span")
    if not ref or not isinstance(span, dict):
        raise ValueError("Dynamic source request is missing a canonical focal span")
    capture = store.get_record(ref, "source-capture")
    if request.get("lead_capture") != capture:
        raise ValueError("Dynamic source capture snapshot does not match admitted bytes")
    candidates = captured_leads(store, [ref])
    matched = [lead for lead in candidates if lead["source_span"] == span]
    if len(matched) != 1:
        raise ValueError("Dynamic source request has ambiguous or unattributed chain/contract span")
    return matched[0]
