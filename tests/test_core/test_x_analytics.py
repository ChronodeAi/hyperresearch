"""Offline behavior over governed records, real ABI decoding, and independent test anchors.

No production source/model adapter is replaced by a successful fallback. Fixtures
are inert protocol evidence; tests explicitly inject their independently owned
origin references rather than accepting flags/public keys in imported records.
"""
from __future__ import annotations

import copy
import hashlib
import json
import socket
from datetime import UTC, datetime, timedelta

import pytest

from hyperresearch.core import x_observations as observations_module
from hyperresearch.core.x_analytics import AnalyticsEngine
from hyperresearch.core.x_classifier import default_policy, project_capture_block, project_plan_question
from hyperresearch.core.x_evidence import EvidenceStore
from hyperresearch.core.x_observations import (
    ACTOR_RULE, CALL_SELECTORS, COHERENCE_RULE, CRYPTO_RULE, FLOW_RULE,
    ObservationCollectionError, V2_TOPICS, captured_leads,
    decode_v2_log, dex_endpoint, instant, ref_key, timestamp,
)
from hyperresearch.models.x_evidence import canonical_bytes, record_digest, validate_record
from tests.x_fixtures import ProtectedOrigin, SCHEMA_ROOT, approval_payload, governed_fixture

START = "2026-10-10T00:00:00Z"
AS_OF = "2026-10-10T00:00:10Z"
CAPTURED = "2026-10-10T00:00:30Z"
EVALUATION = "2026-10-10T00:00:50Z"
BASE, QUOTE, POOL, FACTORY, WALLET = ("0x" + digit * 40 for digit in "12345")
BLOCK, CREATION_BLOCK, TX, CREATION_TX = ("0x" + digit * 64 for digit in "abcd")
CODE = "0x6001600055"
CODE_HASH = hashlib.sha256(bytes.fromhex(CODE[2:])).hexdigest()
UNITS = f"token:eip155:1:{BASE}"
QUOTE_UNITS = f"token:eip155:1:{QUOTE}"
FIXTURES = SCHEMA_ROOT / "fixtures"


def template(kind, name):
    return governed_fixture(kind, name)


@pytest.fixture(autouse=True)
def protected_origin(tmp_vault, monkeypatch):
    class Clock(datetime):
        @classmethod
        def now(cls, tz=None):
            return instant(CAPTURED)
    tmp_vault.x_fixture_origin = ProtectedOrigin(monkeypatch, clock=lambda: Clock.now(UTC))
    tmp_vault.x_fixture_monkeypatch = monkeypatch
    monkeypatch.setattr(observations_module, "datetime", Clock)


def finalize(plan):
    plan["digest"] = record_digest({key: value for key, value in plan.items() if key != "digest"})
    return validate_record("monitor-plan", plan)


def entity(contract=None, pool=None, venue=None):
    return {"namespace": "venue" if venue else "chain-pool" if pool else "chain-contract",
            "entity_id": f"venue:{venue}" if venue else f"eip155:1:{pool or contract}",
            "chain_id": "eip155:1", "contract_address": contract,
            "pool_address": pool, "venue": venue}


def binding(*, adapter="evm-json-rpc", identity="rpc", height=100, digest=BLOCK):
    local = adapter == "local-artifact"
    return {"id": adapter, "binding_id": identity,
            "endpoint": None if local else "https://rpc.example.test/readonly",
            "allowed_hosts": [] if local else ["rpc.example.test"], "chain_id": "eip155:1",
            "contract_addresses": [BASE, QUOTE, WALLET], "pool_addresses": [POOL], "venue": None,
            "block_number": height, "block_hash": digest, "deployment_tx_hash": CREATION_TX,
            "pool_creation_tx_hash": None, "token0": {"address": BASE, "decimals": 18},
            "token1": {"address": QUOTE, "decimals": 6}, "artifact_refs": [],
            "verification_rule": copy.deepcopy(CRYPTO_RULE),
            "coherence": {"rule_id": COHERENCE_RULE["id"], "revision": 1,
                          "max_skew_s": 0, "require_same_block": True},
            "rpc_methods": [] if local else ["eth_chainId", "eth_getBlockByNumber", "eth_getBlockByHash",
                "eth_getTransactionReceipt", "eth_getCode", "eth_call", "eth_getLogs"],
            "call_selectors": [] if local else list(CALL_SELECTORS.values()),
            "factory_address": FACTORY, "pool_code_sha256": CODE_HASH,
            "factory_code_sha256": CODE_HASH, "excluded_supply_addresses": [],
            "receipt_read_scope": "admitted-pool-events",
            "header_read_scope": "admitted-receipt-ancestors", "entity_scope": "explicit"}


def word(value):
    return f"{value:064x}"


def address_word(value):
    return value[2:].rjust(64, "0")


def abi(*values):
    return "0x" + "".join(word(value) for value in values)


def topic_address(value):
    return "0x" + address_word(value)


class Evidence:
    def __init__(self, vault, profile="generic-sentiment", bindings=(), *, analyzed=False):
        self.store = EvidenceStore(vault.root)
        name = "analyzed-sentiment" if analyzed else {
            "generic-sentiment": "source-only-sentiment", "crypto-discovery": "crypto-discovery",
            "market-flow": "market-flow"}[profile]
        self.plan = template("monitor-plan", name)
        self.plan["queries"] = [self.plan["queries"][0]]
        self.plan["profile"]["observation_sources"] = list(copy.deepcopy(bindings))
        self.plan["profile"]["target"] = "Example product" if profile == "generic-sentiment" else "Ethereum tokens"
        if analyzed:
            bound = self.plan["limits"]["analysis"]["provider_bounds_ref"]
            self.plan["limits"]["analysis"]["provider_bounds_ref"] = self.store.put_blob(
                (FIXTURES / bound["path"]).read_bytes(), category="support")
        if profile == "crypto-discovery":
            self.plan["profile"]["criteria"].update(
                cap={"kind": "fdv", "currency": QUOTE_UNITS, "minimum": "1000", "maximum": "3000"},
                liquidity={"measure": "pool-liquidity", "units": QUOTE_UNITS, "minimum": "300"},
                age={"basis": "deployment", "minimum_s": 0, "maximum_s": 3600},
                max_age_s=120, max_skew_s=0)
        if profile == "market-flow":
            self.plan["profile"]["criteria"].update(
                measurement_scope=f"eip155:1:{POOL}", units=UNITS, max_skew_s=120)
        self.plan = finalize(self.plan)
        self.plan_ref = self.store.put_record("monitor-plan", self.plan)
        self.origin = vault.x_fixture_origin
        self.monkeypatch = vault.x_fixture_monkeypatch
        self.keys = self.origin.keys
        self.trusted_digest = self.origin.trust_digest
        self.captures, self.annotations, self.observations, self.owned, self.raw = [], [], [], [], []
        self.admissions = []
        self.grant = self.make_grant()

    def make_grant(self):
        sources = self.plan["profile"]["observation_sources"]
        if not sources:
            return None
        return approval_payload(self.plan, operations=("observations.read",),
            hosts=tuple(sorted({host for source in sources for host in source["allowed_hosts"]})),
            approval_id="offline-observation-grant")

    def capture(self, post="1001", *, text="Example product looks promising.", author="42", revision=1,
                kind="original", role="primary", event_time=AS_OF, captured_at=CAPTURED,
                relationships=(), occurrence="event-one", query="q1"):
        value = template("source-capture", "original")
        value.update(capture_id=f"capture-{post}-{revision}-{len(self.captures)}", post_id=post, text=text,
                     revision=revision, event_type=kind, role=role, event_time=event_time,
                     posted_at=event_time, captured_at=captured_at, url=f"https://x.com/fixture/status/{post}",
                     relationships=list(relationships))
        value["author"].update(id=author)
        value["occurrence"].update(query_id=query, query_revision=1, timeline_event_id=occurrence,
                                    observed_at=captured_at)
        value["artifact"] = self.store.put_blob(canonical_bytes({"id": post, "text": text}), category="source")
        ref = self.store.put_record("source-capture", value)
        self.captures.append(ref)
        return ref

    def annotate(self, ref, *, choice="positive", status="available", contexts=(), revision=1,
                 completed_at="2026-10-10T00:00:40Z", supersedes=None):
        capture = self.store.get_record(ref, "source-capture")
        value = template("analysis-annotation", "available-typed-choice")
        policy = self.plan["analysis"]["export_policy"]
        wire = {"model": self.plan["analysis"]["model"], "state": {
                    "profile_target": self.plan["profile"]["target"],
                    "focal": project_capture_block(capture, "focal", policy),
                    "context": [project_capture_block(self.store.get_record(context, "source-capture"),
                                                      f"context-{index}", policy)
                                for index, context in enumerate(contexts, 1)],
                    "query": next(query for query in self.plan["queries"]
                                  if query["id"] == capture["occurrence"]["query_id"]
                                  and query["revision"] == capture["occurrence"]["query_revision"])},
                "questions": {question["id"]: project_plan_question(question)
                              for question in self.plan["analysis"]["questions"]}}
        request_ref = self.store.put_blob(canonical_bytes(wire), category="support")
        value.update(annotation_id=f"annotation-{len(self.annotations)}", revision=revision,
                     capture_ref=ref, capture_revision=capture["revision"],
                     context_refs=[{"capture_ref": context, "revision": self.store.get_record(context, "source-capture")["revision"],
                                    "delivery": "delivered"} for context in contexts],
                     rubric_ref=self.plan["analysis"]["rubric"], policy_ref=self.plan["analysis"]["policy"],
                     requested_model=self.plan["analysis"]["model"], returned_model=self.plan["analysis"]["model"],
                     effective_input_digest=request_ref["sha256"], status=status,
                     plan_ref={"plan_id": self.plan["plan_id"], "revision": 1,
                               "digest": self.plan["digest"], "artifact_ref": self.plan_ref},
                     profile_ref={"id": self.plan["profile"]["id"], "revision": 1},
                     trusted_policy_ref=self.store.put_blob(canonical_bytes(default_policy(self.plan)), category="support"),
                     source_spans=[], entity_candidates=[])
        value["question_refs"] = [{"id": question["id"], "revision": question["revision"],
                                   "options_digest": record_digest(question["options"])} for question in self.plan["analysis"]["questions"]]
        reservation = {"reservation_id": f"model-reservation-{len(self.annotations)}",
                       "request_id": f"model-request-{len(self.annotations)}", "model_requests": 1,
                       "model_tokens": self.plan["limits"]["analysis"]["request_tokens"],
                       "model_cost_usd": self.plan["limits"]["analysis"]["request_cost_usd"]}
        request = {"action": "model.classify", "endpoint": policy["endpoint"],
                   "provider": policy["provider"], "region": policy["region"], "retention": policy["retention"],
                   "model": wire["model"], "allowed_fields": policy["payload_fields"],
                   "redactions": policy["redactions"], "export_policy": policy,
                   "bounds_ref": self.plan["limits"]["analysis"]["provider_bounds_ref"], "reservation": reservation}
        admitted_at = max([instant(capture["captured_at"])] + [
            instant(self.store.get_record(context, "source-capture")["captured_at"]) for context in contexts])
        grant = self.origin.admit(self.plan, request, approval_payload(self.plan,
            operations=("model.classify",), hosts=("model.example.test",), approval_id="offline-model-grant"),
            now=admitted_at)
        self.admissions.append(grant)
        value["reservation"].update(reservation_id=reservation["reservation_id"],
            request_id=reservation["request_id"], reserved_tokens=reservation["model_tokens"],
            reserved_cost_usd=reservation["model_cost_usd"])
        value["export"].update(request_ref=request_ref,
            policy_ref=self.store.put_blob(canonical_bytes(self.plan["analysis"]["export_policy"]), category="support"),
            grant_ref=self.store.put_blob(canonical_bytes(grant), category="support"),
            redactions=policy["redactions"], context_state="complete" if contexts else "not-required")
        value["timing"].update(started_at=timestamp(admitted_at), completed_at=completed_at)
        value["raw_answers"][0].update(choice=choice, probabilities=None, confidence=None)
        if supersedes:
            value["supersedes"] = supersedes
        if status != "available":
            value.update(raw_answers=[], returned_model=None, effective_input_digest=None)
            value["export"]["request_ref"] = None
            if status == "deferred":
                value["timing"] = {"started_at": None, "completed_at": None, "elapsed_ms": None}
                value["reservation"].update(attempts=0, state="reserved")
        result = self.store.put_record("analysis-annotation", value)
        self.annotations.append(result)
        return result

    def evidence(self, source, method, params, result, *, target=None, proofs=(), response=None):
        reply = response if response is not None else {"jsonrpc": "2.0", "id": 1, "result": result}

        def authorize(request):
            request = {**request, "request_id": f"request-{len(self.raw)}"}
            admission = self.origin.admit(self.plan, request, self.grant)
            self.admissions.append(admission)
            return admission

        def offline_transport(endpoint, *, method, payload, max_bytes, timeout_s, before_emit, deadline):
            before_emit()
            return copy.deepcopy(reply), canonical_bytes(reply)

        with self.monkeypatch.context() as transport:
            transport.setattr(observations_module, "_http_json", offline_transport)
            _, ref = observations_module._request(self.store, self.plan, source,
                entity=target or entity(BASE), method="POST", endpoint=source["endpoint"],
                rpc_method=method, params=params, proof_refs=list(proofs),
                authorize=authorize, on_evidence=self.raw.append)
        return ref

    def evm(self, source, *, as_of=AS_OF, logs=()):
        pinned = {"blockHash": source["block_hash"], "requireCanonical": True}
        refs = [self.evidence(source, "eth_chainId", [], "0x1")]
        header = {"number": hex(source["block_number"]), "hash": source["block_hash"],
                  "timestamp": hex(int(instant(as_of).timestamp()))}
        refs.append(self.evidence(source, "eth_getBlockByNumber", [hex(source["block_number"]), False], header))
        common = list(refs)
        for destination in (BASE, QUOTE, POOL, FACTORY):
            refs.append(self.evidence(source, "eth_getCode", [destination, pinned], CODE, proofs=common))
        calls = [(BASE, "decimals", abi(18)), (QUOTE, "decimals", abi(6)),
                 (BASE, "totalSupply", abi(1000 * 10**18)),
                 (POOL, "token0", "0x" + address_word(BASE)), (POOL, "token1", "0x" + address_word(QUOTE)),
                 (POOL, "factory", "0x" + address_word(FACTORY)),
                 (POOL, "getReserves", abi(100 * 10**18, 200 * 10**6, int(instant(as_of).timestamp()) % 2**32))]
        for destination, name, result in calls:
            refs.append(self.evidence(source, "eth_call", [{"to": destination, "data": CALL_SELECTORS[name]}, pinned],
                                      result, proofs=common))
        pair_data = CALL_SELECTORS["getPair"] + address_word(BASE) + address_word(QUOTE)
        refs.append(self.evidence(source, "eth_call", [{"to": FACTORY, "data": pair_data}, pinned],
                                  "0x" + address_word(POOL), proofs=common))
        for wallet in source.get("excluded_supply_addresses", []):
            data = CALL_SELECTORS["balanceOf"] + address_word(wallet)
            refs.append(self.evidence(source, "eth_call", [{"to": BASE, "data": data}, pinned],
                                      abi(100 * 10**18), proofs=common))
        receipt = {"transactionHash": CREATION_TX, "contractAddress": BASE, "status": "0x1",
                   "blockNumber": "0x5a", "blockHash": CREATION_BLOCK, "logs": []}
        creation = self.evidence(source, "eth_getTransactionReceipt", [CREATION_TX], receipt, proofs=common)
        refs.append(creation)
        refs.append(self.evidence(source, "eth_getBlockByNumber", ["0x5a", False],
            {"number": "0x5a", "hash": CREATION_BLOCK,
             "timestamp": hex(int((instant(START) - timedelta(seconds=100)).timestamp()))}, proofs=[*common, creation]))
        if logs:
            log_ref = self.evidence(source, "eth_getLogs", [{"blockHash": source["block_hash"], "address": POOL,
                "topics": [list(V2_TOPICS.values())]}], list(logs), target=entity(pool=POOL), proofs=common)
            refs.append(log_ref)
            for transaction in sorted({log["transactionHash"] for log in logs}):
                refs.append(self.evidence(source, "eth_getTransactionReceipt", [transaction],
                    {"transactionHash": transaction, "status": "0x1", "blockNumber": hex(source["block_number"]),
                     "blockHash": source["block_hash"], "logs": [log for log in logs if log["transactionHash"] == transaction]},
                    target=entity(pool=POOL), proofs=[*common, log_ref]))
        return refs

    def record(self, source, metric, refs, *, target=None, quantity=None, units=None, basis="fixture",
               as_of=AS_OF, event=None, cap_kind=None, owned=True, previous=None, correction=None):
        value = template("verified-observation", "unverified-provider-fdv")
        target = target or entity(BASE)
        rule = ACTOR_RULE if metric == "actor-association" else FLOW_RULE if metric in {
            "swap", "liquidity-add", "liquidity-remove", "reserves", "orderbook-depth", "orderbook-change"} else CRYPTO_RULE
        value.update(observation_id=f"observation-{len(self.observations)}", entity=target, metric=metric,
                     domain="market" if rule == FLOW_RULE else "crypto", quantity=quantity, units=units,
                     cap_kind=cap_kind, as_of=as_of, observed_at=CAPTURED, evaluation_time=EVALUATION, event=event)
        value["measurement_scope"] = {"scope_id": target["entity_id"],
            "aggregation": "venue" if target["venue"] else "pool" if target["pool_address"] else "contract",
            "chain_id": target["chain_id"], "pool_refs": [entity(pool=target["pool_address"])] if target["pool_address"] else [],
            "venue": target["venue"], "constituent_refs": []}
        first = json.loads(self.store.read_blob(refs[0]))
        value["source"] = {"method": source["id"], "binding_id": source["binding_id"], "basis": basis,
                           "evidence_refs": refs, "admission_ref": first["admission_ref"], "endpoint": source["endpoint"]}
        value["verification"] = {"rule_id": rule["id"], "revision": 1, "state": "unverified",
                                 "reasons": ["awaiting-deterministic-reduction"], "input_refs": refs}
        value["coherence"] = {**source["coherence"], "state": "unknown", "as_of_basis": None,
                              "input_refs": refs, "reasons": ["awaiting-cross-evidence-join"]}
        if previous:
            old = self.store.get_record(previous, "verified-observation")
            value.update(observation_id=old["observation_id"], revision=old["revision"] + 1)
            value["correction"] = {"state": correction or "corrected", "supersedes": previous,
                "retracts": [previous] if correction in {"reorg", "retracted"} else [], "reason": "canonical correction"}
        ref = self.store.put_record("verified-observation", value)
        self.observations.append(ref)
        if owned:
            self.owned.append(ref)
        return ref

    def token_facts(self, source, *, as_of=AS_OF):
        refs = self.evm(source, as_of=as_of)
        facts = {}
        for metric, quantity, units, target, basis in (
            ("deployment", None, None, entity(BASE), "canonical-creation-receipt-and-runtime-code"),
            ("total-supply", "1000", UNITS, entity(BASE), "erc20-totalSupply-at-canonical-block"),
            ("price", "2", f"{QUOTE_UNITS}/{UNITS}", entity(BASE, POOL), "v2-spot-reserve-ratio-v1"),
            ("liquidity", "400", QUOTE_UNITS, entity(BASE, POOL), "v2-two-sided-quote-token-reserves-v1")):
            facts[metric] = self.record(source, metric, refs, target=target, quantity=quantity,
                                        units=units, basis=basis, as_of=as_of)
        if source.get("excluded_supply_addresses"):
            facts["circulating-supply"] = self.record(source, "circulating-supply", refs, quantity="900", units=UNITS,
                basis="declared-totalSupply-minus-excluded-balances-v1", as_of=as_of)
        return facts

    def session(self, *, captures=None, annotations=None, observations=None, outputs=(), snapshot=True):
        value = template("monitor-session", "initial-checkpoint")
        value.update(plan_ref={"plan_id": self.plan["plan_id"], "revision": 1, "digest": self.plan["digest"],
                               "artifact_ref": self.plan_ref}, source_frontier=list(self.captures if captures is None else captures),
                     analysis_frontier=list(self.annotations if annotations is None else annotations),
                     observation_frontier=list(self.observations if observations is None else observations), output_refs=list(outputs))
        value["query_state"] = value["query_state"][:1]
        if snapshot and self.plan["profile"]["observation_sources"]:
            frozen = self.origin.snapshot(self.admissions, self.owned + self.raw)
            value["authority_snapshot_ref"] = self.store.put_blob(canonical_bytes(frozen), category="support")
        return validate_record("monitor-session", value)

    def engine(self, *, origin=True, keys=True):
        return AnalyticsEngine(self.store, trusted_keys=self.keys if keys else None,
            trusted_digest=self.trusted_digest if keys else None, trusted_observation_refs=self.owned if origin else [])

    def reduce(self, session=None, **kwargs):
        refs = self.engine().reduce(self.plan, session or self.session(), window_s=60,
                                   evaluation_time=EVALUATION, **kwargs)
        return refs, [self.store.get_record(ref, "analytics-event") for ref in refs]


def window(events, start=START):
    return next(event for event in events if event["event_role"] == "window" and event["window"]["start"] == start)


def swap_log(*, removed=False):
    return {"address": POOL, "blockNumber": "0x64", "blockHash": BLOCK, "transactionHash": TX,
            "logIndex": "0x1", "removed": removed,
            "topics": [V2_TOPICS["swap"], topic_address(WALLET), topic_address(WALLET)],
            "data": abi(0, 20 * 10**6, 10 * 10**18, 0)}


def swap_record(evidence, source, *, maker_label="spoofed-social-maker"):
    log = swap_log()
    raw = evidence.evm(source, logs=[log])
    decoded = decode_v2_log(log, pool=POOL, token0=BASE, token1=QUOTE, decimals0=18, decimals1=6)
    event = {**decoded["chain_event"], "chain_id": "eip155:1", "venue_sequence": None,
             "kind": "swap", "legs": decoded["legs"], "sender": decoded["sender"],
             "recipient": decoded["recipient"], "removed": False, "actor_id": maker_label,
             "evidence_refs": raw, "block_timestamp": AS_OF}
    return evidence.record(source, "swap", raw, target=entity(pool=POOL), event=event,
                           basis="uniswap-v2-exact-ABI-log-and-transaction-receipt")


def test_deduplicates_occurrences_without_promoting_amplification(tmp_vault):
    data = Evidence(tmp_vault, analyzed=True)
    original = data.capture()
    duplicate = data.capture(query="q1")
    context = data.capture("2001", role="context", text="Example product context", occurrence="context")
    repost = data.capture("1002", kind="repost", author="43", occurrence="repost-one",
        relationships=[{"kind": "repost-of", "target_post_id": "1001", "delivery": "delivered", "capture_ref": original}])
    quote = data.capture("1003", kind="quote", author=None, occurrence="quote-one",
        relationships=[{"kind": "quote-of", "target_post_id": "2001", "delivery": "delivered", "capture_ref": context}])
    data.annotate(original)
    data.annotate(repost, contexts=[original])
    data.annotate(quote, contexts=[context])
    event = window(data.reduce()[1])
    assert duplicate in event["input_refs"]["capture_refs"] or original in event["input_refs"]["capture_refs"]
    assert context in event["input_refs"]["capture_refs"]
    assert event["metrics"]["post_count"] == 3
    assert event["metrics"]["duplicate_occurrences"] == 1
    assert event["metrics"]["unique_authors"] == 2
    assert event["metrics"]["unique_original_authors"] == 1
    assert event["metrics"]["event_type_counts"] == {"original": 1, "repost": 1, "quote": 1, "reply": 0, "unknown": 0}
    assert event["metrics"]["sentiment_by_event_type"]["original"]["positive"] == 1
    assert event["metrics"]["sentiment_by_event_type"]["repost"]["positive"] == 1
    assert event["metrics"]["target_counts"]["matched"] == 3
    assert event["denominators"]["covered"] == 3
    assert event["coverage"]["state"] != "complete"
    assert event["provisional"]


@pytest.mark.parametrize("status,denominator", [("abstained", "abstained"), ("insufficient-context", "insufficient_context"),
    ("unavailable", "unavailable"), ("failed", "errors"), ("deferred", "deferred")])
def test_unavailable_answers_keep_denominators_and_never_become_neutral(tmp_vault, status, denominator):
    data = Evidence(tmp_vault, analyzed=True)
    focal = data.capture()
    data.annotate(focal, status=status)
    session = data.session()
    session["coverage_gaps"] = [{"scope_id": "gap", "query_id": "q1", "state": "error", "start": START,
        "end": "2026-10-10T00:01:00Z", "receipt_ref": None, "reasons": ["durable source gap"]}]
    event = window(data.reduce(session)[1])
    assert event["denominators"]["total"] == event["denominators"]["unknown"] == 1
    assert event["denominators"][denominator] == 1
    assert event["metrics"]["sentiment_counts"]["neutral"] == 0
    assert event["metrics"]["sentiment_counts"]["unknown"] == 1
    assert event["metrics"]["source_gap_count"] >= 1
    assert event["evaluation_time"] == EVALUATION
    assert data.store.get_record(focal, "source-capture")["event_time"] == AS_OF
    assert data.store.get_record(focal, "source-capture")["captured_at"] == CAPTURED


def test_new_context_wins_over_old_answer_completed_later(tmp_vault):
    data = Evidence(tmp_vault, analyzed=True)
    old_context = data.capture("2001", role="context", text="Old context", revision=1)
    focal = data.capture(relationships=[{"kind": "quote-of", "target_post_id": "2001",
                                      "delivery": "delivered", "capture_ref": old_context}])
    old_answer = data.annotate(focal, contexts=[old_context], completed_at="2026-10-10T00:00:49Z")
    new_context = data.capture("2001", role="context", text="Corrected context", revision=2,
                               captured_at="2026-10-10T00:00:35Z")
    unanswered = data.session(captures=[focal, new_context], annotations=[old_answer])
    unknown = window(data.reduce(unanswered)[1])
    assert unknown["denominators"]["covered"] == 0
    assert unknown["metrics"]["stale_annotations"] == 1
    new_answer = data.annotate(focal, choice="negative", contexts=[new_context], completed_at="2026-10-10T00:00:40Z")
    late = data.annotate(focal, contexts=[old_context], revision=2, supersedes=old_answer,
                         completed_at="2026-10-10T00:00:49Z")
    session = data.session(captures=[focal, new_context], annotations=[late, new_answer])
    _, events = data.reduce(session)
    event = window(events)
    assert event["metrics"]["sentiment_counts"]["negative"] == 1
    assert event["metrics"]["sentiment_counts"]["positive"] == 0
    assert event["input_refs"]["annotation_refs"] == [new_answer]
    assert event["metrics"]["stale_annotations"] >= 1


def test_complete_crypto_criteria_are_not_buy_advice(tmp_vault):
    source = binding()
    data = Evidence(tmp_vault, "crypto-discovery", [source])
    data.capture(text=f"🚀 Ethereum contract {BASE}; symbol $EXAMPLE")
    data.token_facts(source)
    _, events = data.reduce()
    lead = next(lead for lead in window(events)["metrics"]["leads"] if lead["entity"]["contract_address"] == BASE)
    assert lead["disposition"] == "matches-criteria"
    assert lead["facts"]["cap"]["quantity"] == "2000"
    assert lead["facts"]["cap"]["kind"] == "fdv"
    assert lead["facts"]["cap"]["currency"] == QUOTE_UNITS
    assert lead["facts"]["liquidity"]["quantity"] == "400"
    assert lead["facts"]["age"]["seconds"] == 150
    assert lead["facts"]["snapshot"]["block_hash"] == BLOCK
    assert any(event["event_role"] == "lead" and event["subject"]["contract_address"] == BASE for event in events)
    assert all(event["disposition"] in {"observed", "needs-verification", "matches-criteria", "does-not-match", "retracted"} for event in events)
    span = next(span for span in lead["source_spans"] if span["text"] == BASE)
    capture = data.store.get_record(span["capture_ref"], "source-capture")
    assert capture["text"][span["start"]:span["end"]] == BASE


@pytest.mark.parametrize("mutation", ["decimal", "unit", "cap-kind", "stale", "scope", "unsupported-rule"])
def test_unknown_or_incompatible_crypto_facts_do_not_become_matches(tmp_vault, mutation):
    source = binding()
    data = Evidence(tmp_vault, "crypto-discovery", [source])
    data.capture(text=f"Ethereum contract {BASE}")
    facts = data.token_facts(source)
    if mutation in {"cap-kind", "unsupported-rule"}:
        criteria = data.plan["profile"]["criteria"]
        if mutation == "cap-kind":
            criteria["cap"]["kind"] = "circulating-market-cap"
        else:
            criteria["verification_rule"]["revision"] = 2
        data.plan = finalize(data.plan)
        data.plan_ref = data.store.put_record("monitor-plan", data.plan)
        # Changing criteria is intentionally a separate lineage: a signed old
        # grant cannot be silently reused as authority for a changed plan.
    elif mutation == "stale":
        refs = data.engine().reduce(data.plan, data.session(), window_s=60,
                                   evaluation_time="2026-10-10T00:05:00Z")
        events = [data.store.get_record(ref, "analytics-event") for ref in refs]
        lead = next(lead for lead in window(events)["metrics"]["leads"] if lead["entity"]["contract_address"] == BASE)
        assert lead["disposition"] == "needs-verification"
        return
    else:
        original = data.store.get_record(facts["price"], "verified-observation")
        if mutation == "decimal":
            original["quantity"] = "2000000000000"
        elif mutation == "unit":
            original["units"] = "USD/token"
        else:
            original["measurement_scope"]["scope_id"] = "an-unrelated-aggregate"
            original["measurement_scope"]["aggregation"] = "aggregate"
        original["revision"] = 2
        original["correction"] = {"state": "corrected", "supersedes": facts["price"], "retracts": [], "reason": "test mismatch"}
        changed = data.store.put_record("verified-observation", original)
        data.observations.append(changed)
        data.owned.append(changed)
    event = window(data.reduce()[1])
    lead = next(lead for lead in event["metrics"]["leads"] if lead["entity"]["contract_address"] == BASE)
    assert lead["disposition"] == "needs-verification"


@pytest.mark.parametrize("bound,threshold", [("maximum", "1500"), ("minimum", "2500")])
def test_no_match_requires_known_facts_not_missing_measurements(tmp_vault, bound, threshold):
    source = binding()
    data = Evidence(tmp_vault, "crypto-discovery", [source])
    data.plan["profile"]["criteria"]["cap"][bound] = threshold
    data.plan = finalize(data.plan)
    data.plan_ref = data.store.put_record("monitor-plan", data.plan)
    data.grant = data.make_grant()
    data.capture(text=f"Ethereum contract {BASE}")
    data.token_facts(source)
    lead = next(lead for lead in window(data.reduce()[1])["metrics"]["leads"] if lead["entity"]["contract_address"] == BASE)
    assert lead["disposition"] == "does-not-match"
    assert lead["facts"]["cap"]["quantity"] == "2000"
    assert lead["reasons"] == [f"cap-{bound}-not-satisfied"]


def test_circulating_cap_requires_the_declared_supply_basis(tmp_vault):
    source = binding()
    source["excluded_supply_addresses"] = [WALLET]
    data = Evidence(tmp_vault, "crypto-discovery", [source])
    data.plan["profile"]["criteria"]["cap"].update(kind="circulating-market-cap",
        supply_basis="declared-totalSupply-minus-excluded-balances-v1")
    data.plan = finalize(data.plan)
    data.plan_ref = data.store.put_record("monitor-plan", data.plan)
    data.grant = data.make_grant()
    data.capture(text=f"Ethereum contract {BASE}")
    data.token_facts(source)
    lead = next(lead for lead in window(data.reduce()[1])["metrics"]["leads"] if lead["entity"]["contract_address"] == BASE)
    assert lead["disposition"] == "matches-criteria"
    assert lead["facts"]["cap"]["quantity"] == "1800"
    assert lead["facts"]["cap"]["kind"] == "circulating-market-cap"


def test_cross_block_snapshots_are_incoherent_even_with_valid_individual_proofs(tmp_vault):
    first = binding()
    second = binding(identity="rpc-second", height=101, digest="0x" + "e" * 64)
    data = Evidence(tmp_vault, "crypto-discovery", [first, second])
    data.capture(text=f"Ethereum contract {BASE}")
    first_facts = data.token_facts(first)
    second_facts = data.token_facts(second, as_of="2026-10-10T00:00:11Z")
    selected = [first_facts[key] for key in ("deployment", "total-supply", "liquidity")] + [second_facts["price"]]
    lead = next(lead for lead in window(data.reduce(data.session(observations=selected))[1])["metrics"]["leads"]
                if lead["entity"]["contract_address"] == BASE)
    assert lead["disposition"] == "needs-verification"
    assert any("coher" in reason or "as-of" in reason or "block" in reason for reason in lead["reasons"])


def test_bare_symbols_and_ambiguous_chains_remain_source_only(tmp_vault):
    data = Evidence(tmp_vault, "crypto-discovery")
    data.capture(text=f"Ethereum and Polygon: {BASE}; new $EXAMPLE")
    event = window(data.reduce()[1])
    assert event["metrics"]["leads"]
    assert all(lead["disposition"] == "needs-verification" for lead in event["metrics"]["leads"])
    assert all(lead["entity"]["chain_id"] is None for lead in event["metrics"]["leads"])
    assert captured_leads(data.store, data.captures) == []


def test_imported_self_signed_snapshot_and_copied_grant_never_establish_origin(tmp_vault):
    source = binding()
    data = Evidence(tmp_vault, "crypto-discovery", [source])
    data.capture(text=f"Ethereum contract {BASE}")
    data.token_facts(source)
    session = data.session()
    for engine in (AnalyticsEngine(data.store), data.engine(origin=False), data.engine(keys=False)):
        refs = engine.reduce(data.plan, session, window_s=60, evaluation_time=EVALUATION)
        events = [data.store.get_record(ref, "analytics-event") for ref in refs]
        lead = next(lead for lead in window(events)["metrics"]["leads"] if lead["entity"]["contract_address"] == BASE)
        assert lead["disposition"] == "needs-verification"
        assert window(events)["metrics"]["observation_status_counts"]["verified"] == 0


def test_genuine_swap_and_spoofed_maker_label_do_not_verify_actor(tmp_vault):
    source = binding()
    source["verification_rule"] = FLOW_RULE
    data = Evidence(tmp_vault, "market-flow", [source])
    data.capture(text="This wallet is definitely a market maker")
    swap_record(data, source)
    event = window(data.reduce()[1])
    flow = next(flow for flow in event["metrics"]["flows"] if flow["units"] == UNITS)
    assert flow["quantity"] == "10"
    assert flow["kind"] == "swap-net"
    assert flow["actor_state"] in {"unknown", "unverified"}
    assert flow["measurement_scope"]["scope_id"] == f"eip155:1:{POOL}"
    transfer = copy.deepcopy(swap_log())
    transfer["topics"][0] = "0x" + "f" * 64
    with pytest.raises(ValueError):
        decode_v2_log(transfer, pool=POOL, token0=BASE, token1=QUOTE, decimals0=18, decimals1=6)


def test_reorg_retracts_contribution_without_arrival_order_overrides(tmp_vault):
    source = binding()
    source["verification_rule"] = FLOW_RULE
    data = Evidence(tmp_vault, "market-flow", [source])
    previous = swap_record(data, source)
    old_refs, old_events = data.reduce()
    assert next(flow for flow in window(old_events)["metrics"]["flows"] if flow["units"] == UNITS)["quantity"] == "10"
    raw = [data.evidence(source, "eth_chainId", [], "0x1"), data.evidence(source,
        "eth_getBlockByNumber", ["0x64", False], {"number": "0x64", "hash": "0x" + "e" * 64,
        "timestamp": hex(int(instant(AS_OF).timestamp()))})]
    old = data.store.get_record(previous, "verified-observation")
    correction = data.record(source, "swap", raw, target=old["entity"], event={**old["event"], "removed": True},
        previous=previous, correction="reorg", basis="canonical-block-hash-changed-v1")
    session = data.session(observations=[correction, previous], outputs=old_refs)
    refs, events = data.reduce(session)
    event = window(events)
    assert event["retraction"]
    assert previous in event["retracted_inputs"]
    assert event["revision"] == window(old_events)["revision"] + 1
    assert all(flow["quantity"] is None for flow in event["metrics"]["flows"])
    assert data.store.get_record(previous, "verified-observation")["event"]["removed"] is False
    reverse = {**session, "observation_frontier": list(reversed(session["observation_frontier"]))}
    assert data.engine().reduce(data.plan, reverse, window_s=60, evaluation_time=EVALUATION) == refs


def test_capture_content_repair_visibly_retracts_old_token_lead(tmp_vault):
    source = binding()
    data = Evidence(tmp_vault, "crypto-discovery", [source])
    original = data.capture(text=f"Ethereum contract {BASE}")
    data.token_facts(source)
    old_refs, old_events = data.reduce()
    previous_lead = next(event for event in old_events if event["event_role"] == "lead"
                         and event["subject"]["contract_address"] == BASE)
    assert previous_lead["disposition"] == "matches-criteria"
    repaired = data.capture(text="The previous contract address was wrong.", revision=2, role="context",
                             captured_at="2026-10-10T00:00:35Z")
    _, events = data.reduce(data.session(captures=[original, repaired], outputs=old_refs))
    lead_event = next(event for event in events if event["event_role"] == "lead" and event["subject"]["contract_address"] == BASE)
    assert lead_event["retraction"]
    assert original in lead_event["retracted_inputs"]
    assert lead_event["disposition"] == "retracted"
    assert lead_event["supersedes"] in old_refs
    assert set(map(ref_key, previous_lead["input_refs"]["observation_refs"])).issubset(
        set(map(ref_key, lead_event["retracted_inputs"])))
    assert original in window(events)["retracted_inputs"]
    assert data.store.get_record(original, "source-capture")["text"].endswith(BASE)


def test_replay_is_frozen_and_policy_changes_have_distinct_lineage(tmp_vault, monkeypatch):
    data = Evidence(tmp_vault, analyzed=True)
    focal = data.capture()
    data.annotate(focal)
    session = data.session()
    def forbidden(*args, **kwargs):
        raise AssertionError("Replay attempted a source/model/market/network call")
    monkeypatch.setattr(socket, "getaddrinfo", forbidden)
    monkeypatch.setattr("hyperresearch.core.x_analytics.observe", forbidden)
    monkeypatch.setattr("hyperresearch.core.x_observations._http_json", forbidden)
    monkeypatch.setattr("httpx.Client", forbidden)
    first = data.engine().reduce(data.plan, session, window_s=60, evaluation_time=EVALUATION)
    data.capture("9999", text="Global unrelated input must not enter frozen replay")
    assert data.engine().reduce(data.plan, session, window_s=60, evaluation_time=EVALUATION) == first
    policy = {**data.plan["analysis"]["guard_policy"], "id": "independent-policy", "revision": 2}
    second = data.engine().reduce(data.plan, session, window_s=60, evaluation_time=EVALUATION, policy=policy)
    assert set(ref_key(ref) for ref in first).isdisjoint(ref_key(ref) for ref in second)
    assert all(data.store.get_record(ref, "analytics-event")["supersedes"] is None for ref in second)


def test_observation_admission_precedes_network_and_true_is_not_a_grant(tmp_vault, monkeypatch):
    data = Evidence(tmp_vault, "crypto-discovery", [binding()])
    focal = data.capture(text=f"Ethereum {BASE}")
    def forbidden(*args, **kwargs):
        raise AssertionError("Request was sent before structured admission")
    monkeypatch.setattr("hyperresearch.core.x_observations._http_json", forbidden)
    monkeypatch.setattr(socket, "getaddrinfo", forbidden)
    with pytest.raises(ObservationCollectionError) as raised:
        data.engine().observe(data.plan, [focal], authorize=lambda request: True)
    assert raised.value.observation_refs == []
    assert raised.value.reason == "PermissionError"


def test_dynamic_lead_scope_uses_only_attributed_focal_spans(tmp_vault):
    source = binding(adapter="dexscreener-pair", identity="dex")
    source.update(endpoint="https://api.dexscreener.com/token-pairs/v1", allowed_hosts=["api.dexscreener.com"],
                  contract_addresses=[], pool_addresses=[], entity_scope="captured-leads", rpc_methods=[], call_selectors=[])
    data = Evidence(tmp_vault, "crypto-discovery", [source])
    good = data.capture(text=f"🚀 Ethereum {BASE}")
    ambiguous = data.capture("1002", text=f"Ethereum or Polygon {BASE}")
    bare = data.capture("1003", text=f"$EXAMPLE {BASE}")
    context = data.capture("1004", text=f"Ethereum {BASE}", role="context")
    leads = captured_leads(data.store, [bare, context, ambiguous, good])
    assert len(leads) == 1 and leads[0]["capture_ref"] == good
    assert dex_endpoint(source, leads[0]["entity"]) == f"https://api.dexscreener.com/token-pairs/v1/ethereum/{BASE}"
    with pytest.raises(ValueError):
        dex_endpoint({**source, "endpoint": "https://api.dexscreener.com/arbitrary/{address}"}, leads[0]["entity"])
