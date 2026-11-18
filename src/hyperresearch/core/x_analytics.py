"""Deterministic, observational X analytics over an explicitly committed evidence closure.

``AnalyticsEngine(store).reduce(plan, session, window_s=..., evaluation_time=...)``
is deliberately a local reducer. It never calls ``observe``, a source provider,
a model, DNS, or a mutable freshness clock. The optional policy is a governed
analysis-policy snapshot and creates a distinct logical lineage. Source/market
refresh is a separate, explicitly authorized ``observe`` operation.

Windows use event time; capture/model/observation clocks remain inspectable via
exact canonical input references. Reposts/quotes are NOT independent originals.
Token joins use chain+contract and named cap/units/methods, never a ticker or a
model assertion. All outputs are research observations, never buy/sell advice.
"""

from __future__ import annotations

import json
import re
from collections import defaultdict
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from decimal import Decimal, localcontext
from fractions import Fraction
from typing import Any

from hyperresearch import __version__
from hyperresearch.core.x_observations import (
    COHERENCE_RULE,
    CRYPTO_RULE,
    FLOW_RULE,
    EvidenceResult,
    ObservationVerifier,
    chains_for_span,
    decimal,
    decimal_text,
    instant,
    observe,
    ref_key,
    timestamp,
)
from hyperresearch.models.x_evidence import plan_digest, record_digest, validate_record

EVENT_TYPES = ("original", "repost", "quote", "reply", "unknown")
SENTIMENTS = ("positive", "negative", "neutral", "mixed", "bullish", "bearish", "unknown")
STATUSES = ("available", "abstained", "insufficient-context", "unavailable", "failed", "deferred")


def _refs(values: list[dict]) -> list[dict]:
    return sorted({ref_key(ref): ref for ref in values}.values(), key=ref_key)


def _bucket(value: datetime, size: int) -> datetime:
    seconds = int(value.timestamp())
    return datetime.fromtimestamp(seconds // size * size, UTC)


def _capture_content(capture: dict) -> str:
    # Query occurrence, role and acquisition clocks do not change delivered content.
    return record_digest({key: capture[key] for key in
                          ("post_id", "revision", "author", "text")})


def _event_key(capture: dict) -> tuple:
    kind = capture["event_type"]
    if kind == "repost":
        # Missing repost identity is one uncertain occurrence, never N independent posts.
        return kind, capture["occurrence"]["timeline_event_id"] or capture["post_id"]
    return kind, capture["post_id"]


def _entity(chain: str | None, contract: str | None, *, symbol: str | None = None) -> dict:
    contract = contract.lower() if contract and contract.startswith("0x") else contract
    identity = f"{chain}:{contract}" if chain and contract else (
        "unresolved-address:" + (contract or "unknown") if contract else "unresolved-symbol:" + (symbol or "unknown")
    )
    return {"namespace": "chain-contract" if chain and contract else "entity",
            "entity_id": identity, "chain_id": chain, "contract_address": contract,
            "pool_address": None, "venue": None}




@dataclass
class CaptureInput:
    ref: dict
    capture: dict
    annotation_ref: dict | None = None
    annotation: dict | None = None
    guarded: dict | None = None
    status: str = "unavailable"
    reasons: tuple[str, ...] = ()
    duplicate_count: int = 0
    occurrence_ref: dict | None = None
    stale_annotations: int = 0


@dataclass
class ObservationInput:
    ref: dict
    observation: dict
    result: EvidenceResult
    effective: bool = True


class AnalyticsEngine:
    """Canonical-store analytics; the store owns all persistence and projections."""

    def __init__(self, store: Any, *, trusted_keys: dict[str, str] | None = None,
                 trusted_digest: str | None = None,
                 trusted_observation_refs: list[dict] | None = None):
        self.store = store
        self.trusted_keys = dict(trusted_keys or {})
        self.trusted_digest = trusted_digest
        self.trusted_observation_refs = frozenset(ref_key(ref) for ref in trusted_observation_refs or [])
        if self.trusted_keys and not trusted_digest:
            raise ValueError("Independent frozen keys require their trusted digest")

    def observe(self, plan: dict, capture_refs: list[dict], *, authorize: Any,
                on_evidence: Any = None, revalidate: Any = None, on_undispatched: Any = None) -> list[dict]:
        """Explicit owned collection; reducers/replay never invoke this seam."""
        prior = []
        for path, digest in sorted(self.trusted_observation_refs):
            ref = {"path": path, "sha256": digest}
            try:
                self.store.get_record(ref, "verified-observation")
            except ValueError:
                continue
            prior.append(ref)
        return observe(self.store, plan, capture_refs, authorize=authorize,
                       on_evidence=on_evidence, prior_observation_refs=prior,
                       revalidate=revalidate, on_undispatched=on_undispatched)

    def _capture_inputs(self, plan: dict, records: list[dict], evaluation: datetime,
                        policy: dict) -> tuple[list[CaptureInput], list[dict], dict[str, dict]]:
        captures = [item for item in records if item["kind"] == "source-capture"
                    and instant(item["payload"]["captured_at"]) <= evaluation]
        by_ref = {ref_key(item["ref"]): item for item in captures}
        by_post: dict[str, list[dict]] = defaultdict(list)
        for item in captures:
            by_post[item["payload"]["post_id"]].append(item)
        newest = {}
        conflicts = set()
        for post, items in by_post.items():
            revision = max(item["payload"]["revision"] for item in items)
            effective = [item for item in items if item["payload"]["revision"] == revision]
            newest[post] = min(effective, key=lambda item: ref_key(item["ref"]))
            if len({_capture_content(item["payload"]) for item in effective}) != 1:
                conflicts.add(post)
        queries = {(query["id"], query["revision"]) for query in plan["queries"]}
        by_event: dict[tuple, list[dict]] = defaultdict(list)
        context_refs = []
        for item in captures:
            capture = item["payload"]
            if capture["role"] == "context":
                context_refs.append(item["ref"])
                continue
            occurrence = capture["occurrence"]
            if occurrence["query_id"] is not None and (occurrence["query_id"], occurrence["query_revision"]) not in queries:
                continue
            by_event[_event_key(capture)].append(item)
        annotations = [item for item in records if item["kind"] == "analysis-annotation"
                       and (item["payload"]["timing"]["completed_at"] is None
                            or instant(item["payload"]["timing"]["completed_at"]) <= evaluation)]
        inputs = []
        for items in by_event.values():
            revision = max(item["payload"]["revision"] for item in items)
            effective = [item for item in items if item["payload"]["revision"] == revision]
            # Preserve primary membership when another query saw identical content as unknown.
            effective.sort(key=lambda item: (item["payload"]["role"] != "primary", ref_key(item["ref"])))
            selected = effective[0]
            capture, ref = selected["payload"], selected["ref"]
            occurrence_ref = ref
            current_content = newest[capture["post_id"]]
            if current_content["payload"]["revision"] > capture["revision"]:
                # Content repair does not invent a new timeline event. Keep the
                # original event/occurrence reference independently of current text.
                capture = {**current_content["payload"],
                           **{key: capture[key] for key in ("role", "event_type", "event_time", "occurrence")}}
                ref = current_content["ref"]
            item_input = CaptureInput(ref, capture, duplicate_count=len(items) - 1,
                                      occurrence_ref=occurrence_ref)
            if capture["post_id"] in conflicts:
                item_input.reasons = ("conflicting-committed-capture-revision",)
                inputs.append(item_input)
                continue
            eligible = []
            for candidate in annotations:
                annotation = candidate["payload"]
                focal = by_ref.get(ref_key(annotation["capture_ref"]))
                if focal is None:
                    focal = {"payload": self.store.get_record(annotation["capture_ref"], "source-capture")}
                if (focal["payload"]["post_id"] != capture["post_id"]
                        or focal["payload"]["event_type"] != capture["event_type"]):
                    continue
                valid, reasons = self._annotation_binding(plan, capture, annotation, by_ref, newest, conflicts)
                if not valid:
                    item_input.stale_annotations += 1
                    continue
                eligible.append({**candidate, "binding_reasons": reasons})
            if eligible:
                # Revision/supersedes, not completion time, determines effective annotation.
                superseded = {ref_key(candidate["payload"]["supersedes"])
                              for candidate in eligible if candidate["payload"].get("supersedes")}
                leaves = [candidate for candidate in eligible if ref_key(candidate["ref"]) not in superseded]
                leaves.sort(key=lambda candidate: (candidate["payload"]["revision"],
                                                    candidate["payload"]["policy_ref"] == {"id": policy["id"], "revision": policy["revision"]},
                                                    ref_key(candidate["ref"])))
                chosen = leaves[-1] if leaves else eligible[0]
                same_rank = [candidate for candidate in leaves
                             if candidate["payload"]["revision"] == chosen["payload"]["revision"]
                             and candidate["payload"]["policy_ref"] == chosen["payload"]["policy_ref"]]
                answers = {record_digest({"status": candidate["payload"]["status"],
                                          "raw": candidate["payload"]["raw_answers"]}) for candidate in same_rank}
                if len(answers) > 1:
                    item_input.reasons = ("conflicting-committed-annotation-frontier",)
                else:
                    from hyperresearch.core.x_classifier import guard_answers

                    annotation = chosen["payload"]
                    reasons = chosen["binding_reasons"]
                    item_input.annotation_ref = chosen["ref"]
                    item_input.annotation = annotation
                    item_input.status = annotation["status"]
                    context_post_ids = tuple(
                        self.store.get_record(context["capture_ref"], "source-capture")["post_id"]
                        for context in annotation["context_refs"] if context["delivery"] == "delivered"
                    )
                    guard_annotation = annotation
                    if "model-context-text-not-complete" in reasons:
                        guard_annotation = {**annotation, "export": {**annotation["export"], "context_state": "partial"}}
                    item_input.guarded = guard_answers(guard_annotation, policy, capture["post_id"],
                                                       context_post_ids=context_post_ids)
                    item_input.reasons = tuple(sorted(set(item_input.guarded["reasons"]) | set(reasons)))
                    if (plan["profile"]["id"] == "generic-sentiment"
                            and plan["profile"]["criteria"]["require_context"]
                            and (any(rel["target_post_id"] not in newest for rel in capture["relationships"])
                                 or (capture["relationships"] and annotation["export"]["context_state"] != "complete")
                                 or "model-context-text-not-complete" in reasons)):
                        item_input.status = "insufficient-context"
                        item_input.guarded["sentiment"] = None
            inputs.append(item_input)
        return (sorted(inputs, key=lambda item: (_event_key(item.capture), ref_key(item.ref))),
                _refs(context_refs), {post: item for post, item in newest.items() if post not in conflicts})

    def _annotation_binding(self, plan: dict, capture: dict, annotation: dict,
                            by_ref: dict, newest: dict, conflicts: set) -> tuple[bool, tuple[str, ...]]:
        focal = by_ref.get(ref_key(annotation["capture_ref"]))
        if focal is None:
            focal = {"payload": self.store.get_record(annotation["capture_ref"], "source-capture")}
        if (annotation["capture_revision"] != capture["revision"]
                or _capture_content(focal["payload"]) != _capture_content(capture)):
            return False, ("stale-focal-capture",)
        expected_plan = {"plan_id": plan["plan_id"], "revision": plan["revision"], "digest": plan["digest"]}
        annotation_plan = annotation.get("plan_ref")
        if not annotation_plan or any(annotation_plan.get(key) != value for key, value in expected_plan.items()):
            return False, ("annotation-plan-lineage-mismatch",)
        if annotation.get("profile_ref") != {"id": plan["profile"]["id"], "revision": plan["profile"]["revision"]}:
            return False, ("annotation-profile-lineage-mismatch",)
        query = annotation["query_ref"]
        if query and not any(query == {"query_id": item["id"], "revision": item["revision"]} for item in plan["queries"]):
            return False, ("annotation-query-lineage-mismatch",)
        occurrence = capture["occurrence"]
        expected_query = ({"query_id": occurrence["query_id"], "revision": occurrence["query_revision"]}
                          if occurrence["query_id"] is not None else None)
        if query != expected_query:
            return False, ("annotation-focal-query-mismatch",)
        if annotation["policy_ref"] != plan["analysis"]["policy"]:
            return False, ("annotation-policy-lineage-mismatch",)
        if annotation["rubric_ref"] != plan["analysis"]["rubric"]:
            return False, ("annotation-rubric-lineage-mismatch",)
        delivered_ids = set()
        context_sources = []
        binding_reasons = []
        for context in annotation["context_refs"]:
            supplied = by_ref.get(ref_key(context["capture_ref"]))
            if supplied is None:
                try:
                    supplied = {"payload": self.store.get_record(context["capture_ref"], "source-capture")}
                except ValueError:
                    if (context["delivery"] != "delivered" and any(
                            rel["capture_ref"] == context["capture_ref"] for rel in capture["relationships"])):
                        context_sources.append(None)
                        continue
                    return False, ("context-not-in-committed-frontier",)
            source = supplied["payload"]
            context_sources.append(source)
            current = newest.get(source["post_id"])
            if (current is None or source["post_id"] in conflicts
                    or context["revision"] != source["revision"]
                    or _capture_content(source) != _capture_content(current["payload"])):
                return False, ("stale-context-capture",)
            if context["delivery"] == "delivered":
                delivered_ids.add(source["post_id"])
        required_ids = {rel["target_post_id"] for rel in capture["relationships"]}
        if annotation["status"] == "available" and not (required_ids & newest.keys()).issubset(delivered_ids):
            return False, ("newer-context-not-delivered-to-annotation",)
        if annotation["status"] == "available":
            if (annotation["requested_model"] != plan["analysis"]["model"]
                    or annotation["returned_model"] != annotation["requested_model"]):
                return False, ("model-lineage-mismatch",)
            request = annotation["export"]["request_ref"]
            if not request or request["sha256"] != annotation["effective_input_digest"]:
                return False, ("actual-model-input-digest-mismatch",)
            wire = json.loads(self.store.read_blob(request))
            if wire.get("model") != annotation["requested_model"]:
                return False, ("model-wire-binding-mismatch",)
            if wire.get("state", {}).get("profile_target") != plan["profile"]["target"]:
                return False, ("model-wire-target-binding-mismatch",)
            from hyperresearch.core.x_classifier import (
                default_policy,
                project_capture_block,
                project_plan_question,
            )

            recorded_policy = validate_record("export-policy", json.loads(self.store.read_blob(annotation["export"]["policy_ref"])))
            if recorded_policy != plan["analysis"]["export_policy"]:
                return False, ("export-policy-lineage-mismatch",)
            trusted_policy = annotation.get("trusted_policy_ref")
            if (not trusted_policy or validate_record("analysis-policy", json.loads(self.store.read_blob(trusted_policy)))
                    != default_policy(plan)):
                return False, ("trusted-guard-policy-lineage-mismatch",)
            expected_focal = project_capture_block(focal["payload"], "focal", recorded_policy)
            if expected_focal is None or wire.get("state", {}).get("focal") != expected_focal:
                return False, ("model-wire-focal-projection-mismatch",)
            expected_query = next((query for query in plan["queries"]
                                   if annotation["query_ref"] == {"query_id": query["id"], "revision": query["revision"]}), None)
            if ("query" in recorded_policy["payload_fields"]
                    and wire.get("state", {}).get("query") != expected_query):
                return False, ("model-wire-query-binding-mismatch",)
            expected_context = []
            for index, source in enumerate(context_sources, 1):
                if source is not None:
                    block = project_capture_block(source, f"context-{index}", recorded_policy)
                    if block is not None:
                        expected_context.append(block)
            if len(expected_context) != len(context_sources):
                binding_reasons.append("model-context-text-not-complete")
            if wire.get("state", {}).get("context") != expected_context:
                return False, ("model-wire-context-projection-mismatch",)
            if wire.get("questions") != {question["id"]: project_plan_question(question)
                                         for question in plan["analysis"]["questions"]}:
                return False, ("model-wire-question-controls-mismatch",)
            question_refs = {item["id"]: item for item in annotation["question_refs"]}
            for question in plan["analysis"]["questions"]:
                expected = {"id": question["id"], "revision": question["revision"],
                            "options_digest": record_digest(question["options"])}
                if question_refs.get(question["id"]) != expected:
                    return False, ("question-options-lineage-mismatch",)
            for answer in annotation["raw_answers"]:
                question_ref = question_refs.get(answer["question_id"])
                compiled = wire.get("questions", {}).get(answer["question_id"])
                if (question_ref is None or compiled is None
                        or question_ref["revision"] != answer["question_revision"]
                        or (answer["choice"] is not None and answer["choice"] not in compiled.get("criteria", {}))):
                    return False, ("typed-answer-options-mismatch",)
        for span in annotation["source_spans"]:
            attributed = by_ref.get(ref_key(span["capture_ref"]))
            if attributed is None:
                attributed = {"payload": self.store.get_record(span["capture_ref"], "source-capture")}
            if (attributed is None or span["end"] < span["start"]
                    or attributed["payload"]["text"][span["start"]:span["end"]] != span["text"]):
                return False, ("source-span-attribution-mismatch",)
        return True, tuple(binding_reasons)

    def _observation_inputs(self, plan: dict, records: list[dict], evaluation: datetime,
                            snapshot: dict | None) -> tuple[list[ObservationInput], list[dict]]:
        verifier = ObservationVerifier(self.store, plan, snapshot,
                                       trusted_observation_refs=self.trusted_observation_refs)
        candidates = [item for item in records if item["kind"] == "verified-observation"
                      and instant(item["payload"]["observed_at"]) <= evaluation]
        by_ref = {ref_key(item["ref"]): item for item in candidates}
        invalidated = set()
        corrections = []
        ignored_corrections = set()
        for item in candidates:
            observation = item["payload"]
            correction = observation["correction"]
            targets = correction["retracts"] + ([correction["supersedes"]] if correction["supersedes"] else [])
            if not targets:
                continue
            # A declared correction is checked, not permission to retract an unrelated entity.
            allowed = True
            for ref in targets:
                old = by_ref.get(ref_key(ref))
                if old is None or not verifier.verify_correction(
                        observation, old["payload"], observation_ref=item["ref"], previous_ref=old["ref"]).known:
                    allowed = False
            if allowed:
                invalidated.update(ref_key(ref) for ref in targets)
                corrections.append(item["ref"])
            elif ref_key(item["ref"]) not in self.trusted_observation_refs:
                ignored_corrections.add(ref_key(item["ref"]))
        groups: dict[tuple, list[dict]] = defaultdict(list)
        for item in candidates:
            if ref_key(item["ref"]) in invalidated:
                continue
            observation = item["payload"]
            event = observation["event"]
            event_identity = ((event["chain_id"], event["block_hash"], event["transaction_hash"], event["log_index"])
                              if event and event["transaction_hash"] else
                              (observation["entity"]["venue"], event["venue_sequence"])
                              if event and event["venue_sequence"] else None)
            key = (observation["observation_id"],) if event_identity is None else (observation["metric"], event_identity)
            if ref_key(item["ref"]) in ignored_corrections:
                key = ("unadmitted-correction", ref_key(item["ref"]))
            groups[key].append(item)
        outputs = []
        for group in groups.values():
            group.sort(key=lambda item: (item["payload"]["revision"], ref_key(item["ref"])))
            chosen = group[-1]
            observation = chosen["payload"]
            result = verifier.verify(observation, observation_ref=chosen["ref"])
            ranked = [item for item in group if item["payload"]["revision"] == observation["revision"]]
            if len({record_digest({key: item["payload"][key] for key in
                                   ("quantity", "units", "as_of", "event", "correction")}) for item in ranked}) > 1:
                result = EvidenceResult(False, ("conflicting-committed-observation-frontier",))
            outputs.append(ObservationInput(chosen["ref"], observation, result,
                                            ref_key(chosen["ref"]) not in ignored_corrections))
        return sorted(outputs, key=lambda item: ref_key(item.ref)), _refs(corrections)

    @staticmethod
    def _metrics(inputs: list[CaptureInput], plan: dict) -> tuple[dict, dict]:
        primary = [item for item in inputs if item.capture["role"] == "primary"]
        metrics = {
            "post_count": len(primary),
            "unique_authors": len({item.capture["author"]["id"] for item in primary
                                   if item.capture["author"]["id"] is not None}),
            "event_type_counts": dict.fromkeys(EVENT_TYPES, 0),
            "sentiment_counts": dict.fromkeys(SENTIMENTS, 0),
            "sentiment_by_event_type": {kind: dict.fromkeys(SENTIMENTS, 0) for kind in EVENT_TYPES},
            "leads": [], "flows": [], "narratives": [],
            "target_counts": dict.fromkeys(("matched", "unmatched", "unknown"), 0),
            "unique_original_authors": len({item.capture["author"]["id"] for item in primary
                                            if item.capture["event_type"] == "original"
                                            and item.capture["author"]["id"] is not None}),
            "unknown_authors": sum(item.capture["author"]["id"] is None for item in primary),
            "duplicate_occurrences": sum(item.duplicate_count for item in inputs),
            "unknown_event_time": sum(item.capture["event_time"] is None for item in inputs),
            "unknown_roles": sum(item.capture["role"] == "unknown" for item in inputs),
            "source_gap_count": 0, "source_error_count": 0, "stale_annotations": 0,
            "annotation_status_counts": {status: 0 for status in STATUSES},
        }
        denominators = dict.fromkeys(("total", "covered", "unknown", "errors", "abstained",
                                      "insufficient_context", "unavailable", "deferred"), 0)
        denominators["total"] = len(primary)
        narratives: dict[str, list[dict]] = defaultdict(list)
        permitted = (set(plan["profile"]["criteria"]["labels"])
                     if plan["profile"]["id"] == "generic-sentiment" else set(SENTIMENTS) - {"unknown"})
        for item in primary:
            kind = item.capture["event_type"]
            metrics["event_type_counts"][kind] += 1
            guarded = item.guarded or {}
            relevance = guarded.get("relevance")
            if relevance in {"irrelevant", "not-relevant", "unrelated"}:
                target_state = "unmatched"
            elif relevance in {"relevant", "related", "target", "on-topic"} or re.search(r"(?<!\w)" + re.escape(plan["profile"]["target"].casefold()) + r"(?!\w)",
                           item.capture["text"].casefold()):
                target_state = "matched"
            else:
                target_state = "unknown"
            metrics["target_counts"][target_state] += 1
            label = guarded.get("sentiment")
            if item.status != "available" or target_state != "matched" or label not in permitted:
                label = "unknown"
            metrics["sentiment_counts"][label] += 1
            metrics["sentiment_by_event_type"][kind][label] += 1
            metrics["annotation_status_counts"][item.status] += 1
            if label != "unknown":
                denominators["covered"] += 1
            if item.status == "failed":
                denominators["errors"] += 1
            elif item.status == "abstained":
                denominators["abstained"] += 1
            elif item.status == "insufficient-context":
                denominators["insufficient_context"] += 1
            elif item.status == "unavailable":
                denominators["unavailable"] += 1
            elif item.status == "deferred":
                denominators["deferred"] += 1
            if guarded.get("narrative") and item.annotation_ref:
                narratives[guarded["narrative"]].append(item.annotation_ref)
        denominators["unknown"] = denominators["total"] - denominators["covered"]
        metrics["narratives"] = [{"label": label, "count": len(refs), "annotation_refs": _refs(refs)}
                                  for label, refs in sorted(narratives.items())]
        return metrics, denominators

    @staticmethod
    def _latest(items: list[ObservationInput], metric: str) -> tuple[ObservationInput | None, list[str]]:
        candidates = [item for item in items if item.effective and item.observation["metric"] == metric]
        if not candidates:
            return None, [f"missing-{metric}"]
        # A newer unavailable/incoherent measurement blocks fallback to an older
        # favorable snapshot. Acquisition/callback order never ranks a fact.
        latest = max(instant(item.observation["as_of"] or item.observation["observed_at"])
                     for item in candidates)
        chosen = [item for item in candidates
                  if instant(item.observation["as_of"] or item.observation["observed_at"]) == latest]
        if len({record_digest({"quantity": item.observation["quantity"],
                               "units": item.observation["units"],
                               "scope": item.observation["measurement_scope"],
                               "cap_kind": item.observation["cap_kind"]}) for item in chosen}) > 1:
            return None, [f"ambiguous-latest-{metric}-snapshot"]
        chosen.sort(key=lambda item: ref_key(item.ref))
        return chosen[0], list(chosen[0].result.reasons) if not chosen[0].result.known else []

    @staticmethod
    def _coherent(items: list[ObservationInput], criteria: dict) -> list[str]:
        if not items:
            return ["missing-snapshot-constituents"]
        reasons = []
        for item in items:
            coherence = item.observation["coherence"]
            if (coherence["rule_id"] != COHERENCE_RULE["id"]
                    or coherence["revision"] != COHERENCE_RULE["revision"]):
                reasons.append("unsupported-snapshot-coherence-rule")
            if not item.result.facts or not item.result.facts.get("as_of_known", False):
                reasons.append("unknown-measurement-as-of")
        if reasons:
            return sorted(set(reasons))
        clocks = [instant(item.result.facts["as_of"]) for item in items]
        allowed_skew = min([criteria["max_skew_s"], *[
            item.observation["coherence"]["max_skew_s"] for item in items
        ]])
        if (max(clocks) - min(clocks)).total_seconds() > allowed_skew:
            reasons.append("incoherent-common-as-of")
        if any(item.observation["coherence"]["require_same_block"] for item in items):
            blocks = {item.result.facts.get("block_hash") for item in items}
            if None in blocks or len(blocks) != 1:
                reasons.append("incoherent-common-block")
        pools = [item for item in items if item.observation["metric"] in {"price", "liquidity", "orderbook-depth"}]
        if len(pools) > 1:
            scopes = [item.observation["measurement_scope"] for item in pools]
            if len({scope["aggregation"] for scope in scopes}) == 1:
                if len({scope["scope_id"] for scope in scopes}) != 1:
                    reasons.append("incompatible-measurement-scope")
                if len({record_digest(scope["pool_refs"]) for scope in scopes}) != 1:
                    reasons.append("incompatible-constituent-pool-references")
            else:
                aggregate = next((item for item in pools
                                  if item.observation["measurement_scope"]["aggregation"] == "aggregate"), None)
                if not aggregate or not aggregate.observation["measurement_scope"]["constituent_refs"]:
                    reasons.append("incompatible-aggregation-scope")
                else:
                    price_pools = {item.result.facts.get("pool_address") for item in pools
                                   if item.observation["metric"] == "price"}
                    if not price_pools.issubset(set(aggregate.result.facts.get("pool_addresses", []))):
                        reasons.append("price-pool-not-in-aggregate-constituents")
        return sorted(set(reasons))

    def _token_criteria(self, entity: dict, observations: list[ObservationInput],
                        criteria: dict, evaluation: datetime) -> tuple[str, list[str], dict | None, list[dict]]:
        if criteria["verification_rule"] != CRYPTO_RULE:
            return "needs-verification", ["unsupported-token-verification-policy"], None, []
        chain, contract = entity["chain_id"], entity["contract_address"]
        if not chain or not contract:
            return "needs-verification", ["ambiguous-chain-contract-identity"], None, []
        if chain not in criteria["chain_ids"]:
            return "needs-verification", ["chain-outside-declared-criteria"], None, []
        relevant = [item for item in observations
                    if item.observation["entity"]["chain_id"] == chain
                    and (item.observation["entity"]["contract_address"] == contract
                         or (item.result.facts and item.result.facts.get("target_contract") == contract))]
        reasons = []
        selected = []
        deployment, errors = self._latest(relevant, "deployment")
        reasons.extend(errors)
        if deployment:
            selected.append(deployment)
        supply_kind = "total-supply" if criteria["cap"]["kind"] == "fdv" else "circulating-supply"
        supply, errors = self._latest(relevant, supply_kind)
        reasons.extend(errors)
        if supply:
            selected.append(supply)
        price, errors = self._latest(relevant, "price")
        reasons.extend(errors)
        if price:
            selected.append(price)
        liquidity_kind = "orderbook-depth" if criteria["liquidity"]["measure"] == "orderbook-depth" else "liquidity"
        liquidity, errors = self._latest(relevant, liquidity_kind)
        reasons.extend(errors)
        if liquidity:
            selected.append(liquidity)
        creation = None
        if criteria["age"]["basis"] == "pool-creation":
            creation, errors = self._latest(relevant, "pool-creation")
            reasons.extend(errors)
            if creation:
                selected.append(creation)
        refs = _refs([item.ref for item in selected])
        for item in selected:
            as_of = item.observation["as_of"]
            if not as_of:
                reasons.append("unknown-measurement-freshness")
            elif not 0 <= (evaluation - instant(as_of)).total_seconds() <= criteria["max_age_s"]:
                reasons.append("stale-or-future-measurement")
        if reasons:
            return "needs-verification", sorted(set(reasons)), None, refs
        reasons.extend(self._coherent(selected, criteria))
        assert deployment and supply and price and liquidity
        supply_facts, price_facts, liquidity_facts = supply.result.facts, price.result.facts, liquidity.result.facts
        if price_facts.get("currency") != criteria["cap"]["currency"]:
            reasons.append("cap-currency-or-decimal-unit-mismatch")
        if (liquidity_facts.get("liquidity_measure") != criteria["liquidity"]["measure"]
                or liquidity_facts.get("units") != criteria["liquidity"]["units"]):
            reasons.append("liquidity-measure-or-unit-mismatch")
        if criteria["cap"]["kind"] == "circulating-market-cap" and (
            criteria["cap"].get("supply_basis") != "declared-totalSupply-minus-excluded-balances-v1"
            or supply_facts.get("basis") != criteria["cap"].get("supply_basis")
        ):
            reasons.append("circulating-supply-methodology-not-explicitly-compatible")
        if reasons:
            return "needs-verification", sorted(set(reasons)), None, refs
        ratio = price_facts.get("price_ratio")
        price_exact = (Fraction(decimal(ratio["numerator"])) / Fraction(decimal(ratio["denominator"]))
                       if ratio else Fraction(decimal(price_facts["quantity"], nonnegative=True)))
        cap_exact = price_exact * Fraction(decimal(supply_facts["quantity"], nonnegative=True))
        with localcontext() as context:
            context.prec = 600
            cap = Decimal(cap_exact.numerator) / Decimal(cap_exact.denominator)
        liquidity_value = decimal(liquidity_facts["quantity"], nonnegative=True)
        birth = (creation.result.facts.get("created_at") if creation else
                 deployment.result.facts.get("deployed_at"))
        if not birth:
            return "needs-verification", ["missing-verified-age-basis"], None, refs
        age = (evaluation - instant(birth)).total_seconds()
        if age < 0:
            return "needs-verification", ["future-age-basis"], None, refs
        failures = []
        for bound, comparison in (("minimum", lambda value, threshold: value < threshold),
                                  ("maximum", lambda value, threshold: value > threshold)):
            threshold = criteria["cap"][bound]
            if threshold is not None and comparison(cap_exact, Fraction(decimal(threshold, nonnegative=True))):
                failures.append(f"cap-{bound}-not-satisfied")
        if liquidity_value < decimal(criteria["liquidity"]["minimum"], nonnegative=True):
            failures.append("liquidity-minimum-not-satisfied")
        if not criteria["age"]["minimum_s"] <= age <= criteria["age"]["maximum_s"]:
            failures.append("age-range-not-satisfied")
        common_as_of = min(instant(item.result.facts["as_of"]) for item in selected)
        blocks = {item.result.facts.get("block_hash") for item in selected}
        facts = {
            "cap": {"quantity": decimal_text(cap), "kind": criteria["cap"]["kind"],
                    "currency": criteria["cap"]["currency"],
                    "basis": ("independent-" + price_facts["basis"] + "-times-" + supply_facts["basis"] + "-v1"),
                    "as_of": price.observation["as_of"], "observation_refs": _refs([price.ref, supply.ref])},
            "liquidity": {"quantity": decimal_text(liquidity_value), "measure": criteria["liquidity"]["measure"],
                          "units": liquidity.observation["units"], "basis": liquidity_facts["basis"],
                          "as_of": liquidity.observation["as_of"], "observation_refs": [liquidity.ref]},
            "age": {"seconds": int(age), "basis": criteria["age"]["basis"],
                    "as_of": timestamp(evaluation), "observation_refs": [creation.ref if creation else deployment.ref]},
            "snapshot": {"rule_id": COHERENCE_RULE["id"], "revision": COHERENCE_RULE["revision"],
                         "common_as_of": timestamp(common_as_of),
                         "block_hash": next(iter(blocks)) if len(blocks) == 1 else None,
                         "max_skew_s": criteria["max_skew_s"],
                         "measurement_scope": liquidity.observation["measurement_scope"]},
        }
        return ("does-not-match" if failures else "matches-criteria"), failures, facts, refs

    def _leads(self, inputs: list[CaptureInput], observations: list[ObservationInput],
               plan: dict, evaluation: datetime, committed_captures: dict[str, dict]) -> list[dict]:
        from hyperresearch.core.x_classifier import extract_candidates

        groups: dict[str, dict] = {}
        criteria = plan["profile"]["criteria"]
        deployments = [item for item in observations if item.result.known
                       and item.observation["metric"] == "deployment"]
        for item in inputs:
            if item.capture["role"] != "primary":
                continue
            sources = [(item.ref, item.capture)]
            for relationship in item.capture["relationships"]:
                context = committed_captures.get(relationship["target_post_id"])
                if relationship["delivery"] == "delivered" and context is not None:
                    sources.append((context["ref"], context["payload"]))
            attributed = {ref_key(ref): capture for ref, capture in sources}
            spans, candidates = extract_candidates(sources)
            for candidate in candidates:
                if candidate["kind"] not in {"address", "symbol", "chain-contract"}:
                    continue
                span = spans[candidate["source_span_indexes"][0]]
                contract = candidate["address"]
                source = attributed[ref_key(span["capture_ref"])]
                chains = chains_for_span(source["text"], span["start"], span["end"]) if contract else []
                chain = chains[0] if len(chains) == 1 else None
                if contract and not chains:
                    resolved = {observation.observation["entity"]["chain_id"] for observation in deployments
                                if observation.observation["entity"]["contract_address"] == contract.lower()
                                and observation.observation["entity"]["chain_id"] in criteria["chain_ids"]}
                    chain = next(iter(resolved)) if len(resolved) == 1 else None
                entity = _entity(chain, contract, symbol=candidate["symbol"])
                identity = entity["entity_id"]
                if identity not in groups:
                    groups[identity] = {"entity": entity, "capture_refs": [], "annotation_refs": [],
                                        "source_spans": [], "ambiguous_claim": len(chains) > 1,
                                        "ambiguous_source": False}
                group = groups[identity]
                group["capture_refs"].append(item.ref)
                group["capture_refs"].append(span["capture_ref"])
                if item.occurrence_ref:
                    group["capture_refs"].append(item.occurrence_ref)
                group["ambiguous_source"] |= "conflicting-committed-capture-revision" in item.reasons
                if item.annotation_ref:
                    group["annotation_refs"].append(item.annotation_ref)
                group["source_spans"].append(span)
        outputs = []
        for _identity, group in sorted(groups.items()):
            disposition, reasons, facts, refs = self._token_criteria(
                group["entity"], observations, criteria, evaluation
            )
            if group["ambiguous_claim"]:
                disposition, facts = "needs-verification", None
                reasons.append("ambiguous-source-chain-claim")
            if group["ambiguous_source"]:
                disposition, facts = "needs-verification", None
                reasons.append("conflicting-committed-capture-revision")
            outputs.append({
                "entity": group["entity"], "disposition": disposition, "reasons": sorted(set(reasons)),
                "capture_refs": _refs(group["capture_refs"]), "annotation_refs": _refs(group["annotation_refs"]),
                "observation_refs": refs, "source_spans": group["source_spans"], "facts": facts,
            })
        return outputs

    def _flows(self, observations: list[ObservationInput], plan: dict, evaluation: datetime,
               start: datetime, end: datetime) -> list[dict]:
        criteria = plan["profile"]["criteria"]
        if criteria["verification_rule"] != FLOW_RULE:
            return [{"entity": {"namespace": "entity", "entity_id": "unknown-flow",
                                "chain_id": None, "contract_address": None, "pool_address": None, "venue": None},
                     "quantity": None, "units": criteria["units"], "observation_refs": [],
                     "actor_state": "unknown", "reasons": ["unsupported-flow-verification-policy"],
                     "kind": "swap-net", "measurement_scope": {
                         "scope_id": criteria["measurement_scope"], "aggregation": "aggregate",
                         "chain_id": None, "pool_refs": [], "venue": None, "constituent_refs": [],
                     }}]
        associations = {ref_key(item.ref): item for item in observations
                        if item.effective and item.observation["metric"] == "actor-association" and item.result.known}
        groups: dict[tuple, dict] = {}
        snapshots: dict[tuple, list[tuple]] = defaultdict(list)
        for item in observations:
            if not item.effective:
                continue
            observation, result = item.observation, item.result
            metric = observation["metric"]
            if metric not in {"swap", "liquidity-add", "liquidity-remove", "reserves",
                              "orderbook-depth", "orderbook-change"}:
                # Especially transfers: a transfer never establishes a buy/sell or maker.
                continue
            as_of = observation["as_of"]
            if not as_of or instant(as_of) >= end:
                continue
            event = observation["event"]
            reasons = list(result.reasons)
            if observation["measurement_scope"]["scope_id"] != criteria["measurement_scope"]:
                reasons.append("flow-measurement-scope-mismatch")
            if not 0 <= (evaluation - instant(as_of)).total_seconds() <= criteria["max_age_s"]:
                reasons.append("stale-or-future-flow-observation")
            coherence = observation["coherence"]
            if coherence["rule_id"] != COHERENCE_RULE["id"] or coherence["revision"] != COHERENCE_RULE["revision"]:
                reasons.append("unsupported-flow-coherence-rule")
            actor_state = "unknown"
            if event:
                addresses = {event["sender"], event["recipient"]} - {None}
                attributed = [associations.get(ref_key(ref))
                              for ref in observation["association"]["attribution_refs"]]
                actor_facts = [candidate.result.facts for candidate in attributed if candidate
                               and candidate.result.facts.get("wallet") in addresses
                               and candidate.result.facts.get("chain_id") == event["chain_id"]
                               and instant(candidate.result.facts["valid_from"]) <= instant(as_of)
                               <= instant(candidate.result.facts["valid_to"])]
                if (actor_facts and len({fact["actor_id"] for fact in actor_facts}) == 1
                        and (event["actor_id"] is None or event["actor_id"] == actor_facts[0]["actor_id"])):
                    actor_state = "verified"
                elif event["actor_id"] or observation["association"]["assertion"] == "present":
                    reasons.append("social-maker-label-is-not-verified-association")
            if criteria["require_actor_attribution"] and actor_state != "verified":
                reasons.append("actor-association-needs-independent-verification")
            if metric in {"orderbook-depth", "orderbook-change"}:
                key = ("depth-change", observation["entity"]["entity_id"], observation["units"])
                if observation["units"] != criteria["units"]:
                    reasons.append("flow-unit-mismatch")
                sequence = event["venue_sequence"] if event else None
                if sequence is None or not re.fullmatch(r"(?:0|[1-9][0-9]*)", sequence):
                    reasons.append("venue-sequence-order-unknown")
                    order = -1
                else:
                    order = int(sequence)
                snapshots[key].append((order, instant(as_of), item, observation["quantity"], reasons, actor_state))
                continue
            if not event:
                continue
            if not event["transaction_hash"] or event["block_hash"] is None or event["log_index"] is None:
                reasons.append("decoded-chain-event-identity-missing")
            if not any(f"token:{event['chain_id']}:{leg['contract_address']}" == criteria["units"]
                       for leg in event["legs"]) and instant(as_of) >= start:
                key = ("swap-net" if metric == "swap" else "liquidity-net",
                       observation["entity"]["entity_id"], criteria["units"])
                groups[key] = {
                    "entity": observation["entity"], "quantity": None, "units": criteria["units"],
                    "observation_refs": [item.ref], "actor_states": [actor_state],
                    "reasons": [*reasons, "flow-unit-mismatch"], "known": False, "kind": key[0],
                    "scope": observation["measurement_scope"], "blocks": {},
                }
            for leg in event["legs"]:
                chain, contract = event["chain_id"], leg["contract_address"]
                units = f"token:{chain}:{contract}"
                if units != criteria["units"]:
                    # Never convert between a token, fiat, wei, or another chain by label.
                    continue
                entity = _entity(chain, contract)
                entity["pool_address"] = observation["entity"]["pool_address"]
                entity["venue"] = observation["entity"]["venue"]
                kind = ("swap-net" if metric == "swap" else
                        "reserve-change" if metric == "reserves" else "liquidity-net")
                key = (kind, entity["entity_id"], units)
                if metric == "reserves":
                    order = (event["block_number"], event["log_index"], event["block_hash"])
                    snapshots[key].append((order, instant(as_of), item, leg["amount_in"], reasons, actor_state))
                    continue
                if instant(as_of) < start:
                    continue
                if key not in groups:
                    groups[key] = {"entity": entity, "quantity": Decimal(0), "units": units,
                                   "observation_refs": [], "actor_states": [], "reasons": [],
                                   "known": True, "kind": kind,
                                   "scope": observation["measurement_scope"], "blocks": {}}
                group = groups[key]
                group["observation_refs"].append(item.ref)
                group["actor_states"].append(actor_state)
                group["reasons"].extend(reasons)
                if group["scope"] != observation["measurement_scope"]:
                    group["known"] = False
                    group["reasons"].append("incompatible-flow-aggregation-scope")
                height, digest = event["block_number"], event["block_hash"]
                if height in group["blocks"] and group["blocks"][height] != digest:
                    group["known"] = False
                    group["reasons"].append("incoherent-chain-branches")
                group["blocks"][height] = digest
                group["known"] = (group["known"] and result.known
                                  and not any(reason in reasons for reason in
                                              ("flow-measurement-scope-mismatch", "stale-or-future-flow-observation",
                                               "decoded-chain-event-identity-missing", "unsupported-flow-coherence-rule")))
                with localcontext() as context:
                    context.prec = 600
                    incoming = decimal(leg["amount_in"], nonnegative=True)
                    outgoing = decimal(leg["amount_out"], nonnegative=True)
                    group["quantity"] += outgoing - incoming if kind == "swap-net" else incoming - outgoing
        for key, values in snapshots.items():
            in_window = [value for value in values if start <= value[1] < end]
            if not in_window:
                continue
            ordered = sorted(values, key=lambda value: (value[0], value[1], ref_key(value[2].ref)))
            before = [value for value in ordered if value[1] <= start]
            first = before[-1] if before else min(in_window, key=lambda value: (value[0], value[1]))
            last = ordered[-1]
            used = [value for value in ordered if first[0] <= value[0] <= last[0]]
            reasons = [reason for value in used for reason in value[4]]
            if (last[1] - first[1]).total_seconds() > criteria["max_skew_s"]:
                reasons.append("incoherent-flow-snapshot-skew")
            if not before:
                reasons.append("no-window-boundary-base-snapshot")
            if any(value[1] > evaluation for value in used):
                reasons.append("future-snapshot")
            known = (len(used) >= 2 and all(value[2].result.known for value in used)
                     and not any(reason in reasons for reason in
                                 ("flow-measurement-scope-mismatch", "stale-or-future-flow-observation",
                                  "venue-sequence-order-unknown", "flow-unit-mismatch", "future-snapshot")))
            if len({value[0] for value in used}) != len(used):
                known = False
                reasons.append("conflicting-venue-or-chain-sequence")
            with localcontext() as context:
                context.prec = 600
                quantity = (decimal(last[3], nonnegative=True) - decimal(first[3], nonnegative=True)
                            if known else None)
            entity = first[2].observation["entity"].copy()
            if key[0] == "reserve-change":
                entity = _entity(first[2].observation["entity"]["chain_id"], key[1].split(":")[-1])
                entity["pool_address"] = first[2].observation["entity"]["pool_address"]
            groups[key] = {"entity": entity, "quantity": quantity, "units": key[2],
                           "observation_refs": [value[2].ref for value in used],
                           "actor_states": [value[5] for value in used],
                           "reasons": reasons, "known": known and "incoherent-flow-snapshot-skew" not in reasons,
                           "kind": key[0], "scope": first[2].observation["measurement_scope"]}
        outputs = []
        for _key, group in sorted(groups.items()):
            quantity = decimal_text(group["quantity"]) if group["known"] else None
            reasons = group["reasons"]
            threshold = criteria["minimum_net_flow"]
            if quantity is not None and threshold is not None and decimal(quantity) < decimal(threshold):
                reasons.append("minimum-net-flow-not-satisfied")
            outputs.append({
                "entity": group["entity"], "quantity": quantity, "units": group["units"],
                "observation_refs": _refs(group["observation_refs"]),
                "actor_state": "verified" if all(state == "verified" for state in group["actor_states"]) else "unknown",
                "reasons": sorted(set(reasons)), "kind": group["kind"],
                "measurement_scope": {**group["scope"], "constituent_refs": _refs(group["observation_refs"])},
            })
        return outputs

    @staticmethod
    def _coverage(plan: dict, session: dict, receipts: list[dict], start: datetime,
                  end: datetime) -> tuple[dict, int, int]:
        reasons = []
        receipt_refs = []
        relevant_receipts = []
        for item in receipts:
            receipt = item["payload"]
            scope_plan = receipt["scope"]["plan_ref"]
            if scope_plan and (scope_plan["plan_id"] != plan["plan_id"]
                               or scope_plan["revision"] != plan["revision"]
                               or scope_plan["digest"] != plan["digest"]):
                continue
            relevant_receipts.append(item)
            receipt_refs.append(item["ref"])
        complete_queries = 0
        for query in plan["queries"]:
            intervals = []
            for item in relevant_receipts:
                receipt = item["payload"]
                query_ref = receipt["scope"]["query_ref"]
                coverage = receipt["coverage"]
                if query_ref != {"query_id": query["id"], "revision": query["revision"]}:
                    continue
                if (receipt["kind"] == "final-outcome" and coverage["state"] == "complete"
                        and coverage["boundary_proven"] and coverage["interval_start"] and coverage["interval_end"]):
                    intervals.append((instant(coverage["interval_start"]), instant(coverage["interval_end"])))
            frontier = start
            for left, right in sorted(intervals):
                if left > frontier:
                    break
                frontier = max(frontier, right)
            complete_queries += frontier >= end
        gaps = [gap for gap in session["coverage_gaps"]
                if (gap["start"] is None or instant(gap["start"]) < end)
                and (gap["end"] is None or instant(gap["end"]) > start)]
        error_count = sum(bool(item["payload"]["errors"]) for item in relevant_receipts)
        error_count += sum(gap["state"] == "error" for gap in gaps)
        if complete_queries != len(plan["queries"]):
            reasons.append("source-query-interval-coverage-not-demonstrated")
        reasons.extend(reason for gap in gaps for reason in gap["reasons"])
        if gaps:
            reasons.append("committed-source-coverage-gaps")
        state = ("complete" if complete_queries == len(plan["queries"]) and not gaps
                 else "partial" if relevant_receipts else "unknown")
        return {"state": state, "receipt_refs": _refs(receipt_refs),
                "reasons": sorted(set(reasons))}, len(gaps), error_count

    @staticmethod
    def _freshness(observations: list[ObservationInput], evaluation: datetime,
                   max_age_s: int) -> dict:
        known = [item.observation["as_of"] for item in observations if item.observation["as_of"]]
        state = "unknown"
        if known and len(known) == len(observations):
            state = ("fresh" if all(0 <= (evaluation - instant(value)).total_seconds() <= max_age_s
                                    for value in known) else "stale")
        return {"state": state, "max_age_s": max_age_s,
                "oldest_as_of": min(known, key=instant) if known else None}

    @staticmethod
    def _semantic(event: dict) -> str:
        return record_digest({key: value for key, value in event.items()
                              if key not in {"revision", "supersedes"}})

    def _publish(self, event: dict, prior_outputs: list[dict]) -> dict:
        prior = [item for item in prior_outputs if item["payload"]["logical_id"] == event["logical_id"]]
        prior.sort(key=lambda item: (item["payload"]["revision"], ref_key(item["ref"])))
        if prior:
            previous = prior[-1]
            old = previous["payload"]
            old_matches = {lead["entity"]["entity_id"] for lead in old["metrics"]["leads"]
                           if lead["disposition"] == "matches-criteria"}
            new_matches = {lead["entity"]["entity_id"] for lead in event["metrics"]["leads"]
                           if lead["disposition"] == "matches-criteria"}
            removed_leads = old_matches - new_matches
            current_captures = {lead["entity"]["entity_id"]: {ref_key(ref) for ref in lead["capture_refs"]}
                                for lead in event["metrics"]["leads"]}
            removed_captures = [ref for lead in old["metrics"]["leads"]
                                if lead["entity"]["entity_id"] in removed_leads
                                for ref in lead["capture_refs"]
                                if ref_key(ref) not in current_captures.get(lead["entity"]["entity_id"], ())]
            removed = set()
            new_observations = {ref_key(ref) for ref in event["input_refs"]["observation_refs"]}
            for ref in old["input_refs"]["observation_refs"]:
                if ref_key(ref) not in new_observations:
                    removed.add(ref_key(ref))
            if old_matches - new_matches or removed or (old["retraction"] and not new_matches):
                event["retracted_inputs"] = _refs(
                    old["retracted_inputs"]
                    + [ref for ref in old["input_refs"]["observation_refs"] if ref_key(ref) in removed]
                    + ([ref for lead in old["metrics"]["leads"] for ref in lead["observation_refs"]]
                       if old_matches - new_matches else [])
                    + removed_captures
                )
                invalidations = [self.store.get_record(ref, "verified-observation")
                                 for ref in event["frontiers"]["corrections"]]
                reorg_targets = {ref_key(ref) for correction in invalidations
                                 if correction["correction"]["state"] in {"reorg", "retracted"}
                                 for ref in correction["correction"]["retracts"]}
                retract_lead = bool(old_matches - new_matches or (old["retraction"] and not new_matches))
                retract_flow = bool(removed & reorg_targets)
                if event["retracted_inputs"] and (retract_lead or retract_flow):
                    event["retraction"] = True
                    event["disposition"] = "retracted"
                    event["reasons"] = sorted(set(event["reasons"] + ["previous-evidence-contribution-retracted"]))
            if self._semantic(old) == self._semantic(event):
                return previous["ref"]
            event["revision"] = old["revision"] + 1
            event["supersedes"] = previous["ref"]
        return self.store.put_record("analytics-event", validate_record("analytics-event", event))

    def reduce(self, plan: dict, session: dict, *, window_s: int,
               evaluation_time: str | datetime, policy: dict | None = None) -> list[dict]:
        """Reduce committed source/analysis/observation/correction frontiers locally.

        Missing market bindings, trust, or annotations produce honest unknowns.
        Missing/corrupt canonical artifacts fail closed instead of silently
        dropping an evidence denominator. No global input scan or callback order.
        """
        from hyperresearch.core.x_classifier import default_policy

        plan = validate_record("monitor-plan", plan)
        plan_digest(plan)
        session = validate_record("monitor-session", session)
        if any(session["plan_ref"].get(key) != value for key, value in
               (("plan_id", plan["plan_id"]), ("revision", plan["revision"]), ("digest", plan["digest"]))):
            raise ValueError("Session is bound to a different plan lineage")
        if isinstance(window_s, bool) or window_s not in plan["schedule"]["windows_s"]:
            raise ValueError("Window size is outside the governed plan")
        evaluation = instant(evaluation_time)
        policy = validate_record("analysis-policy", policy) if policy is not None else default_policy(plan)
        # Supporting evidence cannot silently expand the committed source
        # frontier or resurrect an obsolete focal through a late callback.
        source_records = self.store.resolve_closure(_refs(session["source_frontier"]))
        analysis_records = self.store.resolve_closure(_refs(session["analysis_frontier"]))
        observation_records = self.store.resolve_closure(_refs(session.get("observation_frontier", [])))
        records = ([item for item in source_records if item["kind"] in {"source-capture", "source-receipt"}]
                   + [item for item in analysis_records if item["kind"] == "analysis-annotation"]
                   + [item for item in observation_records if item["kind"] == "verified-observation"])
        # Prior outputs are used for lineage only, never to extend the effective input frontier.
        prior_outputs = [item for item in self.store.resolve_closure(session["output_refs"])
                         if item["kind"] == "analytics-event"] if session["output_refs"] else []
        snapshot_ref = session.get("authority_snapshot_ref")
        snapshot = (validate_record("authority-snapshot", json.loads(self.store.read_blob(snapshot_ref)))
                    if snapshot_ref else None)
        if snapshot and (
                not self.trusted_keys or snapshot["trust_store_digest"] != self.trusted_digest
                or any(self.trusted_keys.get(key) != value for key, value in snapshot["trusted_keys"].items())):
            snapshot = None
        inputs, context_refs, committed_captures = self._capture_inputs(plan, records, evaluation, policy)
        observations, corrections = self._observation_inputs(plan, records, evaluation, snapshot)
        receipts = [item for item in records if item["kind"] == "source-receipt"]
        current_start = _bucket(evaluation, window_s)
        starts = {current_start}
        for item in inputs:
            event_time = item.capture["event_time"]
            if event_time and instant(event_time) <= evaluation:
                starts.add(_bucket(instant(event_time), window_s))
        for item in observations:
            as_of = item.observation["as_of"]
            if as_of and instant(as_of) <= evaluation:
                starts.add(_bucket(instant(as_of), window_s))
        lineage = {
            "monitor_id": session["monitor_id"], "plan_id": plan["plan_id"], "plan_revision": plan["revision"],
            "profile": plan["profile"], "policy_digest": record_digest(policy), "window_s": window_s,
        }
        for prior in prior_outputs:
            event = prior["payload"]
            if (event["monitor_id"] == session["monitor_id"] and event["profile"] == plan["profile"]
                    and event["plan_ref"]["digest"] == plan["digest"] and event["window"]["size_s"] == window_s
                    and event.get("policy") == policy):
                starts.add(instant(event["window"]["start"]))
        outputs = []
        for start in sorted(starts):
            end = start + timedelta(seconds=window_s)
            window_inputs = [item for item in inputs
                             if (item.capture["event_time"] and start <= instant(item.capture["event_time"]) < end
                             and instant(item.capture["event_time"]) <= evaluation)
                             or (not item.capture["event_time"] and start == current_start)]
            metrics, denominators = self._metrics(window_inputs, plan)
            coverage, gap_count, source_errors = self._coverage(plan, session, receipts, start, end)
            metrics["source_gap_count"], metrics["source_error_count"] = gap_count, source_errors
            metrics["stale_annotations"] = sum(item.stale_annotations for item in window_inputs)
            selected_observations = [item for item in observations
                                     if item.observation["as_of"] and start <= instant(item.observation["as_of"]) < end]
            metrics["observation_status_counts"] = {
                "total": len(selected_observations),
                "verified": sum(item.result.known for item in selected_observations),
                "unknown": sum(not item.result.known for item in selected_observations),
                "retracted": sum(item.effective and item.observation["correction"]["state"] in {"retracted", "reorg"}
                                 for item in selected_observations),
            }
            reasons = []
            disposition = "observed"
            if plan["profile"]["id"] == "generic-sentiment":
                if denominators["covered"] < plan["profile"]["criteria"]["min_classified"]:
                    disposition = "insufficient-evidence"
                    reasons.append("minimum-classified-target-count-not-met")
            elif plan["profile"]["id"] == "crypto-discovery":
                metrics["leads"] = self._leads(window_inputs, observations, plan, evaluation, committed_captures)
                refs = {ref_key(ref) for lead in metrics["leads"] for ref in lead["observation_refs"]}
                selected_observations = [item for item in observations if ref_key(item.ref) in refs]
                if any(lead["disposition"] == "needs-verification" for lead in metrics["leads"]):
                    disposition = "needs-verification"
                elif metrics["leads"]:
                    disposition = ("matches-criteria" if any(lead["disposition"] == "matches-criteria"
                                                             for lead in metrics["leads"]) else "does-not-match")
                else:
                    disposition = "insufficient-evidence"
                    reasons.append("no-source-token-address-leads")
            else:
                metrics["flows"] = self._flows(observations, plan, evaluation, start, end)
                if not metrics["flows"]:
                    disposition = "needs-verification"
                    reasons.append("no-admitted-decoded-swap-liquidity-or-orderbook-evidence")
                elif any(flow["quantity"] is None or flow["reasons"] for flow in metrics["flows"]):
                    disposition = "needs-verification"
                refs = {ref_key(ref) for flow in metrics["flows"] for ref in flow["observation_refs"]}
                selected_observations = [item for item in observations if ref_key(item.ref) in refs]
                reasons.append("admitted-event-subset-not-complete-chain-or-venue-volume")
            event = {
                "schema_version": 1, "logical_id": "x-window-" + record_digest({**lineage, "start": timestamp(start)}),
                "revision": 1, "supersedes": None, "retraction": False, "retracted_inputs": [],
                "event_role": "window", "subject": None, "monitor_id": session["monitor_id"],
                "profile": plan["profile"], "plan_ref": session["plan_ref"],
                "input_refs": {
                    "capture_refs": _refs([item.ref for item in window_inputs]
                                          + [item.occurrence_ref for item in window_inputs if item.occurrence_ref]
                                          + context_refs),
                    "receipt_refs": _refs([item["ref"] for item in receipts]),
                    "annotation_refs": _refs([item.annotation_ref for item in window_inputs if item.annotation_ref]),
                    "observation_refs": _refs([item.ref for item in selected_observations]),
                },
                "frontiers": {"source": _refs(session["source_frontier"]),
                              "analysis": _refs(session["analysis_frontier"]),
                              "observations": _refs(session.get("observation_frontier", [])),
                              "corrections": corrections},
                "authority_snapshot_ref": snapshot_ref, "policy": policy,
                "evaluation_time": timestamp(evaluation),
                "window": {"start": timestamp(start), "end": timestamp(end), "size_s": window_s},
                "metrics": metrics, "denominators": denominators, "coverage": coverage,
                "freshness": self._freshness(selected_observations, evaluation,
                                              plan["profile"]["criteria"].get("max_age_s", plan["schedule"]["lookback_s"])),
                "provisional": (plan["profile"]["id"] == "market-flow" or coverage["state"] != "complete"
                                or evaluation < end + timedelta(seconds=plan["schedule"]["lateness_s"])),
                "disposition": disposition, "reasons": sorted(set(reasons)),
                "producer": {"product": "hyperresearch", "version": __version__, "runtime": "python",
                             "extension_version": None, "owner": None, "profile": None},
            }
            outputs.append(self._publish(event, prior_outputs))
            if plan["profile"]["id"] != "crypto-discovery":
                continue
            leads = {lead["entity"]["entity_id"]: lead for lead in metrics["leads"]}
            for prior in prior_outputs:
                old = prior["payload"]
                if (old.get("event_role") == "lead" and old["window"] == event["window"]
                        and old["profile"] == plan["profile"] and old.get("policy") == policy):
                    for old_lead in old["metrics"]["leads"]:
                        identity = old_lead["entity"]["entity_id"]
                        if identity not in leads:
                            leads[identity] = {
                                "entity": old_lead["entity"], "disposition": "needs-verification",
                                "reasons": ["source-lead-invalidated-at-committed-frontier"],
                                "capture_refs": [], "annotation_refs": [], "observation_refs": [],
                                "source_spans": [], "facts": None,
                            }
            for identity, lead in sorted(leads.items()):
                lead_event = {**event, "event_role": "lead", "subject": lead["entity"],
                              "logical_id": "x-lead-" + record_digest({**lineage, "start": timestamp(start), "entity": identity}),
                              "metrics": {**metrics, "leads": [lead], "flows": []},
                              "disposition": lead["disposition"], "reasons": lead["reasons"],
                              "retracted_inputs": [], "retraction": False}
                lead_event["input_refs"] = {
                    **event["input_refs"], "capture_refs": lead["capture_refs"],
                    "annotation_refs": lead["annotation_refs"], "observation_refs": lead["observation_refs"],
                }
                outputs.append(self._publish(lead_event, prior_outputs))
        return _refs(outputs)
