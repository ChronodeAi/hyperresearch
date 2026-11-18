"""Bounded X query compiler and proposal preparation, without execution authority."""
from __future__ import annotations

import copy
import re
from datetime import date

from hyperresearch.models.x_evidence import (
    canonical_bytes,
    plan_digest,
    record_digest,
    validate_record,
)

COMPILER_REVISION = "x-query-v1"
_TOKEN = re.compile(r'-?"(?:\\.|[^"\\])*"|[^\s()" :]+:"(?:\\.|[^"\\])*"|[()]|[^\s()"]+')
_HANDLE = re.compile(r"[A-Za-z0-9_]{1,15}")
_FILTERS = frozenset({"links", "media", "images", "videos", "native_video", "replies", "retweets", "verified", "safe"})


class QueryError(ValueError):
    pass


def compile_expression(expression: str) -> str:
    """Validate public native search grammar; do not broaden or add time operators.

    Values remain strings in the first-party API request, never script/shell source.
    Parentheses, exact phrases, exclusions, OR and a declared operator allowlist are
    supported. Unknown operators fail rather than silently changing query meaning.
    """
    if not isinstance(expression, str) or not expression.strip() or len(expression) > 4096:
        raise QueryError("X query must contain 1-4096 characters")
    if any(ord(char) < 32 or 127 <= ord(char) <= 159 or char in "\u202a\u202b\u202c\u202d\u202e\u2066\u2067\u2068\u2069" for char in expression):
        raise QueryError("X query contains control or bidi-override characters")
    text, tokens, cursor = expression.strip(), [], 0
    for match in _TOKEN.finditer(text):
        if text[cursor:match.start()].strip():
            raise QueryError("X query has an incomplete quote")
        tokens.append(match.group())
        cursor = match.end()
    if text[cursor:].strip() or not tokens or len(tokens) > 512:
        raise QueryError("X query has an incomplete quote or too many terms")
    depth, has_operand = 0, False
    for token in tokens:
        if token == "(":
            depth += 1
            if depth > 16:
                raise QueryError("X query nesting exceeds 16")
            has_operand = False
            continue
        if token == ")":
            if depth == 0 or not has_operand:
                raise QueryError("X query has an empty or unmatched group")
            depth -= 1
            has_operand = True
            continue
        if token == "OR":
            if not has_operand:
                raise QueryError("OR requires a preceding operand")
            has_operand = False
            continue
        if token in {"AND", "NOT"}:
            raise QueryError("Use implicit AND and '-' exclusions in native X queries")
        candidate = token.removeprefix("-")
        if not candidate:
            raise QueryError("An exclusion requires a term")
        if candidate.startswith('"'):
            if candidate == '""':
                raise QueryError("An exact phrase must not be empty")
            has_operand = True
            continue
        operator, separator, value = candidate.partition(":")
        if separator:
            if value.startswith('"') and value.endswith('"'):
                value = value[1:-1]
            if not value:
                raise QueryError("An advanced operator requires a value")
            if operator in {"from", "to"}:
                valid = _HANDLE.fullmatch(value.removeprefix("@")) is not None
            elif operator == "lang":
                valid = re.fullmatch(r"[A-Za-z]{2,3}(?:-[A-Za-z]{2,4})?", value) is not None
            elif operator in {"min_faves", "min_retweets", "min_replies"}:
                valid = value.isascii() and value.isdigit() and int(value) <= 1000000000
            elif operator in {"since", "until"}:
                try:
                    valid = date.fromisoformat(value).isoformat() == value
                except ValueError:
                    valid = False
            elif operator == "filter":
                valid = value in _FILTERS
            elif operator == "include":
                valid = value == "nativeretweets"
            elif operator == "url":
                valid = bool(value) and not value.lower().startswith(("javascript:", "data:", "file:"))
            else:
                raise QueryError(f"Unsupported native X operator: {operator}")
            if not valid:
                raise QueryError(f"Invalid value for native X operator: {operator}")
        has_operand = True
    if depth or not has_operand:
        raise QueryError("X query has an unmatched group or trailing OR")
    return text


def prepare_plan(payload: dict) -> dict:
    """Compile a proposed plan and stamp its content digest; this never grants it."""
    if not isinstance(payload, dict):
        raise QueryError("A monitor plan must be a JSON object")
    value = copy.deepcopy(payload)
    query_ids = set()
    for query in value.get("queries", []):
        if not isinstance(query, dict):
            raise QueryError("Each query must be a JSON object")
        query["expression"] = compile_expression(query.get("expression"))
        query["compiler_revision"] = COMPILER_REVISION
        if query.get("id") in query_ids:
            raise QueryError("Query identities must be unique within a plan")
        query_ids.add(query.get("id"))
    value.pop("digest", None)
    value["digest"] = record_digest(value)
    value = validate_record("monitor-plan", value)
    plan_digest(value)
    return validate_plan(value)


def validate_plan(payload: dict) -> dict:
    value = validate_record("monitor-plan", payload)
    plan_digest(value)
    ids = [query["id"] for query in value["queries"]]
    if len(ids) != len(set(ids)):
        raise QueryError("Query identities must be unique within a plan")
    for query in value["queries"]:
        if compile_expression(query["expression"]) != query["expression"]:
            raise QueryError("Monitor query must already be compiled; use hpr x plan first")
        if query.get("compiler_revision", COMPILER_REVISION) != COMPILER_REVISION:
            raise QueryError("Unsupported query compiler revision")
    poll, session = value["limits"]["poll"], value["limits"]["session"]
    if session["max_operations"] and (poll["max_requests"] > session["max_requests"] or poll["max_pages"] > session["max_pages"] or poll["max_captures"] > session["max_captures"]):
        raise QueryError("A polling scope cannot exceed the independent session ceilings")
    if poll.get("max_primary", poll["max_captures"]) > poll["max_captures"] or poll["max_context"] > poll["max_captures"]:
        raise QueryError("Primary/context ceilings cannot exceed total captures")
    if value["analysis"]["enabled"] and value["limits"]["analysis"]["max_workers"] > 4:
        raise QueryError("Jev classification supports at most four owned workers")
    if value["analysis"]["enabled"] and (value["limits"]["analysis"]["max_workers"] < 1 or value["limits"]["analysis"]["max_queue"] < 1):
        raise QueryError("Enabled analysis requires a bounded nonzero queue and at least one worker")
    # Ensure objects intended for exact digest binding have no nonfinite JSON values.
    canonical_bytes(value)
    return value


def parse_duration(value: str | int) -> int:
    if isinstance(value, int) and not isinstance(value, bool):
        seconds = value
    elif isinstance(value, str):
        match = re.fullmatch(r"([0-9]+)(s|m|h|d)?", value)
        if not match:
            raise ValueError("Duration must be whole seconds or a suffix s/m/h/d")
        seconds = int(match[1]) * {None: 1, "s": 1, "m": 60, "h": 3600, "d": 86400}[match[2]]
    else:
        raise ValueError("Invalid duration")
    if not 1 <= seconds <= 31536000:
        raise ValueError("Duration must be between one second and one year")
    return seconds
