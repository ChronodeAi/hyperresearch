"""Data-only X note projections; canonical evidence is never rewritten by rendering."""

from __future__ import annotations

import json
import re
import unicodedata
from urllib.parse import urlsplit

X_HOSTS = frozenset({"x.com", "www.x.com", "twitter.com", "www.twitter.com", "mobile.twitter.com", "mobile.x.com"})
REFERENCE_FIELDS = ("capture_refs", "receipt_refs", "annotation_refs", "observation_refs", "analytics_refs")


def is_x_url(url: str | None) -> bool:
    if not url:
        return False
    try:
        parsed = urlsplit(url)
        return parsed.scheme in {"http", "https"} and parsed.hostname in X_HOSTS
    except ValueError:
        return False


def unknown_evidence() -> dict:
    return {
        "schema_version": 1, **{key: [] for key in REFERENCE_FIELDS},
        "receipt_state": "unknown",
        "producer": {"product": "unknown", "version": None, "runtime": None,
                     "extension_version": None, "owner": None, "profile": None},
    }


def terminal_text(text: str) -> str:
    """Escape terminal controls and bidi instructions without changing stored bytes."""
    return "".join(
        f"\\u{ord(char):04x}" if unicodedata.category(char) in {"Cc", "Cf"} and char not in "\n\t" else char
        for char in text
    )


def inert_markdown(text: str) -> str:
    """Render literal text without markup, template, wiki-link or embed capabilities."""
    escaped = terminal_text(text)
    # Numeric entities cannot create Markdown delimiters and survive repeated transport.
    tokens = re.compile(r"&#(?:[0-9]+|x[0-9a-fA-F]+);|[&<>\[\]{}!*_`~#\\|\-]")
    return tokens.sub(lambda match: match[0] if match[0].startswith("&#") else f"&#{ord(match[0])};", escaped)


def note_evidence_projection(row) -> dict:
    """Decode a derived SQLite projection into the canonical reference shape."""
    from hyperresearch.models.x_evidence import validate_record

    result = {}
    keys = row.keys()
    if "x_evidence" in keys and row["x_evidence"]:
        result["x_evidence"] = validate_record("note-evidence-refs", json.loads(row["x_evidence"]))
    elif "source" in keys and is_x_url(row["source"]):
        result["x_evidence"] = unknown_evidence()
    for field in ("fetch_provider", "fetch_route", "source_domain", "fetched_at"):
        if field in keys and row[field] is not None:
            result[field] = row[field]
    return result


def note_refs(value: dict | None) -> list[dict]:
    return [ref for key in REFERENCE_FIELDS for ref in (value or {}).get(key, [])]
