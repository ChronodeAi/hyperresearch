"""Escalation queue — blocked fetches become browser-lane work, not losses.

Pre-4.0, a URL that hit a login wall, bot block, or junk gate was discarded;
at dissertation scale that's dozens of silently lost sources per run. Now the
fetch engine ENQUEUES the blocked URL here, and the `hyperresearch-
browser-fetcher` agent drains the queue by driving the user's real Chrome
browser (via Claude-in-Chrome) — one tab at a time, serial, precious.

The queue lives in the vault DB (`escalations` table) rather than a JSON
file: parallel fetcher waves enqueue concurrently, and SQLite gives atomic
claim semantics for free.

Lifecycle:  queued → in_progress → fetched | needs_human | abandoned
`needs_human` is the HARD scope boundary: CAPTCHAs, 2FA, and logins are
consolidated into one prompt for the human — never solved automatically.
"""

from __future__ import annotations

from datetime import UTC, datetime

REASONS = ("login_wall", "bot_block", "captcha", "fetch_failed", "interactive_needed", "scholar_search")
STATUSES = ("queued", "in_progress", "fetched", "needs_human", "abandoned")


class EscalationError(Exception):
    pass


def _now() -> str:
    return datetime.now(UTC).isoformat()


def enqueue(
    conn,
    url: str,
    reason: str,
    vault_tag: str | None = None,
    requested_by: str | None = None,
    suggested_by: str | None = None,
    utility_score: float | None = None,
    detail: str | None = None,
) -> int | None:
    """Add a blocked URL to the queue. Returns the row id, or None when the
    (url, vault_tag) pair is already queued (idempotent re-enqueue)."""
    if reason not in REASONS:
        raise EscalationError(f"invalid reason '{reason}' (one of {REASONS})")
    now = _now()
    cur = conn.execute(
        """INSERT OR IGNORE INTO escalations
           (url, reason, requested_by, suggested_by, utility_score, vault_tag,
            detail, created_at, updated_at)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
        (url, reason, requested_by, suggested_by, utility_score, vault_tag, detail, now, now),
    )
    conn.commit()
    return cur.lastrowid if cur.rowcount else None


def maybe_enqueue_blocked_fetch(
    vault,
    url: str,
    reason: str,
    vault_tag: str | None = None,
    suggested_by: str | None = None,
    utility_score: float | None = None,
    detail: str | None = None,
) -> int | None:
    """Fetch-gate hook: enqueue a blocked fetch if the chrome lane accepts it.

    Applies [chrome] policy: lane enabled, utility threshold (None-scored
    URLs pass — no evidence they're low-value), and the per-run cap.
    Returns the row id or None when policy declined.
    """
    cfg = vault.config.chrome
    if not cfg.enabled:
        return None
    if utility_score is not None and utility_score < cfg.escalation_utility_threshold:
        return None
    if vault_tag:
        count = vault.db.execute(
            "SELECT COUNT(*) AS c FROM escalations WHERE vault_tag = ?", (vault_tag,)
        ).fetchone()["c"]
        if count >= cfg.max_items_per_run:
            return None
    return enqueue(
        vault.db, url, reason,
        vault_tag=vault_tag, requested_by="fetch-gate",
        suggested_by=suggested_by, utility_score=utility_score, detail=detail,
    )


def claim_next(conn, claimed_by: str, vault_tag: str | None = None) -> dict | None:
    """Atomically claim the highest-utility queued item. None when queue empty.

    Single UPDATE with a scalar subquery — safe under concurrent claimers
    (SQLite serializes writers; the subquery re-evaluates inside the write
    lock, so two claimers can never take the same row).
    """
    now = _now()
    tag_clause = "AND vault_tag = ?" if vault_tag else ""
    params: list = [claimed_by, now]
    if vault_tag:
        params.append(vault_tag)
    cur = conn.execute(
        f"""UPDATE escalations
            SET status = 'in_progress', claimed_by = ?, updated_at = ?,
                attempts = attempts + 1
            WHERE id = (
                SELECT id FROM escalations
                WHERE status = 'queued' {tag_clause}
                ORDER BY utility_score IS NULL, utility_score DESC, id
                LIMIT 1
            )
            RETURNING *""",
        params,
    )
    row = cur.fetchone()
    conn.commit()
    return dict(row) if row else None


def resolve(
    conn,
    item_id: int,
    status: str,
    note_id: str | None = None,
    detail: str | None = None,
    *,
    vault=None,
) -> dict:
    """Move an item to a terminal (or needs_human) state."""
    if status not in ("fetched", "needs_human", "abandoned", "queued"):
        raise EscalationError(f"invalid resolution '{status}'")
    if status == "fetched":
        item = conn.execute("SELECT url FROM escalations WHERE id=?", (item_id,)).fetchone()
        from hyperresearch.core.x_projection import is_x_url

        if item and is_x_url(item["url"]):
            if vault is None or note_id is None:
                raise EscalationError("Native X resolution requires a vault and a recoverably indexed note")
            from hyperresearch.core.note import read_note
            from hyperresearch.core.x_evidence import EvidenceStore

            row = conn.execute("SELECT path FROM notes WHERE id=?", (note_id,)).fetchone()
            if row is None:
                raise EscalationError("Native X note is not indexed")
            note = read_note(vault.root / row["path"], vault.root)
            if not note.meta.x_evidence or not note.meta.x_evidence["receipt_refs"]:
                raise EscalationError("Native X note has no recorded source receipt")
            from urllib.parse import urlsplit

            store = EvidenceStore(vault.root)
            store.validate_note_refs(note.meta.x_evidence)
            post_id = urlsplit(item["url"]).path.split("/status/")[-1].split("/")[0]
            if not post_id.isdecimal() or not any(
                store.get_record(ref, "source-capture")["post_id"] == post_id
                for ref in note.meta.x_evidence["capture_refs"]
            ):
                raise EscalationError("Native X note does not cover the queued public post")
    cur = conn.execute(
        """UPDATE escalations
           SET status = ?, note_id = COALESCE(?, note_id),
               detail = COALESCE(?, detail), updated_at = ?
           WHERE id = ? RETURNING *""",
        (status, note_id, detail, _now(), item_id),
    )
    row = cur.fetchone()
    conn.commit()
    if row is None:
        raise EscalationError(f"no escalation item #{item_id}")
    return dict(row)


def list_items(
    conn,
    status: str | None = None,
    vault_tag: str | None = None,
    limit: int = 100,
) -> list[dict]:
    query = "SELECT * FROM escalations"
    conds, params = [], []
    if status:
        conds.append("status = ?")
        params.append(status)
    if vault_tag:
        conds.append("vault_tag = ?")
        params.append(vault_tag)
    if conds:
        query += " WHERE " + " AND ".join(conds)
    query += " ORDER BY utility_score IS NULL, utility_score DESC, id LIMIT ?"
    params.append(limit)
    return [dict(r) for r in conn.execute(query, params).fetchall()]


def queue_stats(conn, vault_tag: str | None = None) -> dict:
    """Counts by status — surfaced in `hpr run status`."""
    query = "SELECT status, COUNT(*) AS c FROM escalations"
    params: list = []
    if vault_tag:
        query += " WHERE vault_tag = ?"
        params.append(vault_tag)
    query += " GROUP BY status"
    stats = dict.fromkeys(STATUSES, 0)
    for row in conn.execute(query, params):
        stats[row["status"]] = row["c"]
    return stats
