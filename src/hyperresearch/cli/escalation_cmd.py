"""Escalation commands — the browser-lane work queue.

Blocked fetches land here (login walls, bot blocks, captchas); the
hyperresearch-browser-fetcher agent drains the queue via `claim` →
(`ingest` | `human` | `abandon`). `ingest` is the one-shot completion:
it writes the note, records the source row, syncs, and resolves the item —
the agent supplies content, Python does the bookkeeping.
"""

from __future__ import annotations

import hashlib
from datetime import UTC, datetime
from pathlib import Path
from urllib.parse import urlparse

import typer
from rich.markup import escape

from hyperresearch.cli._output import console, output
from hyperresearch.models.output import error, success

app = typer.Typer()


def _vault_or_exit(json_output: bool):
    from hyperresearch.core.vault import Vault, VaultError

    try:
        return Vault.discover()
    except VaultError as e:
        if json_output:
            output(error(str(e), "NO_VAULT"), json_mode=True)
        else:
            console.print(f"[red]Error:[/] {e}")
        raise typer.Exit(1)


@app.command("list")
def escalation_list(
    status: str | None = typer.Option(None, "--status", "-s", help="queued|in_progress|fetched|needs_human|abandoned"),
    tag: str | None = typer.Option(None, "--tag", "-t", help="Only items for this vault_tag"),
    limit: int = typer.Option(100, "--limit", "-n", help="Max items"),
    json_output: bool = typer.Option(False, "--json", "-j", help="JSON output"),
) -> None:
    """List escalation queue items (highest utility first)."""
    from hyperresearch.core.escalation import list_items, queue_stats

    vault = _vault_or_exit(json_output)
    items = list_items(vault.db, status=status, vault_tag=tag, limit=limit)
    stats = queue_stats(vault.db, vault_tag=tag)

    if json_output:
        output(success({"items": items, "stats": stats}, count=len(items), vault=str(vault.root)), json_mode=True)
    else:
        for it in items:
            score = f"u{it['utility_score']:g}" if it["utility_score"] is not None else "u?"
            console.print(f"  #{it['id']} [{it['status']}] ({it['reason']}, {score}) {it['url']}")
        console.print(f"[dim]{stats}[/]")


@app.command("add")
def escalation_add(
    url: str = typer.Argument(..., help="URL (or Scholar query for --reason scholar_search)"),
    reason: str = typer.Option(..., "--reason", "-r", help="login_wall|bot_block|captcha|fetch_failed|interactive_needed|scholar_search"),
    tag: str | None = typer.Option(None, "--tag", "-t", help="vault_tag"),
    utility: float | None = typer.Option(None, "--utility", help="Utility score (drives drain priority)"),
    suggested_by: str | None = typer.Option(None, "--suggested-by", help="Note id that surfaced this URL"),
    detail: str | None = typer.Option(None, "--detail", help="One-line context"),
    json_output: bool = typer.Option(False, "--json", "-j", help="JSON output"),
) -> None:
    """Manually queue an item (e.g. an interactive-only page or a Scholar search)."""
    from hyperresearch.core.escalation import EscalationError, enqueue

    vault = _vault_or_exit(json_output)
    try:
        item_id = enqueue(
            vault.db, url, reason, vault_tag=tag, requested_by="manual",
            suggested_by=suggested_by, utility_score=utility, detail=detail,
        )
    except EscalationError as e:
        if json_output:
            output(error(str(e), "ESCALATION_ERROR"), json_mode=True)
        else:
            console.print(f"[red]Error:[/] {e}")
        raise typer.Exit(1)

    data = {"id": item_id, "already_queued": item_id is None}
    if json_output:
        output(success(data, vault=str(vault.root)), json_mode=True)
    else:
        console.print(f"  queued #{item_id}" if item_id else "  already queued")


@app.command("claim")
def escalation_claim(
    claimed_by: str = typer.Option("browser-fetcher", "--by", help="Claimer id"),
    tag: str | None = typer.Option(None, "--tag", "-t", help="Only claim items for this vault_tag"),
    json_output: bool = typer.Option(False, "--json", "-j", help="JSON output"),
) -> None:
    """Atomically claim the next queued item (empty result when queue is drained)."""
    from hyperresearch.core.escalation import claim_next

    vault = _vault_or_exit(json_output)
    item = claim_next(vault.db, claimed_by, vault_tag=tag)

    if json_output:
        output(success({"item": item, "queue_empty": item is None}, vault=str(vault.root)), json_mode=True)
    else:
        if item is None:
            console.print("[dim]Queue empty.[/]")
        else:
            console.print(f"  claimed #{item['id']} ({item['reason']}) {item['url']}")


@app.command("ingest")
def escalation_ingest(
    item_id: int = typer.Argument(..., help="Claimed escalation item id"),
    title: str | None = typer.Option(None, "--title", help="Page title (ordinary browser intake)"),
    body_file: str | None = typer.Option(None, "--body-file", help="Extracted article content; native X requires a receipt"),
    receipt_path: str | None = typer.Option(None, "--receipt", help="Canonical native source receipt path"),
    capture_path: str | None = typer.Option(None, "--capture", help="Canonical native capture path"),
    tags: list[str] = typer.Option([], "--tag", "-t", help="Tags (repeatable; the item's vault_tag is added automatically)"),
    json_output: bool = typer.Option(False, "--json", "-j", help="JSON output"),
) -> None:
    """Complete a claimed item: write the note + source row, sync, resolve.

    One command so the browser agent can't half-finish the bookkeeping.
    Notes carry `fetch_provider: chrome` — browser-lane provenance is visible.
    """
    from hyperresearch.core.escalation import EscalationError, list_items, resolve
    from hyperresearch.core.fetcher import discard_unindexed_note
    from hyperresearch.core.note import indexed_note_ids, write_note
    from hyperresearch.core.scholar import extract_doi
    from hyperresearch.core.sync import compute_sync_plan, execute_sync

    vault = _vault_or_exit(json_output)
    conn = vault.db

    matching = [it for it in list_items(conn, limit=10000) if it["id"] == item_id]
    if not matching:
        if json_output:
            output(error(f"no escalation item #{item_id}", "NOT_FOUND"), json_mode=True)
        else:
            console.print(f"[red]Error:[/] no escalation item #{item_id}")
        raise typer.Exit(1)
    item = matching[0]

    from hyperresearch.core.x_projection import is_x_url

    if is_x_url(item["url"]):
        _ingest_native_x(vault, item, receipt_path, capture_path, tags, json_output)
        return
    if not body_file or not title:
        output(error("Ordinary browser intake requires --title and --body-file", "NO_INPUT"), json_mode=json_output)
        raise typer.Exit(1)
    body = Path(body_file).read_text(encoding="utf-8-sig")
    url = item["url"]
    domain = urlparse(url).netloc
    now = datetime.now(UTC)

    all_tags = list(tags)
    if item["vault_tag"] and item["vault_tag"] not in all_tags:
        all_tags.insert(0, item["vault_tag"])

    extra_meta: dict = {
        "source": url,
        "source_domain": domain,
        "fetched_at": now.isoformat(),
        "fetch_provider": "chrome",
    }
    detected_doi = extract_doi(url, content=body)
    if detected_doi:
        extra_meta["doi"] = detected_doi
    if item["utility_score"] is not None:
        extra_meta["utility_score"] = item["utility_score"]

    if item["suggested_by"]:
        body = f"*Suggested by [[{item['suggested_by']}]]*\n\n" + body

    note_path = write_note(
        vault.notes_dir, title=title, body=body, tags=all_tags,
        status="draft", source=url, extra_frontmatter=extra_meta,
        taken_ids=indexed_note_ids(conn),
    )
    note_id = note_path.stem

    plan = compute_sync_plan(vault)
    sync_result = execute_sync(vault, plan) if plan.to_add or plan.to_update else None

    # A note sync did not index under its own id gets no source row (it would
    # point at whichever file holds that id), and the item stays claimed.
    refused = discard_unindexed_note(vault, note_path)
    if refused:
        if json_output:
            output(error(refused, "NOTE_NOT_INDEXED"), json_mode=True)
        else:
            console.print(f"[red]Error:[/] {escape(refused)}")
        raise typer.Exit(1)
    if sync_result is not None and sync_result.errors:
        envelope = error("Note is durable but indexing failed", "INDEX_PROJECTION_FAILED")
        envelope.data = {"errors": sync_result.errors, "note_id": note_id}
        output(envelope, json_mode=json_output)
        raise typer.Exit(1)

    content_hash = hashlib.sha256(body.encode("utf-8")).hexdigest()[:16]
    conn.execute(
        """INSERT OR IGNORE INTO sources (url, note_id, domain, fetched_at, provider, content_hash)
           VALUES (?, ?, ?, ?, ?, ?)""",
        (url, note_id, domain, now.isoformat(), "chrome", content_hash),
    )
    conn.commit()

    try:
        resolved = resolve(conn, item_id, "fetched", note_id=note_id)
    except EscalationError as e:
        if json_output:
            output(error(str(e), "ESCALATION_ERROR"), json_mode=True)
        else:
            console.print(f"[red]Error:[/] {e}")
        raise typer.Exit(1)

    data = {
        "note_id": note_id,
        "path": str(note_path.relative_to(vault.root)),
        "word_count": len(body.split()),
        "item": resolved,
    }
    if json_output:
        output(success(data, vault=str(vault.root)), json_mode=True)
    else:
        console.print(f"[green]Ingested:[/] #{item_id} -> note '{note_id}'")


def _ingest_native_x(vault, item, receipt_path, capture_path, tags, json_output):
    """Recover an already acquired native post, never fabricate Chrome provenance."""
    from hyperresearch.core.escalation import EscalationError, resolve
    from hyperresearch.core.x_evidence import EvidenceStore
    from hyperresearch.web.opencli_provider import NativeSourceError

    try:
        if not receipt_path:
            raise NativeSourceError("Native X escalation requires --receipt; extracted reader text is not source evidence")
        store = EvidenceStore(vault.root)
        receipt_ref = store.ref_from_path(receipt_path)
        store.get_record(receipt_ref, "source-receipt")
        candidates = store.resolve_closure([receipt_ref])
        post_id = item["url"].split("/status/")[-1].split("/")[0]
        capture_ref = store.ref_from_path(capture_path) if capture_path else next(
            (record["ref"] for record in candidates if record["kind"] == "source-capture" and record["payload"]["post_id"] == post_id), None,
        )
        if capture_ref is None or store.get_record(capture_ref, "source-capture")["post_id"] != post_id:
            raise NativeSourceError("Receipt closure contains no matching escalation post", "X_SOURCE_SCOPE")
        materialized = store.materialize_capture(capture_ref, receipt_ref)
        if materialized["errors"]:
            raise NativeSourceError("Native evidence and note are durable but indexing failed", "INDEX_PROJECTION_FAILED", materialized)
        if tags or item["vault_tag"] or item["suggested_by"]:
            from hyperresearch.cli.batch import _update_file_frontmatter
            from hyperresearch.core.sync import compute_sync_plan, execute_sync

            if item["suggested_by"]:
                from hyperresearch.core.note import read_note
                from hyperresearch.core.frontmatter import render_note
                from hyperresearch.core.x_artifacts import atomic_write
                from hyperresearch.core.x_projection import inert_markdown

                path = vault.root / materialized["path"]
                note = read_note(path, vault.root)
                lineage = f"*Suggested by [[{inert_markdown(item['suggested_by'])}]]*\n\n"
                if not note.body.startswith(lineage):
                    atomic_write(path, render_note(note.meta, lineage + note.body).encode("utf-8"))
            for tag in [*tags, *([item["vault_tag"]] if item["vault_tag"] else [])]:
                _update_file_frontmatter(vault.root, materialized["path"], {"add_tag": tag})
            synced = execute_sync(vault, compute_sync_plan(vault))
            if synced.errors:
                raise NativeSourceError("Native note tag projection failed", "INDEX_PROJECTION_FAILED", {"errors": synced.errors})
        resolved = resolve(vault.db, item["id"], "fetched", note_id=materialized["note_id"], vault=vault)
        output(success({**materialized, "item": resolved}, vault=str(vault.root)), json_mode=json_output)
    except (ValueError, RuntimeError, EscalationError) as exc:
        code = getattr(exc, "code", "X_SOURCE_SCHEMA")
        resolve(vault.db, item["id"], "queued", detail=code)
        envelope = error(str(exc), code)
        envelope.data = getattr(exc, "result", None)
        output(envelope, json_mode=json_output)
        raise typer.Exit(1) from exc


@app.command("human")
def escalation_human(
    item_id: int = typer.Argument(..., help="Item id"),
    detail: str = typer.Option(..., "--detail", help="One line: what the human must do (e.g. 'solve CAPTCHA on nature.com')"),
    json_output: bool = typer.Option(False, "--json", "-j", help="JSON output"),
) -> None:
    """Mark an item as needing the human (CAPTCHA / 2FA / login). NEVER solve these automatically."""
    from hyperresearch.core.escalation import EscalationError, resolve

    vault = _vault_or_exit(json_output)
    try:
        item = resolve(vault.db, item_id, "needs_human", detail=detail)
    except EscalationError as e:
        if json_output:
            output(error(str(e), "ESCALATION_ERROR"), json_mode=True)
        else:
            console.print(f"[red]Error:[/] {e}")
        raise typer.Exit(1)
    if json_output:
        output(success(item, vault=str(vault.root)), json_mode=True)
    else:
        console.print(f"  #{item_id} needs human: {detail}")


@app.command("retry")
def escalation_retry(
    item_id: int = typer.Argument(..., help="Item id"),
    json_output: bool = typer.Option(False, "--json", "-j", help="JSON output"),
) -> None:
    """Re-queue a needs_human item after the human completed the challenge."""
    from hyperresearch.core.escalation import EscalationError, resolve

    vault = _vault_or_exit(json_output)
    try:
        item = resolve(vault.db, item_id, "queued")
    except EscalationError as e:
        if json_output:
            output(error(str(e), "ESCALATION_ERROR"), json_mode=True)
        else:
            console.print(f"[red]Error:[/] {e}")
        raise typer.Exit(1)
    if json_output:
        output(success(item, vault=str(vault.root)), json_mode=True)
    else:
        console.print(f"  #{item_id} re-queued")


@app.command("abandon")
def escalation_abandon(
    item_id: int = typer.Argument(..., help="Item id"),
    detail: str | None = typer.Option(None, "--detail", help="Why (optional)"),
    json_output: bool = typer.Option(False, "--json", "-j", help="JSON output"),
) -> None:
    """Give up on an item. The floor is the pre-4.0 status quo: the source is lost."""
    from hyperresearch.core.escalation import EscalationError, resolve

    vault = _vault_or_exit(json_output)
    try:
        item = resolve(vault.db, item_id, "abandoned", detail=detail)
    except EscalationError as e:
        if json_output:
            output(error(str(e), "ESCALATION_ERROR"), json_mode=True)
        else:
            console.print(f"[red]Error:[/] {e}")
        raise typer.Exit(1)
    if json_output:
        output(success(item, vault=str(vault.root)), json_mode=True)
    else:
        console.print(f"  #{item_id} abandoned")
