"""Export CLI commands."""

from __future__ import annotations

import json
from pathlib import Path

import typer

from hyperresearch.cli._output import console, output
from hyperresearch.models.output import success

app = typer.Typer()


@app.command("json")
def export_json(
    output_path: str | None = typer.Option(None, "--output", "-o", help="Output file path"),
    pretty: bool = typer.Option(True, "--pretty/--compact", help="Pretty print"),
    json_output: bool = typer.Option(False, "--json", help="JSON output for status"),
) -> None:
    """Export all notes as structured JSON."""
    from hyperresearch.core.vault import Vault

    vault = Vault.discover()
    vault.auto_sync()

    from hyperresearch.core.note_transport import export_notes

    rows = vault.db.execute("SELECT path FROM notes ORDER BY title").fetchall()
    transported = export_notes(vault, rows)
    notes = transported["notes"]

    out = Path(output_path) if output_path else vault.exports_dir / "vault.json"
    out.parent.mkdir(parents=True, exist_ok=True)
    indent = 2 if pretty else None
    out.write_text(json.dumps(transported, indent=indent, default=str), encoding="utf-8")

    if json_output:
        output(success({"path": str(out), "count": len(notes)}, vault=str(vault.root)), json_mode=True)
    else:
        console.print(f"[green]Exported {len(notes)} notes to:[/] {out}")


@app.command("vault")
def export_vault(
    output_path: str = typer.Argument(..., help="Output directory"),
    tag: str | None = typer.Option(None, "--tag", "-t", help="Filter by tag"),
    status: str | None = typer.Option(None, "--status", "-s", help="Filter by status"),
    parent: str | None = typer.Option(None, "--parent", "-p", help="Filter by parent topic"),
    dry_run: bool = typer.Option(False, "--dry-run", help="Preview what would be exported"),
    json_output: bool = typer.Option(False, "--json", "-j", help="JSON output"),
) -> None:
    """Export a subset of notes to another directory."""
    import shutil

    from hyperresearch.core.vault import Vault

    vault = Vault.discover()
    vault.auto_sync()

    clauses = ["n.type NOT IN ('index')"]
    params: list = []
    if tag:
        clauses.append("n.id IN (SELECT note_id FROM tags WHERE tag = ?)")
        params.append(tag.lower())
    if status:
        clauses.append("n.status = ?")
        params.append(status)
    if parent:
        clauses.append("(n.parent = ? OR n.parent LIKE ?)")
        params.append(parent)
        params.append(parent + "/%")

    where = " AND ".join(clauses)
    rows = vault.db.execute(f"SELECT id, path, title FROM notes n WHERE {where}", params).fetchall()

    out_dir = Path(output_path).resolve()
    exported = []
    from hyperresearch.core.note import read_note
    from hyperresearch.core.frontmatter import render_note
    from hyperresearch.core.x_artifacts import atomic_write
    from hyperresearch.core.x_evidence import EvidenceStore
    from hyperresearch.core.x_projection import inert_markdown
    from hyperresearch.core.note_transport import note_destination
    from hyperresearch.models.x_evidence import canonical_bytes

    store = EvidenceStore(vault.root)
    bundle = store.export_closure()
    prepared = []
    for row in rows:
        src = vault.root / row["path"]
        if not src.exists():
            raise ValueError(f"Missing note export source: {row['path']}")
        dest = note_destination(out_dir, row["path"])
        exported.append({"id": row["id"], "path": row["path"]})
        note = read_note(src, vault.root)
        store.validate_note_refs(note.meta.x_evidence)
        prepared.append((src, dest, note))
    if not dry_run:
        atomic_write(out_dir / "x-evidence.json", canonical_bytes(bundle))
        for src, dest, note in prepared:
            dest.parent.mkdir(parents=True, exist_ok=True)
            if note.meta.x_evidence is not None:
                atomic_write(dest, render_note(note.meta, inert_markdown(note.body)).encode("utf-8"))
            else:
                shutil.copy2(src, dest)
    if json_output:
        action = "would_export" if dry_run else "exported"
        output(success({action: exported, "count": len(exported), "output_path": str(out_dir)},
                       count=len(exported), vault=str(vault.root)), json_mode=True)
    else:
        verb = "Would export" if dry_run else "Exported"
        console.print(f"[green]{verb} {len(exported)} notes to:[/] {out_dir}")
        for item in exported[:20]:
            console.print(f"  {item['path']}")
        if len(exported) > 20:
            console.print(f"  [dim]...and {len(exported) - 20} more[/]")


