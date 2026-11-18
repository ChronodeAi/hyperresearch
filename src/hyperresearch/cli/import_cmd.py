"""Import notes from another vault or directory."""

from __future__ import annotations

from pathlib import Path

import typer

from hyperresearch.cli._output import console, output
from hyperresearch.models.output import error, success


def import_vault(
    source: str = typer.Argument(..., help="Source directory to import from"),
    prefix: str = typer.Option("", "--prefix", "-p", help="Path prefix for imported notes (e.g. imported/ml)"),
    dry_run: bool = typer.Option(False, "--dry-run", help="Preview what would be imported"),
    json_output: bool = typer.Option(False, "--json", "-j", help="JSON output"),
) -> None:
    """Import markdown notes from another directory into this vault."""
    from hyperresearch.core.vault import Vault, VaultError

    try:
        vault = Vault.discover()
    except VaultError as e:
        if json_output:
            output(error(str(e), "NO_VAULT"), json_mode=True)
        else:
            console.print(f"[red]Error:[/] {e}")
        raise typer.Exit(1)

    source_path = Path(source).resolve()
    from hyperresearch.core.note_transport import import_json_notes, import_markdown_notes

    try:
        if source_path.is_file() and source_path.suffix == ".json":
            imported = import_json_notes(vault, source_path, prefix, dry_run)
        elif source_path.is_dir():
            imported = import_markdown_notes(vault, source_path, prefix, dry_run)
        else:
            raise ValueError(f"Import source not found: {source}")
        if not dry_run:
            from hyperresearch.core.sync import compute_sync_plan, execute_sync

            result = execute_sync(vault, compute_sync_plan(vault))
            if result.errors:
                raise ValueError(f"Imported artifacts and notes are durable but indexing failed: {result.errors}")
    except (ValueError, OSError) as exc:
        output(error(str(exc), "IMPORT_VALIDATION"), json_mode=json_output)
        raise typer.Exit(1) from exc

    if json_output:
        action = "would_import" if dry_run else "imported"
        output(success({action: imported, "count": len(imported)}, count=len(imported),
                       vault=str(vault.root)), json_mode=True)
    else:
        verb = "Would import" if dry_run else "Imported"
        console.print(f"[green]{verb} {len(imported)} files:[/]")
        for item in imported[:20]:
            console.print(f"  {item['source']} -> {item['destination']}")
        if len(imported) > 20:
            console.print(f"  [dim]...and {len(imported) - 20} more[/]")
