"""Offline note transport with full declared metadata and canonical X artifact closure."""

from __future__ import annotations

from pathlib import Path

import yaml

from hyperresearch.core.frontmatter import parse_frontmatter, render_note
from hyperresearch.core.note import read_note
from hyperresearch.core.x_artifacts import atomic_write, decode_json
from hyperresearch.core.x_evidence import EvidenceStore
from hyperresearch.core.x_projection import inert_markdown
from hyperresearch.models.note import NoteMeta
from hyperresearch.models.x_evidence import validate_record


def note_destination(root: Path, relative: str) -> Path:
    """Note filenames may be Unicode; traversal, symlinks and control characters may not."""
    path = Path(relative)
    if not relative or path.is_absolute() or "\\" in relative or ":" in relative or any(part in {"", ".", ".."} for part in relative.split("/")):
        raise ValueError("Unsafe note transport path")
    if any(ord(char) < 32 for char in relative):
        raise ValueError("Control character in note transport path")
    target = root / path
    target.resolve().relative_to(root.resolve())
    for parent in (target, *target.parents):
        if parent == root:
            break
        if parent.is_symlink():
            raise ValueError("Symlink note transport path refused")
    return target


def export_notes(vault, rows) -> dict:
    store = EvidenceStore(vault.root)
    notes = []
    for row in rows:
        note = read_note(vault.root / row["path"], vault.root)
        store.validate_note_refs(note.meta.x_evidence)
        body = inert_markdown(note.body) if note.meta.x_evidence is not None else note.body
        notes.append({"path": note.path, "metadata": note.meta.model_dump(mode="json"), "body": body})
    # Include zero/error operations and all immutable history, not only note-linked records.
    return validate_record("note-transport", {"schema_version": 1, "notes": notes, "evidence": store.export_closure()})


def import_json_notes(vault, path: Path, prefix: str, dry_run: bool) -> list[dict]:
    payload = validate_record("note-transport", decode_json(path.read_bytes()))
    prepared = []
    for entry in payload["notes"]:
        metadata = NoteMeta.model_validate(entry["metadata"])
        relative = f"{prefix}/{entry['path']}" if prefix else entry["path"]
        destination = note_destination(vault.notes_dir, relative)
        body = inert_markdown(entry["body"]) if metadata.x_evidence is not None else entry["body"]
        data = render_note(metadata, body).encode("utf-8")
        if destination.exists() and destination.read_bytes() != data:
            raise ValueError(f"Note import would overwrite an existing note: {relative}")
        prepared.append((destination, data, metadata))
    store = EvidenceStore(vault.root)
    if not dry_run:
        store.import_closure(payload["evidence"])
        for destination, data, metadata in prepared:
            store.validate_note_refs(metadata.x_evidence)
        for destination, data, _ in prepared:
            atomic_write(destination, data, immutable=True)
    else:
        # Dry-run validates the real closure without publishing it in the destination.
        import tempfile

        with tempfile.TemporaryDirectory() as temporary:
            preview_store = EvidenceStore(Path(temporary) / "preview")
            preview_store.import_closure(payload["evidence"])
            for _, _, metadata in prepared:
                preview_store.validate_note_refs(metadata.x_evidence)
    return [{"source": str(path), "destination": destination.relative_to(vault.notes_dir).as_posix()}
            for destination, _, _ in prepared]


def markdown_import_bytes(file: Path) -> tuple[bytes | None, NoteMeta | None]:
    """The bytes to write for a note carrying X evidence (inert body), else (None, None).

    A symlinked note is refused: its target can sit outside the import source.
    An ordinary note whose frontmatter does not parse is copied as-is (sync
    then reports it as not indexed); one that declares X evidence is refused.
    """
    if file.is_symlink():
        raise ValueError(f"Symlink note import refused: {file.name}")
    text = file.read_text(encoding="utf-8-sig")
    try:
        metadata, body = parse_frontmatter(text)
    except (yaml.YAMLError, ValueError) as exc:
        if "x_evidence" not in text.split("\n---", 1)[0]:
            return None, None
        raise ValueError(f"Note with X evidence has invalid frontmatter: {file.name}: {exc}") from exc
    if metadata.x_evidence is None:
        return None, None
    return render_note(metadata, inert_markdown(body)).encode("utf-8"), metadata


def import_markdown_evidence(vault, source: Path, metas: list[NoteMeta], dry_run: bool) -> None:
    """Import the X artifact closure beside a markdown export, then check each note's refs.

    A dry run validates against a temporary store and publishes nothing.
    """
    sidecar = source / "x-evidence.json"
    if sidecar.is_symlink():
        raise ValueError("Symlink evidence sidecar refused")
    if not dry_run:
        store = EvidenceStore(vault.root)
        if sidecar.exists():
            store.import_artifacts(sidecar)
        for metadata in metas:
            store.validate_note_refs(metadata.x_evidence)
        return
    import tempfile

    with tempfile.TemporaryDirectory() as temporary:
        preview_store = EvidenceStore(Path(temporary) / "preview")
        if sidecar.exists():
            preview_store.import_artifacts(sidecar)
        for metadata in metas:
            preview_store.validate_note_refs(metadata.x_evidence)
