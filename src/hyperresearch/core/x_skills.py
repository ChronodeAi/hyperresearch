"""Managed delivery of the monitor resource without hooks or other-provider writes."""
from __future__ import annotations

import hashlib
import importlib.resources
import json
from pathlib import Path

from hyperresearch import __version__
from hyperresearch.core.x_artifacts import atomic_write
from hyperresearch.models.x_evidence import canonical_bytes

_NAME = "hyperresearch-x-monitor"
_MARKER = ".hyperresearch-managed.json"


def _safe(path: Path) -> None:
    if not path.is_absolute() or ".." in path.parts:
        raise ValueError("Skill destination must be an absolute non-traversing path")
    for component in reversed([path, *path.parents]):
        if component.is_symlink():
            raise ValueError("Refusing a symlinked skill destination or ancestor")
        if component.exists() and component != path and not component.is_dir():
            raise ValueError("Skill destination ancestor is not a directory")


def install_monitor_skill(*, platform: str = "omp", scope: str = "user",
                          root: Path | None = None, dry_run: bool = False,
                          hpr_path: str | None = None, home: Path | None = None) -> dict:
    from hyperresearch.core.agent_docs import _resolve_executable
    from hyperresearch.core.platforms import CODEX, OMP, check_platform, paths_for
    from hyperresearch.core.render import build_render_context, render_prompt

    check_platform(platform)
    if scope not in {"user", "project"}:
        raise ValueError("Skill scope must be user or project")
    project = (root or Path.cwd()).absolute()
    base = (home or Path.home()).absolute() if scope == "user" else project
    if platform == OMP and scope == "user":
        from hyperresearch.core.omp import user_omp_agent_dir
        skills = user_omp_agent_dir(base).absolute() / "skills"
    else:
        skills = base / paths_for(platform).skills_dir
    destination = skills / _NAME
    _safe(destination)
    if destination.exists() and not destination.is_dir():
        raise ValueError("Skill destination is not a directory")
    marker = destination / _MARKER
    target = destination / "SKILL.md"
    for path in (marker, target):
        _safe(path)
        if path.exists() and not path.is_file():
            raise ValueError("Managed skill path is not a regular file")
    prior = None
    if marker.is_file():
        prior = json.loads(marker.read_text(encoding="utf-8"))
        if (prior.get("schema_version") != 1 or prior.get("product") != "hyperresearch"
                or prior.get("skill") != _NAME or prior.get("destination") != str(destination)
                or set(prior.get("files", {})) != {"SKILL.md"}):
            raise ValueError("Managed skill ownership marker is invalid")
        if not target.is_file() or hashlib.sha256(target.read_bytes()).hexdigest() != prior["files"]["SKILL.md"]:
            raise ValueError("Managed skill was customized; refusing replacement")
    elif destination.exists() and any(destination.iterdir()):
        raise ValueError("Unowned/custom skill destination; refusing replacement")
    source = importlib.resources.files("hyperresearch.skills").joinpath(_NAME + ".md").read_text(encoding="utf-8")
    config = project / ".hyperresearch" / "config.toml"
    context = build_render_context(config if scope == "project" and config.is_file() else None,
                                  primary="full", platform=CODEX if platform == OMP else platform)
    text = render_prompt(source, context).replace("{hpr_path}", hpr_path or _resolve_executable())
    if platform == OMP:
        from hyperresearch.core.omp import translate_skill
        text = translate_skill(text, entry=False)
    data = text.encode("utf-8")
    ownership = {"schema_version": 1, "product": "hyperresearch", "skill": _NAME,
                 "package_version": __version__, "resource_sha256": hashlib.sha256(source.encode()).hexdigest(),
                 "renderer": "monitor-skill-v1", "platform": platform, "scope": scope,
                 "destination": str(destination), "files": {"SKILL.md": hashlib.sha256(data).hexdigest()}}
    unchanged = prior == ownership and target.read_bytes() == data
    if not dry_run and not unchanged:
        destination.mkdir(parents=True, exist_ok=True)
        # Ownership is rechecked immediately before replacement. No custom files
        # in an otherwise managed directory are enumerated, removed or rewritten.
        _safe(destination)
        if prior and hashlib.sha256(target.read_bytes()).hexdigest() != prior["files"]["SKILL.md"]:
            raise ValueError("Managed skill changed during delivery")
        atomic_write(target, data)
        atomic_write(marker, canonical_bytes(ownership))
    return {"platform": platform, "scope": scope, "path": str(destination),
            "status": "unchanged" if unchanged else "would-install" if dry_run else "installed",
            "dry_run": dry_run, "ownership": ownership, "source_requests": 0, "model_requests": 0}
