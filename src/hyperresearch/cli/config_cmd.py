"""Configuration CLI commands."""

from __future__ import annotations
import json
from dataclasses import asdict, fields, replace


import typer

from hyperresearch.cli._output import console, output
from hyperresearch.models.output import success

app = typer.Typer()

_KEY_MAP = {
    "vault.name": "name",
    "vault.research_dir": "research_dir",
    "web.provider": "web_provider",
    "web.profile": "web_profile",
    "web.magic": "web_magic",
    "search.boost_evergreen": "search_boost_evergreen",
    "search.penalize_deprecated": "search_penalize_deprecated",
    "sync.auto_sync": "auto_sync",
    "index.auto_build": "auto_build_index",
}


def _x_key(config, key: str) -> str | None:
    if not key.startswith("x."):
        return None
    name = key.removeprefix("x.")
    if name not in {item.name for item in fields(config.x)}:
        raise typer.BadParameter(f"Unknown native X configuration key: {key}")
    return name


def _coerce_x_value(current, value: str):
    if isinstance(current, bool):
        normalized = value.lower()
        if normalized not in {"true", "false", "1", "0", "yes", "no"}:
            raise ValueError("expected true or false")
        return normalized in {"true", "1", "yes"}
    if isinstance(current, int):
        return int(value, 10)
    if isinstance(current, tuple):
        decoded = json.loads(value)
        if not isinstance(decoded, list):
            raise ValueError("expected a JSON argv array")
        return tuple(decoded)
    return value



@app.command("show")
def config_show(
    json_output: bool = typer.Option(False, "--json", "-j", help="JSON output"),
) -> None:
    """Display current vault configuration."""
    from hyperresearch.core.vault import Vault

    vault = Vault.discover()
    config = vault.config

    data = {
        "vault_name": config.name,
        "vault_path": str(vault.root),
        "research_dir": config.research_dir,
        "web_provider": config.web_provider,
        "web_profile": config.web_profile or "(none)",
        "web_magic": config.web_magic,
        "auto_sync": config.auto_sync,
        "auto_build_index": config.auto_build_index,
        "search_boost_evergreen": config.search_boost_evergreen,
        "search_penalize_deprecated": config.search_penalize_deprecated,
        "x": asdict(config.x),
    }

    if json_output:
        output(success(data, vault=str(vault.root)), json_mode=True)
    else:
        console.print("[bold]Vault Configuration[/]")
        for k, v in data.items():
            console.print(f"  [dim]{k}:[/] {v}")


@app.command("set")
def config_set(
    key: str = typer.Argument(..., help="Config key (dot notation: vault.name)"),
    value: str = typer.Argument(..., help="Config value"),
    json_output: bool = typer.Option(False, "--json", "-j", help="JSON output"),
) -> None:
    """Set a configuration value."""
    from hyperresearch.core.vault import Vault

    vault = Vault.discover()
    config = vault.config

    x_key = _x_key(config, key)
    if x_key is not None:
        try:
            value = _coerce_x_value(getattr(config.x, x_key), value)
            config.x = replace(config.x, **{x_key: value})
        except (ValueError, TypeError) as exc:
            raise typer.BadParameter(f"Invalid {key}: {exc}") from exc
    else:
        attr = _KEY_MAP.get(key)
        if not attr:
            raise typer.BadParameter(f"Unknown config key: {key}")
        if attr in ("auto_sync", "auto_build_index", "web_magic"):
            value = value.lower() in ("true", "1", "yes")
        setattr(config, attr, value)
    config.save(vault.config_path)

    if json_output:
        output(success({"key": key, "value": value}, vault=str(vault.root)), json_mode=True)
    else:
        console.print(f"[green]Set[/] {key} = {value}")


@app.command("get")
def config_get(
    key: str = typer.Argument(..., help="Config key"),
    json_output: bool = typer.Option(False, "--json", "-j", help="JSON output"),
) -> None:
    """Get a configuration value."""
    from hyperresearch.core.vault import Vault

    vault = Vault.discover()
    config = vault.config

    x_key = _x_key(config, key)
    attr = _KEY_MAP.get(key)
    if x_key is None and attr is None:
        raise typer.BadParameter(f"Unknown config key: {key}")
    value = getattr(config.x, x_key) if x_key is not None else getattr(config, attr)

    if json_output:
        output(success({"key": key, "value": value}, vault=str(vault.root)), json_mode=True)
    else:
        typer.echo(value)


@app.command("agent-docs")
def config_agent_docs(
    json_output: bool = typer.Option(False, "--json", "-j", help="JSON output"),
) -> None:
    """Update CLAUDE.md (and AGENTS.md on Codex installs) with the latest hyperresearch blurb."""
    from hyperresearch.core.agent_docs import inject_agent_docs
    from hyperresearch.core.hooks import installed_platforms
    from hyperresearch.core.vault import Vault

    vault = Vault.discover()
    modified = inject_agent_docs(vault.root)
    if "codex" in installed_platforms(vault.root):
        modified += inject_agent_docs(vault.root, platform="codex")

    if json_output:
        output(success({"modified": modified}, vault=str(vault.root)), json_mode=True)
    else:
        if modified:
            for m in modified:
                console.print(f"  [green]{m}[/]")
        else:
            console.print("[dim]CLAUDE.md already up to date.[/]")
