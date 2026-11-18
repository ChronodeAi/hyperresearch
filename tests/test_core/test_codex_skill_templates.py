"""Codex renders of the pipeline skill templates.

The skill templates branch on the `platform` render variable. The Claude render
is pinned byte-for-byte by the golden tests (test_prompt_golden.py); this module
checks the Codex render: no Claude-only constructs leak through, and every step
file / custom agent the Codex orchestrator is told to read or spawn exists.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest
import yaml

import hyperresearch
from hyperresearch.core import hooks
from hyperresearch.core.profiles import list_profiles
from hyperresearch.core.render import build_render_context, render_prompt

SKILLS_DIR = Path(hyperresearch.__file__).parent / "skills"
TEMPLATES = sorted(p.name for p in SKILLS_DIR.glob("*.md"))
PROFILES = list_profiles(None)

# Constructs that only exist on Claude Code. None may appear in a Codex render.
FORBIDDEN = [
    "Skill(",
    "subagent_type",
    ".claude/",
    "Task tool",
    "Task call",
    "Task result",
    "TodoWrite",
    "claude-in-chrome",
    "Claude-in-Chrome",
    "hyperresearch-browser-fetcher",
    "Claude Code",
    "CLAUDE.md",
    "PreToolUse",
    "end_turn",
    "tool-locked",
    "TOOL-LOCKED",
    "[Read, Edit]",
    "[Read, Write]",
    "Edit tool",
]

STEP_FILE_RE = re.compile(r"\.hyperresearch/codex/steps/([a-z0-9-]+)\.md")


STEPS = set(hooks._HYPERRESEARCH_STEP_SKILLS)


@pytest.fixture(scope="module", params=PROFILES)
def codex_renders(request):
    ctx = build_render_context(None, primary=request.param, platform="codex")
    return {
        name: render_prompt((SKILLS_DIR / name).read_text(encoding="utf-8"), ctx)
        for name in TEMPLATES
    }




@pytest.mark.parametrize("template", TEMPLATES)
def test_codex_render_has_no_claude_constructs(template, codex_renders):
    text = codex_renders[template]
    for needle in FORBIDDEN:
        assert needle not in text, f"{template}: Codex render contains {needle!r}"
    assert not re.search(r"(?<![$\w])/hyperresearch\b", text), (
        f"{template}: Codex render uses the /hyperresearch slash command (use $hyperresearch)"
    )
    assert "<%" not in text and "%>" not in text and "<<" not in text


@pytest.mark.parametrize("template", TEMPLATES)
def test_codex_step_file_references_exist(template, codex_renders):
    for step in STEP_FILE_RE.findall(codex_renders[template]):
        assert step in STEPS, f"{template}: references unknown step file {step}.md"






def test_codex_router_frontmatter_and_enforcement(codex_renders):
    text = codex_renders["hyperresearch.md"]
    fm = yaml.safe_load(text.split("---", 2)[1])
    assert fm["name"] == "hyperresearch"
    assert "hyperresearch" in fm["description"]
    assert len(fm["description"]) <= 1024
    assert "$hyperresearch" in fm["description"]
    # Anti-shortcut + explicit-spawn instructions (the April 2026 bench failure).
    assert "THE JOB IS THE PIPELINE, NOT AN ANSWER" in text
    assert "Stop hook" in text
    assert "Spawning subagents is mandatory" in text
    assert "--target codex" in text
    # Every step in the roster is reachable from the router's table.
    for step in STEPS:
        assert f"`{step}`" in text, step


