"""Exercise the OMP extension against the real CLI stop gate under Node."""

from __future__ import annotations

import json
import shutil
import subprocess
import sys

import pytest

from hyperresearch.core.omp import extension_source
from hyperresearch.core.runs import init_run, set_status, set_step


def _exercise_extension(tmp_path, body):
    node = shutil.which("node")
    if node is None:
        pytest.skip("Node 24+ is needed for type-stripped TypeScript")
    version = subprocess.run(
        [node, "--version"], capture_output=True, text=True, check=True,
    ).stdout.strip()
    if int(version.lstrip("v").split(".")[0]) < 24:
        pytest.skip("Node 24+ is needed for type-stripped TypeScript")
    extension = tmp_path / "hyperresearch.ts"
    extension.write_text(extension_source(sys.executable), encoding="utf-8")
    script = tmp_path / "exercise.mts"
    script.write_text(
        f'''import install from {json.dumps(extension.as_uri())};
import assert from "node:assert/strict";
import {{ execFileSync }} from "node:child_process";
const handlers: Record<string, (event: unknown, ctx: any) => any> = {{}};
const calls: {{ args: string[], cwd: string | undefined, stdout: string }}[] = [];
install({{
  on(event, handler) {{ handlers[event] = handler; }},
  async exec(command, args, options) {{
    const stdout = execFileSync(command, ["-m", "hyperresearch", ...args], {{
      cwd: options?.cwd, encoding: "utf8",
    }});
    calls.push({{ args, cwd: options?.cwd, stdout }});
    return {{ stdout }};
  }},
}});
{body}
''',
        encoding="utf-8",
    )
    result = subprocess.run(
        [node, str(script)], capture_output=True, text=True, check=True, timeout=30,
    )
    return json.loads(result.stdout)


@pytest.mark.parametrize("override", ["absolute", "relative", None])
@pytest.mark.parametrize("completed", [False, True])
def test_stop_gate_tracks_command_vault(
    tmp_vault, tmp_path, monkeypatch, override, completed,
):
    monkeypatch.delenv("HYPERRESEARCH_STOP_GATE", raising=False)
    init_run(tmp_vault, "cwd-regression")
    set_step(tmp_vault, "cwd-regression", "1", "done")
    if completed:
        set_status(tmp_vault, "cwd-regression", "done")
    init_run(tmp_vault, "newer-foreign")
    session_cwd = tmp_vault.root if override is None else tmp_vault.root.parent
    input_cwd = (
        str(tmp_vault.root) if override == "absolute"
        else tmp_vault.root.name if override == "relative"
        else None
    )
    decision = _exercise_extension(
        tmp_path,
        f'''const ctx = {{ cwd: {json.dumps(str(session_cwd))}, agent: {{ kind: "main" }} }};
handlers.session_start({{}}, ctx);
handlers.tool_result({{
  toolName: "bash", isError: false,
  input: {{ command: "/opt/venv/bin/hyperresearch run step cwd-regression 1 --status done -j",
    cwd: {json.dumps(input_cwd)} }},
}}, ctx);
const active = await handlers.session_stop({{}}, ctx);
assert.equal(calls.length, 1);
handlers.session_switch({{}}, ctx);
const cleared = await handlers.session_stop({{}}, ctx);
assert.equal(calls.length, 1);
console.log(JSON.stringify({{ active: active ?? null, cleared: cleared ?? null,
  stdout: calls[0].stdout }}));''',
    )
    if completed:
        assert decision["active"] is None
        assert decision["stdout"] == ""
    else:
        assert decision["active"]["continue"] is True
        reason = decision["active"]["additionalContext"]
        assert "cwd-regression is at step 2" in reason
        assert ".hyperresearch/omp/steps/hyperresearch-2-width-sweep.md" in reason
        assert "newer-foreign" not in reason
        assert len(decision["stdout"].splitlines()) == 1
    assert decision["cleared"] is None


def test_stop_gate_rebinds_last_successful_run(tmp_vault, tmp_path, monkeypatch):
    monkeypatch.delenv("HYPERRESEARCH_STOP_GATE", raising=False)
    init_run(tmp_vault, "Done.run_1")
    set_status(tmp_vault, "Done.run_1", "done")
    init_run(tmp_vault, "Active.run_2")
    set_step(tmp_vault, "Active.run_2", "1", "done")
    init_run(tmp_vault, "newer-foreign")
    decision = _exercise_extension(
        tmp_path,
        f'''const ctx = {{ cwd: {json.dumps(str(tmp_vault.root))}, agent: {{ kind: "main" }} }};
const observe = (command: string, event = {{}}, context = ctx) =>
  handlers.tool_result({{ toolName: "bash", input: {{ command }}, ...event }}, context);
const stop = () => handlers.session_stop({{}}, ctx);
handlers.session_start({{}}, ctx);
assert.equal(await stop(), undefined);
assert.equal(calls.length, 0);
observe("hpr run init 'Done.run_1'");
assert.equal(await stop(), undefined);
assert.equal(calls.at(-1)?.stdout, "");
observe('/opt/bin/hpr run init Done.run_1 && hyperresearch run step "Active.run_2" 1 --status done');
const rebound = await stop();
assert.ok(rebound.additionalContext.includes("Active.run_2 is at step 2"));
observe("hyperresearch run init newer-foreign", {{ isError: true }});
observe("hyperresearch run init newer-foreign", {{}}, {{ ...ctx, agent: {{ kind: "sub" }} }});
observe("hyperresearch run init newer-foreign", {{ toolName: "read" }});
for (const tag of ["newer-foreign/extra", "newer-foreign$BAD", '"newer-foreign"suffix',
                   "'newer-foreign/extra'", "-newer-foreign"]) {{
  observe("hyperresearch run init " + tag);
}}
const preserved = await stop();
assert.equal(preserved.additionalContext, rebound.additionalContext);
observe("hyperresearch run step Active.run_2 1 --status done; hpr run init 'Done.run_1'");
assert.equal(await stop(), undefined);
assert.equal(calls.at(-1)?.stdout, "");
const count = calls.length;
handlers.session_start({{}}, ctx);
assert.equal(await stop(), undefined);
assert.equal(calls.length, count);
observe('hyperresearch run init "Active.run_2"');
assert.equal((await stop()).continue, true);
handlers.session_switch({{}}, ctx);
assert.equal(await stop(), undefined);
assert.equal(calls.length, count + 1);
console.log(JSON.stringify({{ rebound, preserved }}));''',
    )
    assert decision["rebound"]["continue"] is True
    assert decision["preserved"] == decision["rebound"]
