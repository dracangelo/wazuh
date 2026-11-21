"""Runs scripts from custom-simulations/. Catalog `simulation:` keys:
script (relative to custom-simulations/), interpreter (bash|sh|powershell), args (list;
"{target_host}" and "{dv_exec_id}" are substituted), run_from ("target" default | "local" = run on
the runner against target.host), allow_nonzero, timeout, prelude (default true).

By default the shared safety library (custom-simulations/lib/dv_safety.sh) is prepended to the
script and DV_EXEC_ID / DV_TEST_ID are exported, so every run uses unique resource names and only
removes what it created.
"""
from __future__ import annotations

import shlex
from pathlib import Path

from ..models import ExecutionResult, TestCase
from .base import Adapter, Target, new_exec_id, run_script


class CustomAdapter(Adapter):
    def __init__(self, custom_dir: Path, prelude: str | None = None, default_timeout: int = 300):
        self.custom_dir = Path(custom_dir)
        self.default_timeout = int(default_timeout)
        if prelude is None:
            lib = self.custom_dir / "lib" / "dv_safety.sh"
            prelude = lib.read_text(encoding="utf-8") if lib.exists() else ""
        self.prelude = prelude

    def _with_prelude(self, script: str, exec_id: str, test_id: str) -> str:
        if not self.prelude:
            return script
        header = (f"DV_EXEC_ID={shlex.quote(exec_id)}\n"
                  f"DV_TEST_ID={shlex.quote(test_id)}\n"
                  "export DV_EXEC_ID DV_TEST_ID\n")
        return header + self.prelude + "\n" + script

    def run(self, test: TestCase, target: Target) -> ExecutionResult:
        sim = test.simulation
        script_path = (self.custom_dir / sim["script"]).resolve()
        if self.custom_dir.resolve() not in script_path.parents:
            raise ValueError("script must live inside custom-simulations/")
        exec_id = new_exec_id()
        args = [
            str(a).replace("{target_host}", target.host or "127.0.0.1").replace("{dv_exec_id}", exec_id)
            for a in sim.get("args", [])
        ]
        runner = Target("runner", "linux", "local") if sim.get("run_from") == "local" else target
        script = script_path.read_text(encoding="utf-8")
        if sim.get("prelude", True):
            script = self._with_prelude(script, exec_id, test.id)
        return run_script(runner, sim.get("interpreter", "bash"), script,
                          args, timeout=int(sim.get("timeout", self.default_timeout)),
                          allow_nonzero=bool(sim.get("allow_nonzero", False)))
