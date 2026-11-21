"""Runs scripts from custom-simulations/. Catalog `simulation:` keys:
script (relative to custom-simulations/), interpreter (bash|sh|powershell), args (list;
"{target_host}" is substituted), run_from ("target" default | "local" = run on the runner
against target.host), allow_nonzero, timeout.
"""
from __future__ import annotations

from pathlib import Path

from ..models import ExecutionResult, TestCase
from .base import Adapter, Target, run_script


class CustomAdapter(Adapter):
    def __init__(self, custom_dir: Path):
        self.custom_dir = custom_dir

    def run(self, test: TestCase, target: Target) -> ExecutionResult:
        sim = test.simulation
        script_path = (self.custom_dir / sim["script"]).resolve()
        if self.custom_dir.resolve() not in script_path.parents:
            raise ValueError("script must live inside custom-simulations/")
        args = [str(a).replace("{target_host}", target.host or "127.0.0.1") for a in sim.get("args", [])]
        runner = Target("runner", "linux", "local") if sim.get("run_from") == "local" else target
        return run_script(runner, sim.get("interpreter", "bash"), script_path.read_text(encoding="utf-8"),
                          args, timeout=int(sim.get("timeout", 300)),
                          allow_nonzero=bool(sim.get("allow_nonzero", False)))
