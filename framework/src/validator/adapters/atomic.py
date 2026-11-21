"""Runs Atomic Red Team tests from the standard atomics layout:
atomic/<platform>/<Txxxx[.yyy]>/<Txxxx[.yyy]>.yaml
(copy the ones you need from redcanaryco/atomic-red-team/atomics).

Catalog `simulation:` keys: technique (default test.technique), test (1-based index or GUID),
args (input_arguments overrides), allow_nonzero (bool), timeout (s).
"""
from __future__ import annotations

import re
from pathlib import Path

import yaml

from ..models import ExecutionResult, TestCase
from .base import Adapter, Target, run_script

_ARG = re.compile(r"#\{([^}]+)\}")


class AtomicAdapter(Adapter):
    def __init__(self, atomic_dir: Path):
        self.atomic_dir = atomic_dir

    def _load(self, platform: str, technique: str) -> list[dict]:
        path = self.atomic_dir / platform / technique / f"{technique}.yaml"
        if not path.exists():
            raise FileNotFoundError(f"atomic definition not found: {path}")
        return (yaml.safe_load(path.read_text(encoding="utf-8")) or {}).get("atomic_tests", [])

    @staticmethod
    def _pick(tests: list[dict], selector) -> dict:
        if isinstance(selector, int) or str(selector).isdigit():
            idx = int(selector) - 1
            if not 0 <= idx < len(tests):
                raise IndexError(f"atomic test #{selector} out of range (1..{len(tests)})")
            return tests[idx]
        for t in tests:
            if t.get("auto_generated_guid") == selector:
                return t
        raise KeyError(f"atomic test GUID {selector} not found")

    @staticmethod
    def _render(text: str, defaults: dict | None, overrides: dict | None) -> str:
        values = {k: str((v or {}).get("default", "")) for k, v in (defaults or {}).items()}
        values.update({k: str(v) for k, v in (overrides or {}).items()})
        return _ARG.sub(lambda m: values.get(m.group(1), m.group(0)), text)

    def run(self, test: TestCase, target: Target) -> ExecutionResult:
        sim = test.simulation
        technique = sim.get("technique", test.technique)
        atomic = self._pick(self._load(test.platform, technique), sim.get("test", 1))
        ex = atomic["executor"]
        interp, args = ex["name"], sim.get("args", {})
        defaults = atomic.get("input_arguments")
        timeout = int(sim.get("timeout", 300))
        try:
            return run_script(target, interp, self._render(ex["command"], defaults, args),
                              timeout=timeout, allow_nonzero=bool(sim.get("allow_nonzero", False)))
        finally:
            if ex.get("cleanup_command"):
                run_script(target, interp, self._render(ex["cleanup_command"], defaults, args),
                           timeout=timeout, allow_nonzero=True)
