from __future__ import annotations

import json
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Callable

import yaml

from .adapters.base import Adapter, Target
from .collectors.wazuh_alerts import AlertCollector
from .evaluation.evaluator import evaluate
from .evaluation.matcher import satisfied
from .models import ExecutionResult, TestCase, TestResult, Verdict


def load_catalog(directory: Path) -> list[TestCase]:
    """Each YAML file holds one test mapping or a `tests:` list."""
    tests, seen = [], set()
    for path in sorted(Path(directory).rglob("*.y*ml")):
        doc = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        for item in (doc["tests"] if "tests" in doc else [doc]):
            t = TestCase.from_dict(item, path)
            if t.id in seen:
                raise ValueError(f"duplicate test id {t.id} ({path})")
            seen.add(t.id)
            tests.append(t)
    return tests


def select(tests, ids=None, platform=None, technique=None, tag=None, source=None):
    return [t for t in tests
            if (not ids or t.id in ids) and (not platform or t.platform == platform)
            and (not technique or t.technique.startswith(technique)) and (not tag or tag in t.tags)
            and (not source or t.source == source)]


class Orchestrator:
    def __init__(self, settings: dict, targets: dict[str, Target], adapters: dict[str, Adapter],
                 collector: AlertCollector, repo, evidence_dir: Path,
                 sleep: Callable[[float], None] = time.sleep):
        self.cfg = settings["evaluation"]
        self.targets, self.adapters, self.collector = targets, adapters, collector
        self.repo, self.evidence_dir, self.sleep = repo, Path(evidence_dir), sleep
        self.catalog_loader = load_catalog

    def load_catalog(self, directory: Path) -> list[TestCase]:
        return self.catalog_loader(directory)

    def _error(self, test: TestCase, msg: str, execution: ExecutionResult | None = None) -> TestResult:
        return TestResult(test, Verdict.ERROR, execution, error=msg)

    def run_test(self, test: TestCase) -> TestResult:
        target = self.targets.get(test.target)
        adapter = self.adapters.get(test.source)
        if target is None:
            return self._error(test, f"unknown target '{test.target}'")
        if adapter is None:
            return self._error(test, f"no adapter for source '{test.source}'")
        try:
            execution = adapter.run(test, target)
        except Exception as exc:
            return self._error(test, f"{type(exc).__name__}: {exc}")
        if not execution.success:
            return self._error(test, execution.error or "simulation failed", execution)

        skew = timedelta(seconds=self.cfg.get("clock_skew_seconds", 5))
        timeout = test.expected.timeout_seconds or self.cfg.get("default_timeout_seconds", 120)
        deadline = time.monotonic() + timeout
        alerts: list = []
        while True:
            try:
                alerts = self.collector.fetch(target.agent_name, execution.started_at - skew,
                                              datetime.now(timezone.utc) + skew)
            except Exception as exc:
                return self._error(test, f"alert collection failed: {exc}", execution)
            # positives stop as soon as they match; negatives must stay quiet for the whole window
            if (not test.negative and satisfied(alerts, test.expected)) or time.monotonic() >= deadline:
                break
            self.sleep(self.cfg.get("poll_interval_seconds", 5))
        return evaluate(test, execution, alerts)

    def _write_evidence(self, run_id: int, result: TestResult) -> None:
        d = self.evidence_dir / f"run-{run_id}"
        d.mkdir(parents=True, exist_ok=True)
        ex = result.execution
        doc = {
            "test_id": result.test.id, "verdict": result.verdict.value, "error": result.error,
            "execution": None if ex is None else {
                "started_at": ex.started_at.isoformat(), "finished_at": ex.finished_at.isoformat(),
                "exit_code": ex.exit_code, "stdout": ex.stdout[-4000:], "stderr": ex.stderr[-4000:]},
            "matched_alerts": [a.raw for a in result.matched_alerts],
            "window_alerts": [a.raw for a in result.all_alerts[:200]],
        }
        (d / f"{result.test.id}.json").write_text(json.dumps(doc, indent=2, default=str), encoding="utf-8")

    def run(self, tests: list[TestCase], label: str | None = None, progress=print) -> int:
        run_id = self.repo.create_run(label)
        for i, test in enumerate(tests, 1):
            result = self.run_test(test)
            self.repo.save_result(run_id, result.to_row())
            self._write_evidence(run_id, result)
            progress(f"[{i}/{len(tests)}] {test.id:<22} {result.verdict.value:<5} {result.error or ''}")
        self.repo.finish_run(run_id)
        return run_id
