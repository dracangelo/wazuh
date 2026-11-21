from __future__ import annotations

import json
import logging
import time
from collections.abc import Callable
from datetime import datetime, timedelta, timezone
from pathlib import Path

import yaml

from .adapters.base import Adapter, Target
from .collectors.wazuh_alerts import AlertCollector
from .evaluation.evaluator import evaluate
from .evaluation.matcher import satisfied
from .models import ExecutionResult, TestCase, TestResult, Verdict
from .safety import SafetyPolicy, blocked_reason

LOG = logging.getLogger("validator.orchestrator")


def load_catalog(directory: Path) -> list[TestCase]:
    """Each YAML file holds one test mapping or a `tests:` list."""
    tests, seen = [], set()
    for path in sorted(Path(directory).rglob("*.y*ml")):
        doc = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        for item in doc.get("tests", [doc]):
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
                 sleep: Callable[[float], None] = time.sleep, policy: SafetyPolicy | None = None):
        self.cfg = settings.get("evaluation", {})
        self.targets, self.adapters, self.collector = targets, adapters, collector
        self.repo, self.evidence_dir, self.sleep = repo, Path(evidence_dir), sleep
        self.policy = policy if policy is not None else SafetyPolicy()

    def blocked_reason(self, test: TestCase) -> str | None:
        return blocked_reason(test, self.targets, self.policy)

    def _error(self, test: TestCase, msg: str, execution: ExecutionResult | None = None) -> TestResult:
        return TestResult(test, Verdict.ERROR, execution, error=msg)

    def run_test(self, test: TestCase) -> TestResult:
        target = self.targets.get(test.target)
        adapter = self.adapters.get(test.source)
        # Re-check centrally even though run() preflights: no execution path skips the gate.
        blocked = self.blocked_reason(test)
        if blocked:
            LOG.warning("blocked test=%s reason=%s", test.id, blocked)
            return self._error(test, blocked)
        if adapter is None:
            return self._error(test, f"no adapter for source '{test.source}'")
        try:
            execution = adapter.run(test, target)
        except Exception as exc:  # an adapter bug must never look like a detection miss
            LOG.exception("adapter failure test=%s", test.id)
            return self._error(test, f"{type(exc).__name__}: {exc}")
        if not execution.success:
            detail = execution.error or "simulation failed"
            return self._error(test, f"{execution.status}: {detail}", execution)

        skew = timedelta(seconds=self.cfg.get("clock_skew_seconds", 5))
        timeout = test.expected.timeout_seconds or self.cfg.get("default_timeout_seconds", 120)
        deadline = time.monotonic() + timeout
        alerts: list = []
        while True:
            try:
                batch = self.collector.fetch(target.agent_name, execution.started_at - skew,
                                             datetime.now(timezone.utc) + skew)
            except Exception as exc:
                return self._error(test, f"alert collection failed: {exc}", execution)
            if batch.truncated:
                # A capped window may be missing the alert that was never evaluated: never score it.
                return self._error(test, f"alert collection truncated: {batch.reason}", execution)
            alerts = batch.alerts
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
            "run_id": run_id,
            "test_id": result.test.id,
            "target": result.test.target,
            "risk": result.test.risk,
            "verdict": result.verdict.value,
            "error": result.error,
            "execution": None if ex is None else {
                "status": ex.status,
                "started_at": ex.started_at.isoformat(), "finished_at": ex.finished_at.isoformat(),
                "duration_seconds": round(ex.duration_seconds, 3),
                "exit_code": ex.exit_code, "stdout": ex.stdout[-4000:], "stderr": ex.stderr[-4000:]},
            "matched_alerts": [a.raw for a in result.matched_alerts],
            "window_alerts": [a.raw for a in result.all_alerts[:200]],
        }
        (d / f"{result.test.id}.json").write_text(json.dumps(doc, indent=2, default=str), encoding="utf-8")

    def run(self, tests: list[TestCase], label: str | None = None, progress=print) -> int:
        # Preflight every test first so an unsafe target stops the run before any command executes.
        blocked = {t.id: reason for t in tests if (reason := self.blocked_reason(t))}
        run_id = self.repo.create_run(label)
        for i, test in enumerate(tests, 1):
            result = self._error(test, blocked[test.id]) if test.id in blocked else self.run_test(test)
            self.repo.save_result(run_id, result.to_row())
            self._write_evidence(run_id, result)
            progress(f"[{i}/{len(tests)}] {test.id:<22} {result.verdict.value:<5} {result.error or ''}")
        self.repo.finish_run(run_id)
        return run_id
