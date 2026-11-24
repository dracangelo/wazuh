from __future__ import annotations

import hashlib
import json
import logging
import os
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
                 sleep: Callable[[float], None] = time.sleep, policy: SafetyPolicy | None = None,
                 canary=None, run_meta: dict | None = None):
        self.run_meta = run_meta
        self.cfg = settings.get("evaluation", {})
        self.targets, self.adapters, self.collector = targets, adapters, collector
        self.repo, self.evidence_dir, self.sleep = repo, Path(evidence_dir), sleep
        self.policy = policy if policy is not None else SafetyPolicy()
        self.canary = canary
        self._claimed: set[str] = set()  # alert ids already used as proof by an earlier test in this run

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

        exp = test.expected
        if exp.correlation == "exec_id" and not execution.exec_id:
            return self._error(test, "correlation exec_id requested but the adapter returned no execution id",
                               execution)
        skew = timedelta(seconds=self.cfg.get("clock_skew_seconds", 5))
        timeout = test.expected.timeout_seconds or self.cfg.get("default_timeout_seconds", 120)
        deadline = time.monotonic() + timeout
        alerts: list = []
        collection: dict | None = None
        while True:
            try:
                batch = self.collector.fetch(target.agent_name, execution.started_at - skew,
                                             datetime.now(timezone.utc) + skew)
            except Exception as exc:
                return self._error(test, f"alert collection failed: {exc}", execution)
            if batch.truncated:
                # A capped window may be missing the alert that was never evaluated: never score it.
                err = self._error(test, f"alert collection truncated: {batch.reason}", execution)
                err.collection = {"pages_fetched": batch.pages_fetched, "alerts_retrieved": len(batch.alerts),
                                  "max_alerts": batch.max_alerts, "truncated": True, "complete": False}
                return err
            alerts = batch.alerts
            excluded = 0
            if not exp.shared_evidence:
                # one alert can prove only one test, unless the catalog says evidence is shared
                kept = [a for a in alerts if not (a.id and a.id in self._claimed)]
                excluded, alerts = len(alerts) - len(kept), kept
            collection = {"pages_fetched": batch.pages_fetched, "alerts_retrieved": len(batch.alerts),
                          "max_alerts": batch.max_alerts, "truncated": False, "complete": True,
                          "correlation": exp.correlation, "claimed_alerts_excluded": excluded}
            # positives stop as soon as they match; negatives must stay quiet for the whole window
            if (not test.negative and satisfied(alerts, exp, execution.exec_id)) or time.monotonic() >= deadline:
                break
            self.sleep(self.cfg.get("poll_interval_seconds", 5))
        result = evaluate(test, execution, alerts)
        result.collection = collection
        if result.verdict == Verdict.TP and not exp.shared_evidence:
            self._claimed.update(a.id for a in result.matched_alerts if a.id)
        return result

    def _write_evidence(self, run_id: int, result: TestResult) -> str:
        """Write one evidence file (0600, in a 0700 directory) and record its SHA-256 in the run
        manifest so later modification is detectable. Returns the digest."""
        d = self.evidence_dir / f"run-{run_id}"
        d.mkdir(parents=True, exist_ok=True)
        os.chmod(d, 0o700)
        ex = result.execution
        doc = {
            "run_id": run_id,
            "test_id": result.test.id,
            "exec_id": None if ex is None else ex.exec_id,
            "target": result.test.target,
            "risk": result.test.risk,
            "verdict": result.verdict.value,
            "error": result.error,
            "expected": {
                "rule_ids": result.test.expected.rule_ids, "rule_groups": result.test.expected.rule_groups,
                "mitre_ids": result.test.expected.mitre_ids, "min_level": result.test.expected.min_level,
                "require_all": result.test.expected.require_all, "negative": result.test.negative,
                "shared_evidence": result.test.expected.shared_evidence,
            },
            "collection": result.collection,
            "correlation": result.test.expected.correlation,
            "weak_correlation": result.test.expected.correlation == "window",
            "uncorrelated_matches": [a.raw for a in result.uncorrelated_alerts[:50]],
            "execution": None if ex is None else {
                "status": ex.status,
                "started_at": ex.started_at.isoformat(), "finished_at": ex.finished_at.isoformat(),
                "duration_seconds": round(ex.duration_seconds, 3),
                "exit_code": ex.exit_code, "stdout": ex.stdout[-4000:], "stderr": ex.stderr[-4000:]},
            "matched_alerts": [a.raw for a in result.matched_alerts],
            "window_alerts": [a.raw for a in result.all_alerts[:200]],
        }
        path = d / f"{result.test.id}.json"
        data = json.dumps(doc, indent=2, default=str).encode("utf-8")
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "wb") as fh:
            fh.write(data)
        digest = hashlib.sha256(data).hexdigest()
        manifest_path = d / "manifest.json"
        try:
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            manifest = {}
        manifest[path.name] = {"sha256": digest, "test_id": result.test.id,
                               "exec_id": doc["exec_id"], "verdict": doc["verdict"]}
        fd = os.open(manifest_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            json.dump(manifest, fh, indent=2, sort_keys=True)
        return digest

    def run(self, tests: list[TestCase], label: str | None = None, progress=print) -> int:
        # Preflight every test first so an unsafe target stops the run before any command executes.
        self._claimed = set()
        blocked = {t.id: reason for t in tests if (reason := self.blocked_reason(t))}
        run_id = self.repo.create_run(label, meta=self.run_meta)
        canary_status = canary_detail = None
        if self.canary is not None:
            outcome = self.canary.check()
            canary_status, canary_detail = outcome.status, outcome.detail
            if outcome.failed:
                # A known-good alert never arrived: every verdict in this window would be
                # untrustworthy, so the run is inconclusive and no results (especially FNs) exist.
                self.repo.finish_run(run_id, status="inconclusive",
                                     canary_status=canary_status, canary_detail=canary_detail)
                progress(f"run {run_id} INCONCLUSIVE: pipeline canary failed - {canary_detail}")
                return run_id
            progress(f"canary {canary_status}: {canary_detail}")
        done = 0
        try:
            for i, test in enumerate(tests, 1):
                result = self._error(test, blocked[test.id]) if test.id in blocked else self.run_test(test)
                self.repo.save_result(run_id, result.to_row())
                self._write_evidence(run_id, result)
                done = i
                progress(f"[{i}/{len(tests)}] {test.id:<22} {result.verdict.value:<5} {result.error or ''}")
        except BaseException as exc:
            # Never leave a run looking 'running' or complete: a partial run is its own status.
            status = "interrupted" if isinstance(exc, KeyboardInterrupt) else "failed"
            self.repo.finish_run(run_id, status=status, canary_status=canary_status,
                                 canary_detail=canary_detail)
            progress(f"run {run_id} {status.upper()} after {done}/{len(tests)} tests: "
                     f"{type(exc).__name__}: {exc}")
            raise
        self.repo.finish_run(run_id, canary_status=canary_status, canary_detail=canary_detail)
        return run_id
