"""Session-start pipeline canary.

A run's verdicts are only meaningful when the lab pipeline (simulation -> agent -> manager ->
indexer) is delivering alerts at all. The canary executes one benign trigger that a built-in Wazuh
rule detects, then looks for that alert through the same collector the tests use.

Failure - no alert within the timeout, a truncated collection, or a trigger that cannot run - makes
the run INCONCLUSIVE and writes no test verdicts: an empty window is not a detection gap. When the
manager's alert log is readable, the canary is also reconciled manager-to-indexer so a pipeline that
records alerts but does not index them is reported as such.
"""
from __future__ import annotations

import json
import time
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path

from .adapters.base import Target, run_script
from .collectors.wazuh_alerts import parse_ts
from .evaluation.matcher import alert_matches
from .models import ExecutionResult, Expected, TestCase
from .safety import SafetyPolicy, blocked_reason

STATUS_OK = "ok"
STATUS_FAILED = "failed"
STATUS_SKIPPED = "skipped"


@dataclass(frozen=True)
class CanaryOutcome:
    status: str
    detail: str
    indexer_alerts: int = 0
    manager_alerts: int | None = None  # None: reconciliation not configured or not readable

    @property
    def failed(self) -> bool:
        return self.status == STATUS_FAILED


def manager_canary_alerts(path: str | Path, agent_name: str, expected: Expected,
                          since: datetime, until: datetime) -> int | None:
    """Count expected canary alerts in the manager's alerts.json (NDJSON).

    Returns None when the file is not configured or not readable: the caller then reports that
    reconciliation was skipped instead of pretending the pipeline was checked end to end.
    """
    if not path:
        return None
    log = Path(path)
    if not log.is_file():
        return None
    count = 0
    try:
        with open(log, encoding="utf-8", errors="replace") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    doc = json.loads(line)
                except ValueError:
                    continue
                if (doc.get("agent") or {}).get("name") != agent_name:
                    continue
                try:
                    ts = parse_ts(doc["timestamp"])
                except (KeyError, TypeError, ValueError):
                    continue
                if not since <= ts <= until:
                    continue
                rule_id = str((doc.get("rule") or {}).get("id", ""))
                if rule_id and rule_id in expected.rule_ids:
                    count += 1
    except OSError:
        return None
    return count


class PipelineCanary:
    def __init__(self, settings: dict, targets: dict[str, Target], collector, policy: SafetyPolicy,
                 custom_dir: str | Path, trigger: Callable | None = None,
                 sleep: Callable[[float], None] = time.sleep,
                 monotonic: Callable[[], float] = time.monotonic,
                 enabled: bool | None = None, disabled_detail: str | None = None):
        self.settings = settings or {}
        self.cfg = self.settings.get("canary") or {}
        self.targets, self.collector, self.policy = targets, collector, policy
        self.custom_dir = Path(custom_dir)
        self.enabled = bool(self.cfg.get("enabled", True)) if enabled is None else bool(enabled)
        self.disabled_detail = disabled_detail
        self.target_name = str(self.cfg.get("target", "lab-linux-01"))
        self.expected = Expected(rule_ids=[str(r) for r in self.cfg.get("expected_rule_ids") or []])
        self.timeout = int(self.cfg.get("timeout_seconds", 120))
        self.poll = float(self.cfg.get("poll_interval_seconds", 5))
        self.grace = float(self.cfg.get("reconcile_grace_seconds", 30))
        self.manager_path = str(self.cfg.get("manager_alert_file") or "")
        self.script = str(self.cfg.get("trigger_script", "canary/pipeline_canary.sh"))
        self.trigger = trigger or self._default_trigger
        self.sleep, self.monotonic = sleep, monotonic
        ev = self.settings.get("evaluation") or {}
        self.skew = timedelta(seconds=float(ev.get("clock_skew_seconds", 5)))

    def check(self) -> CanaryOutcome:
        if not self.enabled:
            return CanaryOutcome(STATUS_SKIPPED,
                                 self.disabled_detail or "disabled in framework/config/settings.yaml")
        if not self.expected.rule_ids:
            return CanaryOutcome(STATUS_FAILED, "canary.expected_rule_ids is empty; nothing to verify")
        target = self.targets.get(self.target_name)
        if target is None:
            return CanaryOutcome(STATUS_FAILED,
                                 f"canary target {self.target_name!r} is not in environments.yaml")
        if target.platform != "linux":
            return CanaryOutcome(STATUS_FAILED,
                                 f"canary trigger is a bash script but target {self.target_name!r} "
                                 f"is {target.platform}")
        test = TestCase("CANARY", "pipeline canary", "T1078", "linux", "custom", self.target_name,
                        self.expected, risk="low")
        blocked = blocked_reason(test, self.targets, self.policy)
        if blocked:
            return CanaryOutcome(STATUS_FAILED, f"canary blocked: {blocked}")

        try:
            execution = self.trigger(test, target)
        except Exception as exc:  # a broken trigger is a pipeline problem, not a detection miss
            return CanaryOutcome(STATUS_FAILED,
                                 f"canary trigger failed to start: {type(exc).__name__}: {exc}")
        if not execution.success:
            detail = execution.error or "failed"
            return CanaryOutcome(STATUS_FAILED, f"canary trigger {execution.status}: {detail}")

        since = execution.started_at - self.skew
        started = self.monotonic()
        deadline = started + self.timeout
        indexer, manager = 0, None
        while True:
            indexer, manager, error = self._observe(since, target.agent_name)
            if error:
                return CanaryOutcome(STATUS_FAILED, error, indexer, manager)
            if indexer:
                return CanaryOutcome(STATUS_OK, self._detail(started, indexer, manager),
                                     indexer, manager)
            if self.monotonic() >= deadline:
                break
            self.sleep(self.poll)

        # The manager may have processed the alert before the indexer stored it: wait once, then
        # only call the pipeline broken if the alert still never appears in the indexer.
        if manager:
            self.sleep(self.grace)
            indexer, manager, error = self._observe(since, target.agent_name)
            if error:
                return CanaryOutcome(STATUS_FAILED, error, indexer, manager)
            if indexer:
                return CanaryOutcome(
                    STATUS_OK, self._detail(started, indexer, manager) + " after reconciliation grace",
                    indexer, manager)

        return CanaryOutcome(STATUS_FAILED, self._failure(started, indexer, manager),
                             indexer, manager)

    def _observe(self, since: datetime, agent_name: str) -> tuple[int, int | None, str | None]:
        """One indexer read plus, when available, the manager-side count for the same window."""
        until = datetime.now(timezone.utc) + self.skew
        try:
            batch = self.collector.fetch(agent_name, since, until)
        except Exception as exc:
            return 0, None, f"canary alert collection failed: {type(exc).__name__}: {exc}"
        if batch.truncated:
            return 0, None, f"canary alert collection truncated: {batch.reason}"
        indexer = sum(1 for a in batch.alerts if alert_matches(a, self.expected))
        manager = manager_canary_alerts(self.manager_path, agent_name, self.expected, since, until)
        return indexer, manager, None

    def _default_trigger(self, test: TestCase, target: Target) -> ExecutionResult:
        script = (self.custom_dir / self.script).resolve()
        if self.custom_dir.resolve() not in script.parents:
            raise ValueError("canary.trigger_script must live inside custom-simulations/")
        return run_script(target, "bash", script.read_text(encoding="utf-8"), [],
                          timeout=self.timeout)

    def _detail(self, started: float, indexer: int, manager: int | None) -> str:
        rules = ", ".join(self.expected.rule_ids)
        side = f"indexer={indexer}" + (f", manager={manager}" if manager is not None else "")
        return f"canary rule {rules} observed after {round(self.monotonic() - started, 1)}s ({side})"

    def _failure(self, started: float, indexer: int, manager: int | None) -> str:
        rules = ", ".join(self.expected.rule_ids)
        elapsed = round(self.monotonic() - started, 1)
        if manager:
            return (f"manager alert file recorded {manager} canary alert(s) for rule {rules}, but the "
                    f"indexer returned {indexer} after {elapsed}s plus a {self.grace:g}s reconciliation "
                    "grace; the manager->indexer pipeline is not delivering alerts")
        if manager is None:
            return (f"canary rule {rules} was not observed in the indexer within {elapsed}s and "
                    "manager->indexer reconciliation is unavailable (canary.manager_alert_file is "
                    "empty or unreadable)")
        return (f"canary rule {rules} was not observed in the indexer or the manager alert file within "
                f"{elapsed}s; the trigger may not produce that rule with this Wazuh/agent configuration")
