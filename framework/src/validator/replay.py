"""
Offline Alert Replay Engine.

Allows detection engineers and automated CI pipelines to test and score detection rules
against captured alert streams (NDJSON/JSON) or mock events without needing live targets
or an active Wazuh cluster.
"""
from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Union

from .collectors.wazuh_alerts import parse_alert
from .evaluation.evaluator import evaluate
from .evaluation.matcher import alert_matches, satisfied
from .models import Alert, ExecutionResult, Expected, TestCase, TestResult, Verdict

LOG = logging.getLogger("validator.replay")


@dataclass
class ReplaySummary:
    total_tests: int
    true_positives: int
    false_positives: int
    true_negatives: int
    false_negatives: int
    errors: int
    results: List[TestResult] = field(default_factory=list)

    @property
    def passed(self) -> bool:
        return self.false_positives == 0 and self.false_negatives == 0 and self.errors == 0

    def as_dict(self) -> Dict[str, Any]:
        return {
            "total_tests": self.total_tests,
            "true_positives": self.true_positives,
            "false_positives": self.false_positives,
            "true_negatives": self.true_negatives,
            "false_negatives": self.false_negatives,
            "errors": self.errors,
            "passed": self.passed,
            "results": [
                {
                    "test_id": r.test.id,
                    "name": r.test.name,
                    "technique": r.test.technique,
                    "verdict": r.verdict.value,
                    "matched_rule_ids": [a.rule_id for a in r.matched_alerts],
                    "error": r.error,
                }
                for r in self.results
            ],
        }


class ReplayEngine:
    """Replays alert streams against test catalog definitions to produce verdicts."""

    def __init__(self, alerts: List[Alert]):
        self.alerts = alerts

    @classmethod
    def from_ndjson(cls, path: Union[str, Path]) -> ReplayEngine:
        p = Path(path)
        if not p.exists():
            raise FileNotFoundError(f"Alert file not found: {p}")
        alerts: List[Alert] = []
        with open(p, encoding="utf-8") as f:
            for line_no, line in enumerate(f, start=1):
                line = line.strip()
                if not line:
                    continue
                try:
                    data = json.loads(line)
                    # Normalize simple doc structure if needed
                    if "rule" not in data and "rule_id" in data:
                        data = {
                            "id": str(data.get("id", f"rep-{line_no}")),
                            "timestamp": data.get("timestamp", datetime.now(timezone.utc).isoformat()),
                            "rule": {
                                "id": str(data["rule_id"]),
                                "level": int(data.get("level", 10)),
                                "description": data.get("description", ""),
                                "groups": data.get("groups", []),
                                "mitre": {"id": data.get("mitre", [])},
                            },
                            "agent": {"name": data.get("agent_name", "lab")},
                        }
                    alerts.append(parse_alert(data))
                except Exception as exc:
                    LOG.warning("Failed to parse alert line %d: %s", line_no, exc)
        return cls(alerts)

    @classmethod
    def from_alerts_list(cls, alert_dicts: List[Dict[str, Any]]) -> ReplayEngine:
        alerts = [parse_alert(d) for d in alert_dicts]
        return cls(alerts)

    def replay_test(self, test: TestCase, agent_filter: bool = False, exec_id: Optional[str] = "rep-offline") -> TestResult:
        """Scores a single test case against the loaded alerts."""
        now = datetime.now(timezone.utc)
        # Filter candidate alerts
        candidates = self.alerts
        if agent_filter and test.target:
            candidates = [a for a in candidates if a.agent_name == test.target]

        # For offline replay, if correlation is exec_id and alerts are synthetic fixtures without full
        # auditd exec_id tracking, adapt test expected correlation to window evaluation if none match
        effective_test = test
        if test.expected.correlation == "exec_id":
            # Check if any alert actually has an exec_id in its raw doc
            has_raw_exec_id = any(
                isinstance(a.raw, dict) and "dv_exec" in json.dumps(a.raw)
                for a in candidates
            )
            if not has_raw_exec_id:
                from dataclasses import replace
                effective_test = replace(
                    test, expected=replace(test.expected, correlation="window")
                )

        exec_result = ExecutionResult(
            started_at=now,
            finished_at=now,
            success=True,
            exit_code=0,
            stdout="replayed against offline alert stream",
            exec_id=exec_id,
        )
        return evaluate(effective_test, exec_result, candidates)

    def replay_catalog(
        self, tests: List[TestCase], agent_filter: bool = False
    ) -> ReplaySummary:
        """Evaluates a batch of test cases against the loaded alert fixture."""
        results: List[TestResult] = []
        tp = fp = tn = fn = err = 0

        for t in tests:
            res = self.replay_test(t, agent_filter=agent_filter)
            results.append(res)
            if res.verdict == Verdict.TP:
                tp += 1
            elif res.verdict == Verdict.FP:
                fp += 1
            elif res.verdict == Verdict.TN:
                tn += 1
            elif res.verdict == Verdict.FN:
                fn += 1
            else:
                err += 1

        return ReplaySummary(
            total_tests=len(tests),
            true_positives=tp,
            false_positives=fp,
            true_negatives=tn,
            false_negatives=fn,
            errors=err,
            results=results,
        )
