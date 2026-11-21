from __future__ import annotations

from ..models import ExecutionResult, TestCase, TestResult, Verdict
from .matcher import filter_matches, missing_rules, satisfied


def evaluate(test: TestCase, execution: ExecutionResult, alerts: list) -> TestResult:
    if not execution.success:
        return TestResult(test, Verdict.ERROR, execution, all_alerts=alerts,
                          error=execution.error or "simulation failed")
    matched = filter_matches(alerts, test.expected)
    ok = satisfied(alerts, test.expected)
    latency, note = None, None
    if matched:
        if test.expected.require_all and ok:
            # time until the LAST required rule was first seen
            firsts = [min(a.timestamp for a in matched if a.rule_id == r) for r in test.expected.rule_ids]
            first = max(firsts)
        else:
            first = min(a.timestamp for a in matched)
        latency = max(0.0, (first - execution.started_at).total_seconds())
    if test.negative:
        verdict = Verdict.FP if matched else Verdict.TN
    else:
        verdict = Verdict.TP if ok else Verdict.FN
        if not ok and matched:
            note = f"partial: missing rules {missing_rules(alerts, test.expected)}"
    return TestResult(test, verdict, execution, matched, alerts, latency, error=note)
