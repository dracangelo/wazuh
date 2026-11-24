from __future__ import annotations

from dataclasses import replace

from ..models import ExecutionResult, TestCase, TestResult, Verdict
from .matcher import filter_matches, missing_rules, satisfied


def evaluate(test: TestCase, execution: ExecutionResult, alerts: list) -> TestResult:
    if not execution.success:
        return TestResult(test, Verdict.ERROR, execution, all_alerts=alerts,
                          error=execution.error or "simulation failed")
    exp, exec_id = test.expected, execution.exec_id
    if exp.correlation == "exec_id" and not exec_id:
        return TestResult(test, Verdict.ERROR, execution, all_alerts=alerts,
                          error="correlation exec_id requested but the execution has no id")
    matched = filter_matches(alerts, exp, exec_id)
    ok = satisfied(alerts, exp, exec_id)
    # Alerts that satisfy every criterion except the execution id: kept for investigation, never scored.
    uncorrelated = []
    if exp.correlation == "exec_id":
        loose = filter_matches(alerts, replace(exp, correlation="window"))
        uncorrelated = [a for a in loose if all(a is not m for m in matched)]
    latency, note = None, None
    if matched:
        if exp.require_all and ok:
            # time until the LAST required rule was first seen
            firsts = [min(a.timestamp for a in matched if a.rule_id == r) for r in exp.rule_ids]
            first = max(firsts)
        else:
            first = min(a.timestamp for a in matched)
        latency = max(0.0, (first - execution.started_at).total_seconds())
    if test.negative:
        verdict = Verdict.FP if matched else Verdict.TN
    else:
        verdict = Verdict.TP if ok else Verdict.FN
        if not ok and matched:
            note = f"partial: missing rules {missing_rules(alerts, exp, exec_id)}"
    if uncorrelated and verdict in (Verdict.FN, Verdict.TN):
        extra = (f"{len(uncorrelated)} alert(s) matched the rule but not execution id {exec_id}; "
                 "not counted")
        note = f"{note}; {extra}" if note else extra
    return TestResult(test, verdict, execution, matched, alerts, latency, error=note,
                      uncorrelated_alerts=uncorrelated)
