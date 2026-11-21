from datetime import datetime, timedelta, timezone

import pytest

from validator.collectors.wazuh_alerts import parse_alert
from validator.evaluation.evaluator import evaluate
from validator.evaluation.matcher import alert_matches
from validator.evaluation.metrics import compute_metrics
from validator.models import ExecutionResult, Expected, TestCase, Verdict
from validator.regression.comparator import compare

T0 = datetime(2026, 1, 1, 10, 0, 0, tzinfo=timezone.utc)


def mk_alert(rule_id="5712", level=10, groups=("sshd",), mitre=("T1110",), dt=10):
    return parse_alert({"id": "x", "timestamp": (T0 + timedelta(seconds=dt)).strftime("%Y-%m-%dT%H:%M:%S.000+0000"),
                        "rule": {"id": rule_id, "level": level, "groups": list(groups), "mitre": {"id": list(mitre)}},
                        "agent": {"name": "a"}})


def mk_test(negative=False, **exp):
    return TestCase("t1", "n", "T1110", "linux", "custom", "a",
                    Expected(**(exp or {"rule_ids": ["5712"]})), negative=negative)


def ex(ok=True):
    return ExecutionResult(T0, T0 + timedelta(seconds=5), ok, 0 if ok else 1, error=None if ok else "boom")


def test_timestamp_parsing_wazuh_format():
    assert mk_alert(dt=0).timestamp == T0


def test_matcher_criteria():
    a = mk_alert()
    assert alert_matches(a, Expected(rule_ids=["5712"]))
    assert not alert_matches(a, Expected(rule_ids=["1"]))
    assert alert_matches(a, Expected(rule_groups=["sshd"], min_level=10))
    assert not alert_matches(a, Expected(rule_groups=["sshd"], min_level=11))
    assert alert_matches(a, Expected(mitre_ids=["T1110"]))


@pytest.mark.parametrize("negative,alerts,verdict", [
    (False, [mk_alert()], Verdict.TP), (False, [], Verdict.FN),
    (True, [mk_alert()], Verdict.FP), (True, [], Verdict.TN)])
def test_verdicts(negative, alerts, verdict):
    assert evaluate(mk_test(negative), ex(), alerts).verdict == verdict


def test_latency_and_error():
    assert evaluate(mk_test(), ex(), [mk_alert(dt=12)]).latency_seconds == 12
    assert evaluate(mk_test(), ex(False), []).verdict == Verdict.ERROR


def test_positive_test_requires_expectation():
    with pytest.raises(ValueError):
        TestCase.from_dict({"id": "x", "name": "n", "technique": "T1", "platform": "linux",
                            "source": "custom", "target": "t"})


def test_metrics():
    rows = [{"verdict": v, "technique": "T1", "latency_seconds": 4.0 if v == "TP" else None}
            for v in ["TP", "TP", "FN", "TN", "FP"]]
    m = compute_metrics(rows)
    assert m["detection_rate"] == round(2 / 3, 4) and m["precision"] == round(2 / 3, 4)
    assert m["false_positive_rate"] == 0.5 and m["mean_time_to_detect_s"] == 4.0


def test_regression_compare():
    base = [{"test_id": "a", "verdict": "TP"}, {"test_id": "b", "verdict": "FN"}, {"test_id": "c", "verdict": "TN"}]
    cur = [{"test_id": "a", "verdict": "FN"}, {"test_id": "b", "verdict": "TP"}, {"test_id": "d", "verdict": "TP"}]
    r = compare(base, cur)
    assert [x["test_id"] for x in r.regressions] == ["a"] and [x["test_id"] for x in r.improvements] == ["b"]
    assert r.new_tests == ["d"] and r.missing_tests == ["c"] and r.has_regressions


def test_require_all():
    t = TestCase("m", "m", "MARKER", "linux", "custom", "a",
                 Expected(rule_ids=["100100", "100101"], require_all=True))
    partial = evaluate(t, ex(), [mk_alert("100100", dt=3)])
    assert partial.verdict == Verdict.FN and "100101" in partial.error
    both = evaluate(t, ex(), [mk_alert("100100", dt=3), mk_alert("100101", dt=9)])
    assert both.verdict == Verdict.TP and both.latency_seconds == 9  # last required rule decides latency
    with pytest.raises(ValueError):
        TestCase.from_dict({"id": "x", "name": "n", "technique": "M", "platform": "linux", "source": "custom",
                            "target": "t", "expected": {"rule_ids": ["1"], "require_all": True}})
