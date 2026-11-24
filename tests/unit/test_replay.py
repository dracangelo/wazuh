"""Unit tests for the offline Alert Replay Engine."""
import json
from pathlib import Path

from validator.models import Expected, TestCase, Verdict
from validator.replay import ReplayEngine

SAMPLE_ALERTS = [
    {
        "id": "1",
        "timestamp": "2026-01-01T10:00:10.000+0000",
        "rule": {
            "id": "100401",
            "level": 10,
            "description": "Binary executed from /tmp",
            "groups": ["execution"],
            "mitre": {"id": ["T1059.004"]},
        },
        "agent": {"name": "lab-linux-01"},
    },
    {
        "id": "2",
        "timestamp": "2026-01-01T10:00:20.000+0000",
        "rule": {
            "id": "100856",
            "level": 8,
            "description": "Encoded PowerShell",
            "groups": ["windows"],
            "mitre": {"id": ["T1059.001"]},
        },
        "agent": {"name": "lab-win-01"},
    },
]


def test_replay_engine_from_list():
    engine = ReplayEngine.from_alerts_list(SAMPLE_ALERTS)
    assert len(engine.alerts) == 2

    test_pos = TestCase(
        "T-POS",
        "Temp exec test",
        "T1059.004",
        "linux",
        "custom",
        "lab-linux-01",
        Expected(rule_ids=["100401"]),
    )
    result = engine.replay_test(test_pos)
    assert result.verdict == Verdict.TP
    assert len(result.matched_alerts) == 1

    test_neg = TestCase(
        "T-NEG",
        "Negative test expecting quiet",
        "T1059.004",
        "linux",
        "custom",
        "lab-linux-01",
        Expected(rule_ids=["999999"]),
        negative=True,
    )
    result_neg = engine.replay_test(test_neg)
    assert result_neg.verdict == Verdict.TN


def test_replay_engine_from_ndjson(tmp_path: Path):
    ndjson_file = tmp_path / "alerts.ndjson"
    ndjson_file.write_text(
        "\n".join(json.dumps(a) for a in SAMPLE_ALERTS) + "\n", encoding="utf-8"
    )

    engine = ReplayEngine.from_ndjson(ndjson_file)
    test_win = TestCase(
        "T-WIN",
        "PowerShell Encoded",
        "T1059.001",
        "windows",
        "custom",
        "lab-win-01",
        Expected(rule_ids=["100856"]),
    )
    summary = engine.replay_catalog([test_win])
    assert summary.total_tests == 1
    assert summary.true_positives == 1
    assert summary.passed

