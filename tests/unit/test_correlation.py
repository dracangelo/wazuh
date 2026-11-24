"""Execution-id correlation, claimed evidence, and uncorrelated-match reporting."""
import json
from datetime import datetime, timedelta, timezone

import pytest

from validator.adapters.base import Adapter, Target
from validator.collectors.wazuh_alerts import AlertBatch, parse_alert
from validator.evaluation.evaluator import evaluate
from validator.evaluation.matcher import alert_matches, carries_exec_id
from validator.models import ExecutionResult, Expected, TestCase, Verdict
from validator.orchestrator import Orchestrator, load_catalog
from validator.safety import SafetyPolicy
from validator.storage.database import connect
from validator.storage.repository import RunRepository

T0 = datetime(2026, 1, 1, 10, 0, 0, tzinfo=timezone.utc)
EID = "dv261123073531c669"


def alert(rule="100311", aid="a1", path="/etc/sudoers.d/dv_x", dt=3, **extra):
    doc = {"id": aid, "timestamp": (T0 + timedelta(seconds=dt)).strftime("%Y-%m-%dT%H:%M:%S.000+0000"),
           "rule": {"id": rule, "level": 12, "groups": ["syscheck"]}, "agent": {"name": "lab"},
           "syscheck": {"path": path}, "full_log": f"File '{path}' added", **extra}
    return parse_alert(doc)


def mk_case(tid="t", correlation="exec_id", negative=False, **exp):
    e = Expected(**({"rule_ids": ["100311"]} | exp), correlation=correlation)
    return TestCase(tid, tid, "T1", "linux", "custom", "lab", e, negative=negative)


def ex(exec_id=EID, ok=True):
    return ExecutionResult(T0, T0 + timedelta(seconds=2), ok, 0 if ok else 1, exec_id=exec_id)


# --- matcher ---------------------------------------------------------------------------------

def test_exec_id_found_in_event_payload_not_in_wazuh_sections():
    assert carries_exec_id(alert(path=f"/etc/sudoers.d/dv_{EID}"), EID)
    assert carries_exec_id(alert(path=f"/etc/sudoers.d/dv_{EID.upper()}"), EID)       # case-insensitive
    assert not carries_exec_id(alert(), EID)
    # the id appearing only in rule/agent metadata must not count as correlation
    spoof = alert(path="/etc/x")
    spoof.raw["rule"]["description"] = EID
    spoof.raw["agent"]["name"] = EID
    assert not carries_exec_id(spoof, EID)


def test_strict_correlation_needs_an_id():
    a = alert(path=f"/etc/sudoers.d/dv_{EID}")
    exp = Expected(rule_ids=["100311"], correlation="exec_id")
    assert alert_matches(a, exp, EID)
    assert not alert_matches(a, exp, None) and not alert_matches(a, exp, "dv000000000000aaaa")
    assert alert_matches(a, Expected(rule_ids=["100311"]), None)                       # window mode unchanged


def test_invalid_correlation_value_rejected():
    with pytest.raises(ValueError, match="correlation"):
        TestCase.from_dict({"id": "x", "name": "n", "technique": "T1", "platform": "linux",
                            "source": "custom", "target": "t",
                            "expected": {"rule_ids": ["1"], "correlation": "fuzzy"}})


# --- evaluator ---------------------------------------------------------------------------------

def test_other_executions_alert_cannot_satisfy_a_strict_test():
    foreign = alert(path="/etc/sudoers.d/dv_dv000000000000aaaa", aid="other")
    r = evaluate(mk_case(), ex(), [foreign])
    assert r.verdict == Verdict.FN and r.matched_alerts == []
    assert r.uncorrelated_alerts == [foreign] and "not counted" in r.error and EID in r.error


def test_own_alert_is_tp_even_with_noise_present():
    own = alert(path=f"/etc/sudoers.d/dv_{EID}", aid="mine")
    noise = alert(path="/etc/sudoers.d/dv_other", aid="noise")
    r = evaluate(mk_case(), ex(), [noise, own])
    assert r.verdict == Verdict.TP and r.matched_alerts == [own] and r.uncorrelated_alerts == [noise]


def test_window_mode_still_matches_any_alert():
    assert evaluate(mk_case(correlation="window"), ex(None), [alert()]).verdict == Verdict.TP


def test_missing_exec_id_is_error_not_fn():
    r = evaluate(mk_case(), ex(None), [])
    assert r.verdict == Verdict.ERROR and "no id" in r.error


def test_strict_negative_ignores_foreign_noise():
    foreign = alert(path="/etc/sudoers.d/dv_somebody_else")
    assert evaluate(mk_case(negative=True), ex(), [foreign]).verdict == Verdict.TN
    own = alert(path=f"/etc/sudoers.d/dv_{EID}")
    assert evaluate(mk_case(negative=True), ex(), [own]).verdict == Verdict.FP


def test_require_all_needs_every_rule_to_carry_the_id():
    t = mk_case(rule_ids=["100100", "100101"], require_all=True)
    mine = alert("100100", "m1", f"/etc/dv_{EID}.txt")
    foreign = alert("100101", "f1", "/etc/dv_other.txt")
    r = evaluate(t, ex(), [mine, foreign])
    assert r.verdict == Verdict.FN and "100101" in r.error


# --- orchestrator: claimed evidence, persistence -----------------------------------------------------

class SeqAdapter(Adapter):
    """Returns a fixed exec id per test; the alert for it is already in the collector."""

    def __init__(self, ids):
        self.ids = ids

    def run(self, test, target):
        now = datetime.now(timezone.utc)
        return ExecutionResult(now, now, True, 0, exec_id=self.ids.get(test.id))


class StaticCollector:
    def __init__(self, alerts):
        self.alerts = alerts

    def fetch(self, agent_name, since, until):
        return AlertBatch(list(self.alerts), pages_fetched=1)


def orch(tmp_path, adapter, alerts):
    repo = RunRepository(connect(tmp_path / "db.sqlite"))
    o = Orchestrator({"evaluation": {"default_timeout_seconds": 1, "poll_interval_seconds": 0}},
                     {"lab": Target("lab", "linux", "local", "lab")}, {"custom": adapter},
                     StaticCollector(alerts), repo, tmp_path / "evidence", sleep=lambda _: None,
                     policy=SafetyPolicy(lab_acknowledged=True))
    return o, repo


def t_window(tid, **kw):
    return TestCase(tid, tid, "T1", "linux", "custom", "lab",
                    Expected(rule_ids=["100311"], timeout_seconds=1, **kw))


def test_one_alert_cannot_prove_two_tests(tmp_path):
    only = alert(aid="shared-1", dt=0)
    o, repo = orch(tmp_path, SeqAdapter({}), [only])
    rid = o.run([t_window("first"), t_window("second")], progress=lambda _: None)
    v = {r["test_id"]: r["verdict"] for r in repo.results(rid)}
    assert v == {"first": "TP", "second": "FN"}


def test_shared_evidence_is_opt_in(tmp_path):
    only = alert(aid="shared-1", dt=0)
    o, repo = orch(tmp_path, SeqAdapter({}), [only])
    rid = o.run([t_window("first", shared_evidence=True), t_window("second", shared_evidence=True)],
                progress=lambda _: None)
    assert {r["verdict"] for r in repo.results(rid)} == {"TP"}


def test_claims_do_not_leak_across_runs(tmp_path):
    only = alert(aid="shared-1", dt=0)
    o, repo = orch(tmp_path, SeqAdapter({}), [only])
    o.run([t_window("first")], progress=lambda _: None)
    rid = o.run([t_window("first")], progress=lambda _: None)
    assert repo.results(rid)[0]["verdict"] == "TP"


def test_correlation_and_exec_id_persisted_and_in_evidence(tmp_path):
    own = alert(path=f"/etc/sudoers.d/dv_{EID}", aid="mine", dt=0)
    noise = alert(path="/etc/sudoers.d/dv_other", aid="noise", dt=0)
    o, repo = orch(tmp_path, SeqAdapter({"s": EID}), [noise, own])
    rid = o.run([mk_case("s")], progress=lambda _: None)
    row = repo.results(rid)[0]
    assert row["verdict"] == "TP" and row["exec_id"] == EID and row["correlation"] == "exec_id"
    doc = json.loads((tmp_path / "evidence" / f"run-{rid}" / "s.json").read_text())
    assert doc["weak_correlation"] is False and doc["correlation"] == "exec_id"
    assert [a["id"] for a in doc["uncorrelated_matches"]] == ["noise"]


def test_adapter_without_exec_id_is_error_before_polling(tmp_path):
    o, repo = orch(tmp_path, SeqAdapter({}), [alert()])
    rid = o.run([mk_case("s")], progress=lambda _: None)
    row = repo.results(rid)[0]
    assert row["verdict"] == "ERROR" and "exec" in row["error"]


def test_metrics_split_strict_and_weak_tps():
    from validator.evaluation.metrics import compute_metrics
    rows = [{"verdict": "TP", "technique": "T", "latency_seconds": 1, "correlation": "exec_id"},
            {"verdict": "TP", "technique": "T", "latency_seconds": 1, "correlation": "window"},
            {"verdict": "TP", "technique": "T", "latency_seconds": 1}]
    m = compute_metrics(rows)
    assert (m["tp_exec_correlated"], m["tp_window_only"]) == (1, 2)


def test_old_database_gains_new_result_columns(tmp_path):
    import sqlite3
    path = tmp_path / "old.sqlite"
    c = sqlite3.connect(path)
    c.executescript("CREATE TABLE runs(id INTEGER PRIMARY KEY AUTOINCREMENT,label TEXT,started_at TEXT "
                    "NOT NULL,finished_at TEXT,git_sha TEXT);"
                    "CREATE TABLE results(id INTEGER PRIMARY KEY AUTOINCREMENT,run_id INTEGER,test_id TEXT,"
                    "name TEXT,technique TEXT,platform TEXT,negative INTEGER,verdict TEXT,latency_seconds REAL,"
                    "matched_rule_ids TEXT,error TEXT);")
    c.commit()
    c.close()
    cols = {r[1] for r in connect(path).execute("PRAGMA table_info(results)")}
    assert {"exec_id", "correlation"} <= cols


# --- catalog ------------------------------------------------------------------------------------------

def test_strict_tests_use_scripts_that_embed_the_exec_id():
    """Every exec_id-correlated custom test must run a script whose artifacts carry DV_EXEC_ID."""
    from pathlib import Path
    root = Path(__file__).resolve().parents[2]
    strict = [t for t in load_catalog(root / "test-catalog") if t.expected.correlation == "exec_id"]
    assert len(strict) >= 8
    for t in strict:
        if t.source == "atomic":
            assert "dv_exec_id" in json.dumps(t.simulation), t.id
        else:
            text = (root / "custom-simulations" / t.simulation["script"]).read_text(encoding="utf-8")
            assert "dv_suffix" in text, t.id
