"""Offline pipeline-canary tests: fake trigger, fake collector and an NDJSON manager log."""
import json
from datetime import datetime, timezone

from validator.adapters.base import Adapter, Target
from validator.canary import CanaryOutcome, PipelineCanary
from validator.collectors.wazuh_alerts import AlertBatch, parse_alert
from validator.models import ExecutionResult, Expected, TestCase
from validator.orchestrator import Orchestrator
from validator.safety import SafetyPolicy
from validator.storage.database import connect
from validator.storage.repository import RunRepository


def settings(**canary):
    cfg = {"enabled": True, "target": "lab", "expected_rule_ids": ["5710"],
           "timeout_seconds": 0, "poll_interval_seconds": 0, "reconcile_grace_seconds": 0,
           "manager_alert_file": ""} | canary
    return {"canary": cfg, "evaluation": {"clock_skew_seconds": 5}}


def alert(rule_id="5710", agent="lab"):
    now = datetime.now(timezone.utc)
    return parse_alert({"id": f"c-{rule_id}", "timestamp": now.strftime("%Y-%m-%dT%H:%M:%S.000+0000"),
                        "rule": {"id": rule_id, "level": 5}, "agent": {"name": agent}})


class FakeCollector:
    """Repeats its batches; an Exception entry is raised on that observation."""

    def __init__(self, *batches):
        self.batches, self.calls = list(batches) or [AlertBatch([])], 0

    def fetch(self, agent_name, since, until):
        batch = self.batches[min(self.calls, len(self.batches) - 1)]
        self.calls += 1
        if isinstance(batch, Exception):
            raise batch
        return batch


class StaticCollector:
    def __init__(self, alerts):
        self.alerts = alerts

    def fetch(self, agent_name, since, until):
        return AlertBatch(self.alerts)


class OkAdapter(Adapter):
    def run(self, test, target):
        now = datetime.now(timezone.utc)
        return ExecutionResult(now, now, True, 0)


class StubCanary:
    def __init__(self, outcome):
        self.outcome = outcome

    def check(self):
        return self.outcome


def ok_trigger(test, target):
    now = datetime.now(timezone.utc)
    return ExecutionResult(now, now, True, 0)


def make_canary(tmp_path, collector, trigger=ok_trigger, **cfg):
    return PipelineCanary(settings(**cfg), {"lab": Target("lab", "linux", "local", "lab")},
                          collector, SafetyPolicy(lab_acknowledged=True), tmp_path,
                          trigger=trigger, sleep=lambda _: None)


def write_manager_log(path, alerts):
    path.write_text("".join(json.dumps({"timestamp": a.timestamp.strftime("%Y-%m-%dT%H:%M:%S.000+0000"),
                                        "rule": {"id": a.rule_id}, "agent": {"name": a.agent_name}})
                            + "\n" for a in alerts), encoding="utf-8")
    return path


def test_canary_ok_when_known_good_alert_arrives(tmp_path):
    outcome = make_canary(tmp_path, FakeCollector(AlertBatch([alert()]))).check()
    assert outcome.status == "ok" and not outcome.failed
    assert outcome.indexer_alerts == 1 and "5710" in outcome.detail


def test_missing_alert_with_manager_record_fails_as_pipeline_problem(tmp_path):
    collector = FakeCollector(AlertBatch([]))
    manager_log = write_manager_log(tmp_path / "alerts.json", [alert()])
    outcome = make_canary(tmp_path, collector, manager_alert_file=str(manager_log)).check()
    assert outcome.status == "failed"
    assert outcome.manager_alerts == 1
    assert "manager alert file recorded 1" in outcome.detail and "manager->indexer" in outcome.detail
    assert collector.calls >= 2  # one reconciliation-grace re-read after the timeout


def test_missing_alert_without_reconciliation_says_so(tmp_path):
    outcome = make_canary(tmp_path, FakeCollector(AlertBatch([])), manager_alert_file="").check()
    assert outcome.status == "failed"
    assert outcome.manager_alerts is None and "reconciliation is unavailable" in outcome.detail


def test_canary_collection_error_fails(tmp_path):
    outcome = make_canary(tmp_path, FakeCollector(RuntimeError("indexer down"))).check()
    assert outcome.status == "failed" and "canary alert collection failed" in outcome.detail
    assert "indexer down" in outcome.detail


def test_canary_truncated_collection_fails(tmp_path):
    batch = AlertBatch([], truncated=True, reason="alert cap reached (1 alerts)")
    outcome = make_canary(tmp_path, FakeCollector(batch)).check()
    assert outcome.status == "failed" and "truncated" in outcome.detail


def test_canary_trigger_failure_fails(tmp_path):
    def broken(test, target):
        raise OSError("ssh missing")

    outcome = make_canary(tmp_path, FakeCollector(AlertBatch([])), trigger=broken).check()
    assert outcome.status == "failed" and "failed to start" in outcome.detail


def test_disabled_canary_is_skipped(tmp_path):
    outcome = make_canary(tmp_path, FakeCollector(AlertBatch([])), enabled=False).check()
    assert outcome.status == "skipped"


def test_missing_canary_target_is_a_configuration_failure(tmp_path):
    outcome = make_canary(tmp_path, FakeCollector(AlertBatch([])), target="nope").check()
    assert outcome.status == "failed" and "not in environments.yaml" in outcome.detail


def make_orchestrator(tmp_path, collector, canary=None):
    repo = RunRepository(connect(tmp_path / "db.sqlite"))
    orch = Orchestrator({"evaluation": {"default_timeout_seconds": 1, "poll_interval_seconds": 0}},
                        {"lab": Target("lab", "linux", "local", "lab")},
                        {"custom": OkAdapter()}, collector, repo, tmp_path / "evidence",
                        sleep=lambda _: None, policy=SafetyPolicy(lab_acknowledged=True),
                        canary=canary)
    return orch, repo


def positive_test():
    return TestCase("t", "n", "T1110", "linux", "custom", "lab",
                    Expected(rule_ids=["5712"], timeout_seconds=1))


def test_failed_canary_makes_run_inconclusive_without_fns(tmp_path):
    canary = StubCanary(CanaryOutcome("failed", "manager recorded 1 canary alert(s) but the indexer "
                                                  "returned 0; the manager->indexer pipeline is not "
                                                  "delivering alerts"))
    orch, repo = make_orchestrator(tmp_path, StaticCollector([alert("9999")]), canary)
    run_id = orch.run([positive_test()], progress=lambda _: None)

    run = repo.get_run(run_id)
    assert run["status"] == "inconclusive" and run["canary_status"] == "failed"
    assert "manager->indexer" in run["canary_detail"]
    assert repo.results(run_id) == []  # no FN, because the window was never trustworthy


def test_ok_canary_allows_verdicts_and_is_recorded_on_the_run(tmp_path):
    orch, repo = make_orchestrator(tmp_path, StaticCollector([alert("5712")]),
                                   StubCanary(CanaryOutcome("ok", "canary rule 5710 observed")))
    run_id = orch.run([positive_test()], progress=lambda _: None)

    run = repo.get_run(run_id)
    assert run["status"] == "completed" and run["canary_status"] == "ok"
    assert [r["verdict"] for r in repo.results(run_id)] == ["TP"]


def test_skipped_canary_runs_tests_and_is_recorded(tmp_path):
    orch, repo = make_orchestrator(tmp_path, StaticCollector([alert("5712")]),
                                   StubCanary(CanaryOutcome("skipped", "disabled by --no-canary")))
    run_id = orch.run([positive_test()], progress=lambda _: None)
    run = repo.get_run(run_id)
    assert run["status"] == "completed" and run["canary_status"] == "skipped"
    assert [r["verdict"] for r in repo.results(run_id)] == ["TP"]


def test_regression_baseline_skips_inconclusive_runs(tmp_path):
    repo = RunRepository(connect(tmp_path / "db.sqlite"))
    completed = repo.create_run("regression")
    repo.finish_run(completed)
    inconclusive = repo.create_run("regression")
    repo.finish_run(inconclusive, status="inconclusive", canary_status="failed", canary_detail="x")
    assert repo.latest_run_id(label="regression", status="completed") == completed
