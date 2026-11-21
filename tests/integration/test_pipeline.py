"""End-to-end pipeline with a fake simulation adapter and NDJSON fixture alerts (no Wazuh, no SSH)."""
import json
from datetime import datetime, timedelta, timezone

from validator.adapters.base import Adapter, Target
from validator.collectors.wazuh_alerts import FileAlertCollector
from validator.models import ExecutionResult, Expected, TestCase
from validator.orchestrator import Orchestrator
from validator.storage.database import connect
from validator.storage.repository import RunRepository


class FakeAdapter(Adapter):
    def __init__(self, alerts_path):
        self.path = alerts_path

    def run(self, test, target):
        now = datetime.now(timezone.utc)
        # Pretend the target's Wazuh agent produced an alert 2s after the simulation began.
        if test.id == "pos":
            line = {"id": "1", "timestamp": (now + timedelta(seconds=2)).strftime("%Y-%m-%dT%H:%M:%S.000+0000"),
                    "rule": {"id": "5712", "level": 10, "groups": ["sshd"]}, "agent": {"name": "lab"}}
            self.path.write_text(json.dumps(line) + "\n")
        return ExecutionResult(now, now, True, 0)


def test_pipeline(tmp_path):
    alerts = tmp_path / "alerts.json"
    repo = RunRepository(connect(tmp_path / "db.sqlite"))
    orch = Orchestrator({"evaluation": {"default_timeout_seconds": 1, "poll_interval_seconds": 0, "clock_skew_seconds": 5}},
                        {"lab": Target("lab", "linux", agent_name="lab")}, {"custom": FakeAdapter(alerts)},
                        FileAlertCollector(alerts), repo, tmp_path / "evidence", sleep=lambda s: None)
    tests = [TestCase("pos", "p", "T1110", "linux", "custom", "lab", Expected(rule_ids=["5712"], timeout_seconds=1)),
             TestCase("neg", "n", "T1110", "linux", "custom", "lab", Expected(rule_ids=["9999"], timeout_seconds=1),
                      negative=True)]
    run_id = orch.run(tests, progress=lambda m: None)
    verdicts = {r["test_id"]: r["verdict"] for r in repo.results(run_id)}
    assert verdicts == {"pos": "TP", "neg": "TN"}
    assert (tmp_path / "evidence" / f"run-{run_id}" / "pos.json").exists()
