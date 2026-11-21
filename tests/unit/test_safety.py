import ipaddress
from datetime import datetime, timezone

import pytest

from validator.adapters.base import Adapter, Target
from validator.collectors.wazuh_alerts import FileAlertCollector
from validator.models import ExecutionResult, Expected, TestCase, Verdict
from validator.orchestrator import Orchestrator
from validator.safety import SafetyPolicy
from validator.storage.database import connect
from validator.storage.repository import RunRepository

ACK = SafetyPolicy(lab_acknowledged=True)


def ssh(host, name="lab-linux-01"):
    return Target(name, "linux", "ssh", name, host, 22, "labrunner")


def make_test(target="lab-linux-01", **kwargs):
    return TestCase("t1", "name", "T1110", "linux", "custom", target,
                    Expected(rule_ids=["1"], timeout_seconds=1), **kwargs)


@pytest.mark.parametrize("host", ["10.0.0.21", "172.16.4.9", "192.168.56.10", "127.0.0.1"])
def test_private_and_loopback_targets_allowed(host):
    decision = ACK.check_target(ssh(host))
    assert decision.allowed, decision
    assert decision.code == "ok"


@pytest.mark.parametrize("host", ["8.8.8.8", "1.1.1.1", "203.0.113.10", "2606:4700::1111"])
def test_public_targets_rejected(host):
    decision = ACK.check_target(ssh(host))
    assert not decision.allowed
    assert decision.code == "target-outside-lab"


@pytest.mark.parametrize("host", ["", "300.1.1.1", "not a host!", "10.0.0.1; rm -rf /"])
def test_malformed_targets_rejected(host):
    assert not ACK.check_target(ssh(host)).allowed


def test_hostname_must_be_allowlisted():
    decision = ACK.check_target(ssh("wazuh.example.com"))
    assert not decision.allowed
    assert decision.code == "hostname-not-allowed"


def test_allowlisted_hostname_inside_lab_allowed(monkeypatch):
    monkeypatch.setattr("validator.safety._resolve", lambda host: [ipaddress.ip_address("10.0.0.99")])
    policy = SafetyPolicy(lab_acknowledged=True, allowed_hostnames=("lab.example.com",))
    assert policy.check_target(ssh("lab.example.com")).allowed


def test_allowlisted_hostname_resolving_public_rejected(monkeypatch):
    monkeypatch.setattr("validator.safety._resolve", lambda host: [ipaddress.ip_address("93.184.216.34")])
    policy = SafetyPolicy(lab_acknowledged=True, allowed_hostnames=("lab.example.com",))
    assert policy.check_target(ssh("lab.example.com")).code == "target-outside-lab"


def test_unresolvable_allowlisted_hostname_rejected(monkeypatch):
    def boom(host):
        raise OSError("name or service not known")

    monkeypatch.setattr("validator.safety._resolve", boom)
    policy = SafetyPolicy(lab_acknowledged=True, allowed_hostnames=("lab.example.com",))
    assert policy.check_target(ssh("lab.example.com")).code == "target-unresolved"


def test_lab_acknowledgement_required():
    decision = SafetyPolicy().check_target(ssh("10.0.0.21"))
    assert not decision.allowed
    assert decision.code == "no-lab-ack"


def test_lab_acknowledgement_from_environment(monkeypatch):
    monkeypatch.setenv("DV_LAB_ACK", "1")
    assert SafetyPolicy.from_settings({}).lab_acknowledged


def test_local_target_policy():
    local = Target("local", "linux", "local", "local")
    assert ACK.check_target(local).allowed
    restricted = SafetyPolicy(lab_acknowledged=True, allow_local_targets=False)
    assert restricted.check_target(local).code == "local-disabled"


def test_invalid_cidr_configuration_is_refused():
    policy = SafetyPolicy(lab_acknowledged=True, allowed_cidrs=("not-a-network",))
    with pytest.raises(ValueError):
        policy.check_target(ssh("10.0.0.1"))


def test_high_risk_requires_explicit_opt_in():
    assert not ACK.check_test(make_test(risk="high")).allowed
    assert ACK.with_destructive().check_test(make_test(risk="high")).allowed
    assert ACK.check_test(make_test(risk="medium")).allowed


def test_catalog_rejects_unknown_risk():
    doc = {"id": "x", "name": "n", "technique": "T1", "platform": "linux", "source": "custom",
           "target": "t", "expected": {"rule_ids": ["1"]}, "risk": "extreme"}
    with pytest.raises(ValueError):
        TestCase.from_dict(doc)


class RecordingAdapter(Adapter):
    def __init__(self):
        self.calls = []

    def run(self, test, target):
        self.calls.append(test.id)
        now = datetime.now(timezone.utc)
        return ExecutionResult(now, now, True, 0)


def build_orchestrator(tmp_path, targets, policy):
    adapter = RecordingAdapter()
    repo = RunRepository(connect(tmp_path / "db.sqlite"))
    orch = Orchestrator({}, targets, {"custom": adapter}, FileAlertCollector(tmp_path / "alerts.ndjson"),
                        repo, tmp_path / "evidence", policy=policy, sleep=lambda _: None)
    return orch, repo, adapter


def verdicts(repo, run_id):
    return {r["test_id"]: r["verdict"] for r in repo.results(run_id)}


def test_unsafe_target_is_rejected_before_any_command_runs(tmp_path):
    targets = {"public": ssh("8.8.8.8", name="public"), "lab": Target("lab", "linux", "local", "lab")}
    orch, repo, adapter = build_orchestrator(tmp_path, targets, ACK)
    tests = [make_test("public"), make_test("lab")]
    run_id = orch.run(tests, progress=lambda _: None)
    assert adapter.calls == []  # nothing executed, not even the safe second test
    assert verdicts(repo, run_id) == {"t1": Verdict.ERROR.value}


def test_high_risk_test_is_blocked_without_opt_in(tmp_path):
    targets = {"lab": Target("lab", "linux", "local", "lab")}
    orch, repo, adapter = build_orchestrator(tmp_path, targets, ACK)
    run_id = orch.run([make_test("lab", risk="high")], progress=lambda _: None)
    assert adapter.calls == []
    assert verdicts(repo, run_id) == {"t1": Verdict.ERROR.value}


def test_missing_lab_acknowledgement_blocks_execution(tmp_path):
    targets = {"lab": Target("lab", "linux", "local", "lab")}
    orch, repo, adapter = build_orchestrator(tmp_path, targets, SafetyPolicy())
    run_id = orch.run([make_test("lab")], progress=lambda _: None)
    assert adapter.calls == []
    assert verdicts(repo, run_id) == {"t1": Verdict.ERROR.value}


def test_allowed_test_runs(tmp_path):
    targets = {"lab": Target("lab", "linux", "local", "lab")}
    orch, repo, adapter = build_orchestrator(tmp_path, targets, ACK)
    run_id = orch.run([make_test("lab")], progress=lambda _: None)
    assert adapter.calls == ["t1"]
    assert verdicts(repo, run_id) == {"t1": Verdict.FN.value}  # ran, no alert fixture
