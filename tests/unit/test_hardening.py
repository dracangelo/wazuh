"""Coverage denominators, regression transition matrix, evidence integrity, interrupted runs,
ssh argument safety, catalog cross-checks and shell lab-host validation."""
import hashlib
import json
import subprocess
from datetime import datetime, timezone
from pathlib import Path

import pytest

from validator.adapters.base import Adapter, Target, build_command
from validator.cli import lint_catalog
from validator.collectors.wazuh_alerts import AlertBatch
from validator.evaluation.metrics import coverage_matrix, coverage_summary
from validator.models import ExecutionResult, Expected, TestCase
from validator.orchestrator import Orchestrator
from validator.regression.comparator import compare
from validator.safety import SafetyPolicy
from validator.storage.database import connect
from validator.storage.repository import RunRepository

ROOT = Path(__file__).resolve().parents[2]
LIB = ROOT / "custom-simulations" / "lib" / "dv_safety.sh"


def tc(tid, technique="T1", negative=False):
    exp = Expected(rule_ids=["1"])
    return TestCase(tid, tid, technique, "linux", "custom", "lab", exp, negative=negative)


# --- coverage -------------------------------------------------------------------------------

def cov(tests, verdicts, techniques=None):
    techniques = techniques or {"T1": {"name": "x", "tactic": "y"}}
    return {r["technique"]: r for r in coverage_matrix(techniques, tests, verdicts)}


def test_missing_positive_test_is_never_covered():
    row = cov([tc("a"), tc("b")], {"a": "TP"})["T1"]
    assert row["status"] == "partial" and row["passed"] == 1 and row["positive_tests"] == 2


def test_all_positive_tp_is_validated():
    assert cov([tc("a"), tc("b")], {"a": "TP", "b": "TP"})["T1"]["status"] == "validated"


@pytest.mark.parametrize("verdicts,status", [
    ({"a": "FN"}, "gap"), ({"a": "ERROR"}, "inconclusive"), ({}, "untested"),
    ({"a": "TP", "b": "ERROR"}, "partial"), ({"a": "FN", "b": "ERROR"}, "gap")])
def test_coverage_states(verdicts, status):
    assert cov([tc("a"), tc("b")], verdicts)["T1"]["status"] == status


def test_negative_tests_do_not_count_as_coverage():
    assert cov([tc("n", negative=True)], {"n": "TN"})["T1"]["status"] == "no-test"
    assert cov([tc("a"), tc("n", negative=True)], {"a": "TP"})["T1"]["status"] == "validated"


def test_coverage_summary_has_numerator_and_denominator():
    techniques = {"T1": {}, "T2": {}, "T3": {}}
    rows = coverage_matrix(techniques, [tc("a", "T1"), tc("b", "T2")], {"a": "TP", "b": "ERROR"})
    s = coverage_summary(rows)
    assert (s["techniques_validated"], s["techniques_with_positive_tests"], s["techniques_in_scope"]) == (1, 2, 3)
    assert (s["positive_tests_passed"], s["positive_tests"]) == (1, 2)
    assert s["validated_ratio"] == 0.5 and "not total MITRE" in s["scope_note"]


# --- regression transitions --------------------------------------------------------------------

def rows(**v):
    return [{"test_id": k, "verdict": x} for k, x in v.items()]


def test_fn_to_error_is_not_unchanged():
    r = compare(rows(a="FN"), rows(a="ERROR"))
    assert r.unchanged == 0 and r.inconclusive == [
        {"test_id": "a", "from": "FN", "to": "ERROR", "kind": "lost_signal"}]
    assert r.has_operational_failures and not r.has_regressions


def test_pass_to_error_flags_operational_failure_not_regression():
    r = compare(rows(a="TP"), rows(a="ERROR"))
    assert r.has_operational_failures and not r.has_regressions


def test_error_to_pass_is_regained_signal():
    r = compare(rows(a="ERROR"), rows(a="TP"))
    assert r.inconclusive[0]["kind"] == "regained_signal" and not r.has_operational_failures


def test_fn_to_fp_is_reported_as_changed():
    r = compare(rows(a="FN"), rows(a="FP"))
    assert r.changed and r.unchanged == 0


def test_compared_total_accounts_for_every_shared_test():
    r = compare(rows(a="TP", b="FN", c="TN", d="FN", e="ERROR"),
                rows(a="FN", b="TP", c="TN", d="ERROR", e="TP", f="TP"))
    assert r.compared == 5 and r.new_tests == ["f"]


# --- orchestrator: evidence integrity, interrupted runs ------------------------------------------------

class EmptyCollector:
    def fetch(self, agent_name, since, until):
        return AlertBatch([], pages_fetched=1)


class IdAdapter(Adapter):
    def run(self, test, target):
        now = datetime.now(timezone.utc)
        return ExecutionResult(now, now, True, 0, exec_id="dv-unit-1")


class BoomAdapter(Adapter):
    def __init__(self, exc):
        self.exc = exc

    def run(self, test, target):
        raise self.exc


def make_orch(tmp_path, adapter):
    repo = RunRepository(connect(tmp_path / "db.sqlite"))
    orch = Orchestrator({"evaluation": {"default_timeout_seconds": 1, "poll_interval_seconds": 0}},
                        {"lab": Target("lab", "linux", "local", "lab")}, {"custom": adapter},
                        EmptyCollector(), repo, tmp_path / "evidence", sleep=lambda _: None,
                        policy=SafetyPolicy(lab_acknowledged=True))
    return orch, repo


def test_evidence_is_private_hashed_and_traceable(tmp_path):
    orch, _repo = make_orch(tmp_path, IdAdapter())
    run_id = orch.run([tc("t")], progress=lambda _: None)
    d = tmp_path / "evidence" / f"run-{run_id}"
    ev, manifest = d / "t.json", json.loads((d / "manifest.json").read_text())
    assert manifest["t.json"]["sha256"] == hashlib.sha256(ev.read_bytes()).hexdigest()
    assert (ev.stat().st_mode & 0o777) == 0o600 and (d.stat().st_mode & 0o777) == 0o700
    doc = json.loads(ev.read_text())
    assert doc["exec_id"] == "dv-unit-1" and doc["collection"]["complete"] is True
    assert doc["collection"]["pages_fetched"] == 1 and doc["expected"]["rule_ids"] == ["1"]


def test_tampering_changes_the_recorded_hash(tmp_path):
    orch, _ = make_orch(tmp_path, IdAdapter())
    run_id = orch.run([tc("t")], progress=lambda _: None)
    d = tmp_path / "evidence" / f"run-{run_id}"
    recorded = json.loads((d / "manifest.json").read_text())["t.json"]["sha256"]
    (d / "t.json").write_text("{}", encoding="utf-8")
    assert hashlib.sha256((d / "t.json").read_bytes()).hexdigest() != recorded


def test_interrupted_run_is_marked_and_never_completed(tmp_path):
    orch, repo = make_orch(tmp_path, BoomAdapter(KeyboardInterrupt()))
    # an adapter exception becomes ERROR, but Ctrl-C must propagate and leave an 'interrupted' run
    with pytest.raises(KeyboardInterrupt):
        orch.run([tc("t")], progress=lambda _: None)
    assert repo.get_run(1)["status"] == "interrupted"
    assert repo.latest_run_id(status="completed") is None


def test_adapter_crash_is_error_not_fn(tmp_path):
    orch, repo = make_orch(tmp_path, BoomAdapter(RuntimeError("bug")))
    run_id = orch.run([tc("t")], progress=lambda _: None)
    assert repo.results(run_id)[0]["verdict"] == "ERROR"


# --- ssh command construction ---------------------------------------------------------------------

def test_ssh_command_cannot_be_read_as_option():
    t = Target("x", "linux", "ssh", "x", "-oProxyCommand=evil", 22, "u")
    cmd = build_command(t, ["sh", "-s"])
    assert cmd.index("--") < cmd.index("u@-oProxyCommand=evil")
    assert "ConnectTimeout=10" in cmd


# --- catalog cross-checks --------------------------------------------------------------------------

def test_lint_catalog_flags_unknown_target_missing_script_and_platform(tmp_path):
    (tmp_path / "custom").mkdir()
    (tmp_path / "atomic").mkdir()
    paths = {"custom": tmp_path / "custom", "atomic": tmp_path / "atomic"}
    good = Target("lab", "linux", "local", "lab")
    t1 = tc("a")
    t1.target = "ghost"
    t2 = tc("b")
    t2.simulation = {"script": "nope.sh"}
    t3 = tc("c")
    t3.platform = "windows"
    t3.simulation = {"script": "x.sh"}
    (tmp_path / "custom" / "x.sh").write_text("true")
    t4 = tc("d")
    t4.source = "atomic"
    problems = lint_catalog([t1, t2, t3, t4], {"lab": good}, paths)
    text = "\n".join(problems)
    assert "unknown target 'ghost'" in text and "script not found: nope.sh" in text
    assert "platform windows != target lab" in text and "atomic definition not found" in text


def test_real_catalog_cross_checks_clean():
    from validator.config import load_environments
    from validator.orchestrator import load_catalog
    tests = load_catalog(ROOT / "test-catalog") + load_catalog(ROOT / "tests" / "regression")
    targets = {n: Target.from_config(n, c) for n, c in
               load_environments(ROOT)["targets"].items()}
    paths = {"custom": ROOT / "custom-simulations", "atomic": ROOT / "atomic"}
    assert lint_catalog(tests, targets, paths) == []


# --- shell lab-host validation ------------------------------------------------------------------------

def host_check(host):
    return subprocess.run(["bash", "-c", f'. "{LIB}"; dv_require_lab_host "$1"', "_", host],
                          capture_output=True, text=True, check=False)


@pytest.mark.parametrize("host", ["10.0.0.21", "127.0.0.1", "192.168.5.5", "172.16.0.9",
                                  "172.31.255.254", "localhost"])
def test_lab_hosts_accepted(host):
    assert host_check(host).returncode == 0


@pytest.mark.parametrize("host", ["10.evil.example", "127.0.0.1.evil.com", "192.168.1.1.attacker.io",
                                  "8.8.8.8", "172.32.0.1", "10.0.0.999", "", "localhost.evil.com"])
def test_non_lab_hosts_refused(host):
    p = host_check(host)
    assert p.returncode == 64 and "refusing non-lab target" in p.stderr


@pytest.mark.parametrize("script,args", [
    ("brute-force/ssh_failed_logins.sh", ["10.evil.example"]),
    ("shellshock/shellshock_probe.sh", ["192.168.9.9.evil.io"]),
    ("shellshock/web_probes.sh", ["127.0.0.1.evil.io", "80", "canary"])])
def test_probe_scripts_refuse_lookalike_public_hosts(script, args):
    p = subprocess.run(["bash", str(ROOT / "custom-simulations" / script), *args],
                       capture_output=True, text=True, check=False, timeout=20)
    assert p.returncode == 64 and "refusing non-lab target" in p.stderr


def test_fim_touch_rejects_relative_or_missing_dir(tmp_path):
    script = str(ROOT / "custom-simulations" / "file-integrity" / "fim_touch.sh")
    for bad in ("relative/dir", str(tmp_path / "nope"), "/etc'; touch /tmp/pwned; '"):
        p = subprocess.run(["bash", script, bad], capture_output=True, text=True, check=False, timeout=20)
        assert p.returncode == 64
    assert not Path("/tmp/pwned").exists()


# --- regressions found by running the real scripts -----------------------------------------------------

def test_exec_tmp_really_copies_and_runs_a_binary():
    """`command -v true` returns the builtin name, so the copy used to fail silently (exit 0)."""
    from validator.adapters.custom import CustomAdapter
    ad = CustomAdapter(ROOT / "custom-simulations", default_timeout=30)
    test = tc("x")
    test.simulation = {"script": "rules-lab/scenarios.sh", "args": ["exec_tmp"], "timeout": 30}
    r = ad.run(test, Target("local", "linux"))
    assert r.status == "ok" and "cannot stat" not in r.stderr and r.exec_id


def test_failed_scenario_is_a_failed_execution_not_a_quiet_success():
    from validator.adapters.custom import CustomAdapter
    ad = CustomAdapter(ROOT / "custom-simulations", default_timeout=30)
    test = tc("x")
    test.simulation = {"script": "rules-lab/scenarios.sh", "args": ["no_such_scenario"], "timeout": 30}
    r = ad.run(test, Target("local", "linux"))
    assert not r.success and r.exit_code == 2


def test_ssh_exit_255_is_connection_failure_even_with_allow_nonzero(monkeypatch):
    import subprocess as sp

    from validator.adapters import base

    monkeypatch.setattr(base.subprocess, "run", lambda *a, **k: sp.CompletedProcess(a, 255, "", "refused"))
    t = Target("s", "linux", "ssh", "s", "10.0.0.1", 22, "u")
    r = base.run_script(t, "bash", "true", allow_nonzero=True)
    assert r.status == "connection_failed" and not r.success
