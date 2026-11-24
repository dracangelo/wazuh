"""Run fingerprints: what a run was tested against, and when two runs are comparable."""
import json
from pathlib import Path

from validator.fingerprint import (
    definition_hash,
    live_versions,
    meta_diff,
    run_fingerprint,
    tree_hash,
)
from validator.models import Expected, TestCase
from validator.regression.comparator import compare
from validator.regression.runner import run_regression
from validator.storage.database import connect
from validator.storage.repository import RunRepository

ROOT = Path(__file__).resolve().parents[2]


def mk(tid="t", **kw):
    return TestCase(tid, tid, "T1", "linux", "custom", "lab", Expected(rule_ids=["1"]), **kw)


def test_tree_hash_tracks_content_name_and_ignores_other_files(tmp_path):
    (tmp_path / "a.xml").write_text("<a/>")
    h1 = tree_hash(tmp_path, ("*.xml",))
    assert h1 == tree_hash(tmp_path, ("*.xml",))                       # deterministic
    (tmp_path / "notes.txt").write_text("irrelevant")
    assert tree_hash(tmp_path, ("*.xml",)) == h1                       # pattern-scoped
    (tmp_path / "a.xml").write_text("<b/>")
    assert tree_hash(tmp_path, ("*.xml",)) != h1                       # content
    (tmp_path / "a.xml").write_text("<a/>")
    (tmp_path / "a.xml").rename(tmp_path / "b.xml")
    assert tree_hash(tmp_path, ("*.xml",)) != h1                       # rename
    assert tree_hash(tmp_path / "missing", ("*.xml",)) is None


def test_real_project_fingerprint_is_complete_and_secret_free():
    paths = {"rules": ROOT / "rules/wazuh", "catalog": ROOT / "test-catalog",
             "regression": ROOT / "tests/regression", "custom": ROOT / "custom-simulations",
             "atomic": ROOT / "atomic"}
    meta = run_fingerprint(paths, {"wazuh_manager_version": "v4.9.2"})
    for key in ("rules_sha256", "catalog_sha256", "custom_simulations_sha256", "atomic_sha256"):
        assert meta[key] and len(meta[key]) == 64
    assert meta["wazuh_manager_version"] == "v4.9.2"
    assert "password" not in json.dumps(meta).lower()


def test_definition_hash_changes_with_expectation_or_simulation():
    base = definition_hash(mk())
    assert base == definition_hash(mk())
    assert base != definition_hash(mk(simulation={"script": "x.sh"}))
    other = mk()
    other.expected.rule_ids = ["2"]
    assert base != definition_hash(other)


def test_meta_diff_separates_experiment_from_rules_and_unknowns():
    base = {"rules_sha256": "r1", "catalog_sha256": "c1", "framework_version": "0.1.0"}
    cur = {"rules_sha256": "r2", "catalog_sha256": "c2", "framework_version": "0.1.0"}
    d = meta_diff(base, cur)
    assert [x["key"] for x in d["experiment_changed"]] == ["catalog_sha256"]
    assert [x["key"] for x in d["subject_changed"]] == ["rules_sha256"]
    assert "atomic_sha256" in d["unknown"]                              # absent on both sides
    assert meta_diff({}, cur)["experiment_changed"] == []               # old run: unknown, not "changed"


def test_live_versions_failure_is_a_note_not_an_exception():
    class Down:
        def manager_info(self):
            raise ConnectionError("refused")

    out = live_versions(Down())
    assert "wazuh_manager_version" not in out and "ConnectionError" in out["live_versions_error"]

    class Up:
        def manager_info(self):
            return {"version": "v4.9.2"}

        def agents(self):
            return [{"name": "lab", "version": "Wazuh v4.9.2"}]

    assert live_versions(Up()) == {"wazuh_manager_version": "v4.9.2",
                                   "agent_versions": {"lab": "Wazuh v4.9.2"}}


def test_compare_flags_changed_definition_but_not_missing_hashes():
    base = [{"test_id": "a", "verdict": "TP", "test_hash": "h1"},
            {"test_id": "b", "verdict": "TP", "test_hash": None}]
    cur = [{"test_id": "a", "verdict": "FN", "test_hash": "h2"},
           {"test_id": "b", "verdict": "FN", "test_hash": "h9"}]
    r = compare(base, cur)
    assert r.definition_changed == ["a"] and r.regressions[0]["definition_changed"] is True
    assert "definition_changed" not in r.regressions[1]


def test_run_meta_round_trips_and_old_runs_have_empty_meta(tmp_path):
    repo = RunRepository(connect(tmp_path / "db.sqlite"))
    rid = repo.create_run("x", meta={"rules_sha256": "abc"})
    assert repo.get_run(rid)["meta"] == {"rules_sha256": "abc"}
    assert repo.get_run(repo.create_run("y"))["meta"] == {}


def test_regression_runner_reports_context_between_runs(tmp_path, monkeypatch):
    from test_hardening import IdAdapter, make_orch  # reuse fakes
    orch, repo = make_orch(tmp_path, IdAdapter())
    tests = [mk("t")]
    orch.run_meta = {"rules_sha256": "r1", "catalog_sha256": "c1"}
    first = orch.run(tests, label="regression", progress=lambda _: None)
    orch.run_meta = {"rules_sha256": "r2", "catalog_sha256": "c2"}
    import validator.regression.runner as rr
    monkeypatch.setattr(rr, "load_catalog", lambda _dir: tests)        # avoid touching the real catalog
    run_id, base, rep = run_regression(orch, repo, tmp_path)
    assert base == first and run_id != first
    assert [d["key"] for d in rep.context["experiment_changed"]] == ["catalog_sha256"]
    assert [d["key"] for d in rep.context["subject_changed"]] == ["rules_sha256"]
