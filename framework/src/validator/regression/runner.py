"""Regression = re-run the tests in tests/regression/ and diff against a baseline run."""
from __future__ import annotations

from ..fingerprint import meta_diff
from ..orchestrator import load_catalog
from .comparator import RegressionReport, compare


def run_regression(orchestrator, repo, catalog_dir, baseline_run_id: int | None = None):
    """Returns (run_id, baseline_id, report). The report is None when the run was inconclusive:
    a run with no verdicts must not be compared (every test would look 'missing')."""
    tests = load_catalog(catalog_dir)
    run_id = orchestrator.run(tests, label="regression")
    run = repo.get_run(run_id) or {}
    if run.get("status") != "completed":
        return run_id, baseline_run_id, None
    baseline_id = baseline_run_id or repo.latest_run_id(label="regression", before=run_id,
                                                        status="completed")
    if baseline_id is None:
        return run_id, None, RegressionReport(new_tests=[t.id for t in tests])
    base_run = repo.get_run(baseline_id)
    if base_run is None:
        raise ValueError(f"baseline run {baseline_id} does not exist")
    context = meta_diff(base_run.get("meta"), run.get("meta"))
    return run_id, baseline_id, compare(repo.results(baseline_id), repo.results(run_id), context)
