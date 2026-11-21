"""Regression = re-run the tests in tests/regression/ and diff against a baseline run."""
from __future__ import annotations

from .comparator import RegressionReport, compare


def run_regression(orchestrator, repo, catalog_dir, baseline_run_id: int | None = None):
    tests = orchestrator.load_catalog(catalog_dir)
    run_id = orchestrator.run(tests, label="regression")
    baseline_id = baseline_run_id or repo.latest_run_id(label="regression", before=run_id)
    if baseline_id is None:
        return run_id, None, RegressionReport(new_tests=[t.id for t in tests])
    return run_id, baseline_id, compare(repo.results(baseline_id), repo.results(run_id))
