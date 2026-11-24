from __future__ import annotations

import csv
from collections import defaultdict
from pathlib import Path


def _ratio(n: int, d: int) -> float | None:
    return round(n / d, 4) if d else None


def compute_metrics(rows: list[dict]) -> dict:
    """rows: TestResult.to_row() dicts (or equivalent DB rows)."""
    c = defaultdict(int)
    lat = []
    tp_exec = sum(r["verdict"] == "TP" and r.get("correlation") == "exec_id" for r in rows)
    by_tech: dict[str, dict] = defaultdict(lambda: defaultdict(int))
    for r in rows:
        c[r["verdict"]] += 1
        by_tech[r["technique"]][r["verdict"]] += 1
        if r["verdict"] == "TP" and r.get("latency_seconds") is not None:
            lat.append(r["latency_seconds"])
    tp, fn, tn, fp = c["TP"], c["FN"], c["TN"], c["FP"]
    return {
        "total": len(rows), "tp": tp, "fn": fn, "tn": tn, "fp": fp, "errors": c["ERROR"],
        # TPs proven by the execution's own id vs TPs resting on agent + time window only
        "tp_exec_correlated": tp_exec, "tp_window_only": tp - tp_exec,
        "detection_rate": _ratio(tp, tp + fn),          # recall over attack tests
        "precision": _ratio(tp, tp + fp),
        "false_positive_rate": _ratio(fp, fp + tn),
        "mean_time_to_detect_s": round(sum(lat) / len(lat), 2) if lat else None,
        "by_technique": {t: dict(v) for t, v in sorted(by_tech.items())},
    }


def _status(positives: list, verdicts: dict[str, str]) -> str:
    """Per-technique state from its *mandatory positive* tests (negative tests are not coverage).

    validated      every positive test has a TP
    partial        some TP, but others are FN, ERROR or never executed
    gap            no TP and at least one FN (the detection is demonstrably missing)
    inconclusive   no TP and no FN, but at least one ERROR
    untested       positive tests exist, none has a recorded verdict
    no-test        the catalog has no positive test for the technique
    """
    if not positives:
        return "no-test"
    vs = [verdicts.get(t.id) for t in positives]
    tp, fn, err = vs.count("TP"), vs.count("FN"), vs.count("ERROR")
    if tp == len(vs):
        return "validated"
    if tp:
        return "partial"
    if fn:
        return "gap"
    if err:
        return "inconclusive"
    return "untested"


def coverage_matrix(techniques: dict, tests: list, last_verdicts: dict[str, str]) -> list[dict]:
    """One row per technique in mappings/attack-techniques.yaml.

    A missing or errored positive test can never count as covered: a technique is ``validated`` only
    when every one of its positive catalog tests last produced TP.
    """
    rows = []
    for tid, meta in sorted(techniques.items()):
        ts = [t for t in tests if t.technique == tid]
        positives = [t for t in ts if not t.negative]
        rows.append({
            "technique": tid, "name": meta.get("name", ""), "tactic": meta.get("tactic", ""),
            "tests": len(ts), "positive_tests": len(positives),
            "negative_tests": len(ts) - len(positives),
            "passed": sum(last_verdicts.get(t.id) == "TP" for t in positives),
            "status": _status(positives, last_verdicts),
        })
    return rows


def coverage_summary(rows: list[dict]) -> dict:
    """Explicit numerators and denominators; never a bare percentage.

    The denominator is the techniques *listed in the mapping file*, not the whole ATT&CK matrix.
    """
    total = len(rows)
    with_tests = sum(r["status"] != "no-test" for r in rows)
    validated = sum(r["status"] == "validated" for r in rows)
    pos = sum(r["positive_tests"] for r in rows)
    passed = sum(r["passed"] for r in rows)
    by_status: dict[str, int] = defaultdict(int)
    for r in rows:
        by_status[r["status"]] += 1
    return {
        "techniques_in_scope": total, "techniques_with_positive_tests": with_tests,
        "techniques_validated": validated,
        "validated_ratio": _ratio(validated, with_tests),
        "positive_tests": pos, "positive_tests_passed": passed,
        "by_status": dict(sorted(by_status.items())),
        "scope_note": "Denominator = techniques in mappings/attack-techniques.yaml, not total MITRE ATT&CK.",
    }


def write_coverage_csv(rows: list[dict], path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=["technique", "name", "tactic", "tests", "positive_tests", "negative_tests",
                                          "passed", "status"])
        w.writeheader()
        w.writerows(rows)
