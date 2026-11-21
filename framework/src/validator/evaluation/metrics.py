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
    by_tech: dict[str, dict] = defaultdict(lambda: defaultdict(int))
    for r in rows:
        c[r["verdict"]] += 1
        by_tech[r["technique"]][r["verdict"]] += 1
        if r["verdict"] == "TP" and r.get("latency_seconds") is not None:
            lat.append(r["latency_seconds"])
    tp, fn, tn, fp = c["TP"], c["FN"], c["TN"], c["FP"]
    return {
        "total": len(rows), "tp": tp, "fn": fn, "tn": tn, "fp": fp, "errors": c["ERROR"],
        "detection_rate": _ratio(tp, tp + fn),          # recall over attack tests
        "precision": _ratio(tp, tp + fp),
        "false_positive_rate": _ratio(fp, fp + tn),
        "mean_time_to_detect_s": round(sum(lat) / len(lat), 2) if lat else None,
        "by_technique": {t: dict(v) for t, v in sorted(by_tech.items())},
    }


def coverage_matrix(techniques: dict, tests: list, last_verdicts: dict[str, str]) -> list[dict]:
    """techniques: mappings/attack-techniques.yaml 'techniques' dict. One row per technique."""
    rows = []
    for tid, meta in sorted(techniques.items()):
        ts = [t for t in tests if t.technique == tid]
        verdicts = [last_verdicts.get(t.id) for t in ts if not t.negative]
        status = "no-test" if not ts else (
            "untested" if not any(verdicts) else
            "covered" if all(v == "TP" for v in verdicts if v) else "gap")
        rows.append({"technique": tid, "name": meta.get("name", ""), "tactic": meta.get("tactic", ""),
                     "tests": len(ts), "negative_tests": sum(t.negative for t in ts), "status": status})
    return rows


def write_coverage_csv(rows: list[dict], path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=["technique", "name", "tactic", "tests", "negative_tests", "status"])
        w.writeheader()
        w.writerows(rows)
