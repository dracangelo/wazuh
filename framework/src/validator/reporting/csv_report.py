import csv
from pathlib import Path

FIELDS = ["test_id", "name", "technique", "platform", "negative", "verdict", "latency_seconds",
          "matched_rule_ids", "error"]


def write(run: dict, rows: list[dict], metrics: dict, path: Path) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=FIELDS, extrasaction="ignore")
        w.writeheader()
        for r in rows:
            w.writerow({**r, "matched_rule_ids": ";".join(r.get("matched_rule_ids", []))})
    return path
