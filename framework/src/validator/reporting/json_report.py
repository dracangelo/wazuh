import json
from pathlib import Path


def write(run: dict, rows: list[dict], metrics: dict, path: Path) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps({"run": run, "metrics": metrics, "results": rows}, indent=2, default=str),
                    encoding="utf-8")
    return path
