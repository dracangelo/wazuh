"""Structural checks for the reference Sigma rules (no Sigma backend is installed)."""
import re
import uuid
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[2]
SIGMA_DIR = ROOT / "rules" / "sigma"
REQUIRED = ("title", "id", "status", "logsource", "detection", "level", "tags")
LEVELS = {"informational", "low", "medium", "high", "critical"}
TECHNIQUE_TAG = re.compile(r"^attack\.t\d{4}(\.\d{3})?$")


def rules():
    return sorted(SIGMA_DIR.rglob("*.yml"))


def test_sigma_rules_are_well_formed_and_unique():
    files = rules()
    assert len(files) >= 30, f"only {len(files)} Sigma rules found"
    seen = {}
    for path in files:
        doc = yaml.safe_load(path.read_text(encoding="utf-8"))
        assert isinstance(doc, dict) and doc, f"{path}: empty or not a mapping"
        missing = [key for key in REQUIRED if key not in doc]
        assert not missing, f"{path}: missing {missing}"
        uuid.UUID(str(doc["id"]))  # raises when the id is not a UUID
        assert doc["id"] not in seen, f"{path}: duplicate id also used by {seen.get(doc['id'])}"
        seen[doc["id"]] = path
        assert doc["status"] in {"experimental", "test", "stable"}, f"{path}: bad status"
        assert doc["level"] in LEVELS, f"{path}: bad level {doc['level']!r}"
        logsource = doc["logsource"]
        assert isinstance(logsource, dict) and (logsource.get("category") or logsource.get("service")), \
            f"{path}: logsource needs a category or service"
        detection = doc["detection"]
        assert isinstance(detection, dict) and detection.get("condition"), \
            f"{path}: detection needs a condition"
        attack_tags = [t for t in doc["tags"] if str(t).startswith("attack.t")]
        assert attack_tags, f"{path}: no ATT&CK technique tag"
        for tag in attack_tags:
            assert TECHNIQUE_TAG.match(str(tag)), f"{path}: malformed technique tag {tag!r}"
