"""What a run was tested against, so two runs can be judged comparable.

Hashes are content hashes of the files that define the experiment (rules, catalog, simulation
scripts, vendored atomic definitions), plus the framework version and - best effort, from the live
Wazuh API - the manager and agent versions. Nothing here contains credentials.
"""
from __future__ import annotations

import dataclasses
import hashlib
import json
from pathlib import Path

# Meta keys whose change means the *experiment* changed (not just the rules under test).
EXPERIMENT_KEYS = ("catalog_sha256", "custom_simulations_sha256", "atomic_sha256",
                   "framework_version", "wazuh_manager_version")
# Rules are what a regression run exists to change, so a difference there is informational.
SUBJECT_KEYS = ("rules_sha256",)


def tree_hash(root: Path, patterns: tuple[str, ...]) -> str | None:
    """SHA-256 over (relative path, content) of every matching file, in sorted order."""
    root = Path(root)
    if not root.is_dir():
        return None
    h = hashlib.sha256()
    files = sorted({p for pat in patterns for p in root.rglob(pat) if p.is_file()})
    for p in files:
        h.update(p.relative_to(root).as_posix().encode())
        h.update(b"\0")
        h.update(p.read_bytes())
        h.update(b"\0")
    return h.hexdigest() if files else None


def framework_version() -> str | None:
    try:
        from importlib.metadata import version
        return version("detection-validator")
    except Exception:
        pass
    try:
        import tomllib
        pyproject = Path(__file__).resolve().parents[2] / "pyproject.toml"
        return tomllib.loads(pyproject.read_text(encoding="utf-8"))["project"]["version"]
    except Exception:
        return None


def run_fingerprint(paths: dict, extra: dict | None = None) -> dict:
    """Offline fingerprint; ``extra`` carries live versions (manager/agents) when available."""
    meta = {
        "framework_version": framework_version(),
        "rules_sha256": tree_hash(paths["rules"], ("*.xml",)),
        "catalog_sha256": tree_hash(paths["catalog"], ("*.yaml", "*.yml")),
        "regression_catalog_sha256": tree_hash(paths["regression"], ("*.yaml", "*.yml")),
        "custom_simulations_sha256": tree_hash(paths["custom"], ("*.sh", "*.ps1", "*.py")),
        "atomic_sha256": tree_hash(paths["atomic"], ("*.yaml", "*.yml")),
    }
    meta.update({k: v for k, v in (extra or {}).items() if v is not None})
    return meta


def live_versions(api) -> dict:
    """Manager and agent versions from the Wazuh API. Failure yields a note, never an exception."""
    out: dict = {}
    try:
        info = api.manager_info()
        out["wazuh_manager_version"] = info.get("version")
    except Exception as exc:
        out["live_versions_error"] = f"{type(exc).__name__}: {exc}"[:200]
        return out
    try:
        out["agent_versions"] = {a.get("name"): a.get("version") for a in api.agents()}
    except Exception as exc:
        out["live_versions_error"] = f"{type(exc).__name__}: {exc}"[:200]
    return out


def definition_hash(test) -> str:
    """Stable hash of everything that defines a test (simulation, expectation, target, polarity)."""
    doc = json.dumps(dataclasses.asdict(test), sort_keys=True, default=str)
    return hashlib.sha256(doc.encode()).hexdigest()[:16]


def meta_diff(base: dict | None, cur: dict | None) -> dict:
    """Differences between two runs' fingerprints, split into experiment vs subject changes.

    A key missing on either side is 'unknown', not 'changed': old runs predate fingerprints.
    """
    base, cur = base or {}, cur or {}

    def diffs(keys):
        return [{"key": k, "baseline": base[k], "current": cur[k]}
                for k in keys if k in base and k in cur and base[k] != cur[k]]

    unknown = [k for k in EXPERIMENT_KEYS + SUBJECT_KEYS if (k in base) != (k in cur)
               or (k not in base and k not in cur)]
    return {"experiment_changed": diffs(EXPERIMENT_KEYS), "subject_changed": diffs(SUBJECT_KEYS),
            "unknown": unknown}
