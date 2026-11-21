"""Config + path helpers. Repo root is auto-detected (override with DV_ROOT)."""
from __future__ import annotations

import os
import re
from pathlib import Path
from typing import Any

import yaml

_VAR = re.compile(r"\$\{([A-Z0-9_]+)\}")


def repo_root() -> Path:
    return Path(os.environ.get("DV_ROOT") or Path(__file__).resolve().parents[3])


def _expand(value: Any) -> Any:
    if isinstance(value, str):
        return _VAR.sub(lambda m: os.environ.get(m.group(1), ""), value)
    if isinstance(value, dict):
        return {k: _expand(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_expand(v) for v in value]
    return value


def load_yaml(path: Path) -> Any:
    with open(path, encoding="utf-8") as fh:
        return _expand(yaml.safe_load(fh) or {})


def load_settings(root: Path | None = None) -> dict:
    root = root or repo_root()
    return load_yaml(root / "framework" / "config" / "settings.yaml")


def load_environments(root: Path | None = None) -> dict:
    root = root or repo_root()
    return load_yaml(root / "framework" / "config" / "environments.yaml")
