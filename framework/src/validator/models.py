from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Any


class Verdict(str, Enum):
    TP = "TP"        # attack ran, expected alert fired
    FN = "FN"        # attack ran, expected alert did NOT fire (coverage gap)
    TN = "TN"        # benign activity, no alert (good)
    FP = "FP"        # benign activity, alert fired (noisy rule)
    ERROR = "ERROR"  # simulation/collection failed; result is not trustworthy


PASSING = {Verdict.TP, Verdict.TN}


@dataclass
class Expected:
    rule_ids: list[str] = field(default_factory=list)
    rule_groups: list[str] = field(default_factory=list)
    mitre_ids: list[str] = field(default_factory=list)
    min_level: int = 0
    timeout_seconds: int | None = None
    require_all: bool = False  # every id in rule_ids must fire (default: any one)


@dataclass
class TestCase:
    __test__ = False  # keep pytest from collecting this class

    id: str
    name: str
    technique: str
    platform: str
    source: str            # "atomic" | "custom"
    target: str            # key in environments.yaml
    expected: Expected
    negative: bool = False  # True => `expected` describes alerts that must NOT fire
    tags: list[str] = field(default_factory=list)
    simulation: dict[str, Any] = field(default_factory=dict)
    path: Path | None = None

    REQUIRED = ("id", "name", "technique", "platform", "source", "target")

    @classmethod
    def from_dict(cls, d: dict, path: Path | None = None) -> "TestCase":
        missing = [k for k in cls.REQUIRED if k not in d]
        if missing:
            raise ValueError(f"{path or ''} test {d.get('id', '?')}: missing {missing}")
        if d["source"] not in ("atomic", "custom"):
            raise ValueError(f"{d['id']}: source must be 'atomic' or 'custom'")
        e = d.get("expected") or {}
        exp = Expected(
            rule_ids=[str(x) for x in e.get("rule_ids", [])],
            rule_groups=list(e.get("rule_groups", [])),
            mitre_ids=list(e.get("mitre_ids", [])),
            min_level=int(e.get("min_level", 0)),
            timeout_seconds=e.get("timeout_seconds"),
            require_all=bool(e.get("require_all", False)),
        )
        if exp.require_all and len(exp.rule_ids) < 2:
            raise ValueError(f"{d['id']}: require_all needs at least two rule_ids")
        negative = bool(d.get("negative", False))
        if not negative and not (exp.rule_ids or exp.rule_groups or exp.mitre_ids):
            raise ValueError(f"{d['id']}: positive test needs rule_ids, rule_groups or mitre_ids")
        return cls(
            id=d["id"], name=d["name"], technique=d["technique"], platform=d["platform"],
            source=d["source"], target=d["target"], expected=exp, negative=negative,
            tags=list(d.get("tags", [])), simulation=dict(d.get("simulation", {})), path=path,
        )


@dataclass
class ExecutionResult:
    started_at: datetime
    finished_at: datetime
    success: bool
    exit_code: int | None = None
    stdout: str = ""
    stderr: str = ""
    error: str | None = None


@dataclass
class Alert:
    id: str
    timestamp: datetime
    rule_id: str
    rule_level: int
    rule_description: str
    rule_groups: list[str]
    mitre_ids: list[str]
    agent_name: str
    raw: dict = field(default_factory=dict)


@dataclass
class TestResult:
    __test__ = False

    test: TestCase
    verdict: Verdict
    execution: ExecutionResult | None = None
    matched_alerts: list[Alert] = field(default_factory=list)
    all_alerts: list[Alert] = field(default_factory=list)
    latency_seconds: float | None = None
    error: str | None = None

    @property
    def passed(self) -> bool:
        return self.verdict in PASSING

    def to_row(self) -> dict:
        return {
            "test_id": self.test.id,
            "name": self.test.name,
            "technique": self.test.technique,
            "platform": self.test.platform,
            "negative": self.test.negative,
            "verdict": self.verdict.value,
            "latency_seconds": self.latency_seconds,
            "matched_rule_ids": sorted({a.rule_id for a in self.matched_alerts}),
            "error": self.error,
        }
