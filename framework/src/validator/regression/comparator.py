from __future__ import annotations

from dataclasses import dataclass, field

PASS = {"TP", "TN"}


@dataclass
class RegressionReport:
    regressions: list[dict] = field(default_factory=list)   # passed before, fails now
    improvements: list[dict] = field(default_factory=list)  # failed before, passes now
    new_tests: list[str] = field(default_factory=list)
    missing_tests: list[str] = field(default_factory=list)
    unchanged: int = 0

    @property
    def has_regressions(self) -> bool:
        return bool(self.regressions)


def compare(baseline: list[dict], current: list[dict]) -> RegressionReport:
    base = {r["test_id"]: r for r in baseline}
    cur = {r["test_id"]: r for r in current}
    rep = RegressionReport(new_tests=sorted(set(cur) - set(base)), missing_tests=sorted(set(base) - set(cur)))
    for tid in sorted(set(base) & set(cur)):
        b, c = base[tid]["verdict"], cur[tid]["verdict"]
        if b == c:
            rep.unchanged += 1
        elif b in PASS and c not in PASS:
            rep.regressions.append({"test_id": tid, "from": b, "to": c})
        elif b not in PASS and c in PASS:
            rep.improvements.append({"test_id": tid, "from": b, "to": c})
        else:
            rep.unchanged += 1  # e.g. FN -> ERROR: still not passing
    return rep
