"""Baseline vs current comparison with an explicit verdict transition matrix.

Verdict classes: PASS = {TP, TN}, FAIL = {FN, FP}, ERROR (not scorable).

=========  ======================  ==========================================================
from       to                      reported as
=========  ======================  ==========================================================
same       same                    unchanged
PASS       FAIL                    regression      (detection regressed)
FAIL       PASS                    improvement
PASS/FAIL  ERROR                   inconclusive    kind=lost_signal (execution/collection)
ERROR      PASS/FAIL               inconclusive    kind=regained_signal (baseline unscorable)
FAIL       other FAIL / PASS<>PASS changed         (e.g. FN -> FP, or the test polarity changed)
=========  ======================  ==========================================================

An ERROR transition is never "unchanged": it means the run could not score the test at all, so it
must neither hide a regression nor be counted as one.
"""
from __future__ import annotations

from dataclasses import dataclass, field

PASS = {"TP", "TN"}
FAIL = {"FN", "FP"}


@dataclass
class RegressionReport:
    regressions: list[dict] = field(default_factory=list)    # passed before, fails now
    improvements: list[dict] = field(default_factory=list)   # failed before, passes now
    inconclusive: list[dict] = field(default_factory=list)   # an ERROR on either side
    changed: list[dict] = field(default_factory=list)        # FN<->FP and similar
    definition_changed: list[str] = field(default_factory=list)  # test body differs from the baseline's
    context: dict = field(default_factory=dict)  # fingerprint diff between the two runs
    new_tests: list[str] = field(default_factory=list)
    missing_tests: list[str] = field(default_factory=list)
    unchanged: int = 0

    @property
    def has_regressions(self) -> bool:
        return bool(self.regressions)

    @property
    def has_operational_failures(self) -> bool:
        """A test that was scorable in the baseline could not be scored now."""
        return any(i["kind"] == "lost_signal" for i in self.inconclusive)

    @property
    def compared(self) -> int:
        return (self.unchanged + len(self.regressions) + len(self.improvements)
                + len(self.inconclusive) + len(self.changed))


def compare(baseline: list[dict], current: list[dict], context: dict | None = None) -> RegressionReport:
    base = {r["test_id"]: r for r in baseline}
    cur = {r["test_id"]: r for r in current}
    rep = RegressionReport(new_tests=sorted(set(cur) - set(base)), missing_tests=sorted(set(base) - set(cur)),
                           context=context or {})
    for tid in sorted(set(base) & set(cur)):
        b, c = base[tid]["verdict"], cur[tid]["verdict"]
        entry = {"test_id": tid, "from": b, "to": c}
        bh, ch = base[tid].get("test_hash"), cur[tid].get("test_hash")
        if bh and ch and bh != ch:
            # same id, different definition: the comparison is not like for like
            entry["definition_changed"] = True
            rep.definition_changed.append(tid)
        if cur[tid].get("error"):
            entry["reason"] = cur[tid]["error"]
        if b == c:
            rep.unchanged += 1
        elif c == "ERROR":
            rep.inconclusive.append({**entry, "kind": "lost_signal"})
        elif b == "ERROR":
            rep.inconclusive.append({**entry, "kind": "regained_signal"})
        elif b in PASS and c in FAIL:
            rep.regressions.append(entry)
        elif b in FAIL and c in PASS:
            rep.improvements.append(entry)
        else:
            rep.changed.append(entry)
    return rep
