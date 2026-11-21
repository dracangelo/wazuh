"""Static checks for Wazuh rule XML. Offline: well-formedness, duplicate ids, id range, levels,
description, frequency/timeframe pairing, MITRE id format, regex compilation, parent ordering.
Live (optional): every parent rule outside our id range must exist on the manager."""
from __future__ import annotations

import re
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from pathlib import Path

ID_RANGE = (100000, 120000)
MITRE = re.compile(r"^T\d{4}(\.\d{3})?$")


@dataclass
class Issue:
    severity: str  # "error" | "warn"
    file: str
    rule_id: int | None
    message: str

    def __str__(self) -> str:
        rid = f" rule {self.rule_id}" if self.rule_id else ""
        return f"{self.severity.upper():5} {self.file}{rid}: {self.message}"


@dataclass
class LintReport:
    rules: dict[int, dict] = field(default_factory=dict)
    issues: list[Issue] = field(default_factory=list)
    external_refs: set[int] = field(default_factory=set)

    @property
    def errors(self) -> list[Issue]:
        return [i for i in self.issues if i.severity == "error"]


def _refs(rule: ET.Element) -> list[int]:
    out = []
    for tag in ("if_sid", "if_matched_sid"):
        for el in rule.findall(tag):
            out += [int(x) for x in re.split(r"[,\s]+", (el.text or "").strip()) if x.isdigit()]
    return out


def lint_dir(rules_dir: Path) -> LintReport:
    rep = LintReport()
    order: dict[int, int] = {}
    pending: list[tuple[str, int, list[int]]] = []
    for path in sorted(Path(rules_dir).rglob("*.xml")):
        if "agent-config" in path.parts:
            continue
        name = path.name
        try:
            root = ET.fromstring(f"<root>{path.read_text(encoding='utf-8')}</root>")
        except ET.ParseError as exc:
            rep.issues.append(Issue("error", name, None, f"XML not well-formed: {exc}"))
            continue
        for rule in root.iter("rule"):
            try:
                rid = int(rule.get("id", ""))
            except ValueError:
                rep.issues.append(Issue("error", name, None, f"bad rule id {rule.get('id')!r}"))
                continue
            if rid in rep.rules:
                rep.issues.append(Issue("error", name, rid, f"duplicate id (also in {rep.rules[rid]['file']})"))
            if not ID_RANGE[0] <= rid < ID_RANGE[1]:
                rep.issues.append(Issue("error", name, rid, f"id outside custom range {ID_RANGE}"))
            lvl = rule.get("level", "")
            if not lvl.isdigit() or not 0 <= int(lvl) <= 15:
                rep.issues.append(Issue("error", name, rid, f"level must be 0-15, got {lvl!r}"))
            level = int(lvl) if lvl.isdigit() else 0
            if rule.find("description") is None or not (rule.findtext("description") or "").strip():
                rep.issues.append(Issue("error", name, rid, "missing <description>"))
            if bool(rule.get("frequency")) != bool(rule.get("timeframe")) and rule.get("frequency"):
                rep.issues.append(Issue("error", name, rid, "frequency requires timeframe"))
            mitre = [(e.text or "").strip() for e in rule.findall("mitre/id")]
            for m in mitre:
                if not MITRE.match(m):
                    rep.issues.append(Issue("error", name, rid, f"invalid MITRE id {m!r}"))
            if level >= 8 and not mitre:
                rep.issues.append(Issue("warn", name, rid, "level >= 8 without MITRE mapping"))
            for el in list(rule.findall("regex")) + [f for f in rule.findall("field") if f.get("type") == "pcre2"]:
                if el.tag == "regex" and el.get("type") != "pcre2":
                    continue
                try:
                    re.compile(el.text or "")
                except re.error as exc:
                    rep.issues.append(Issue("error", name, rid, f"regex does not compile: {exc}"))
            refs = _refs(rule)
            rep.rules[rid] = {"file": name, "level": level, "mitre": mitre, "refs": refs}
            order[rid] = len(order)
            pending.append((name, rid, refs))
    for name, rid, refs in pending:
        for ref in refs:
            if ref in rep.rules:
                if order[ref] > order[rid]:
                    rep.issues.append(Issue("warn", name, rid, f"parent {ref} is defined after this rule"))
            elif ID_RANGE[0] <= ref < ID_RANGE[1]:
                rep.issues.append(Issue("error", name, rid, f"parent {ref} not defined in this repo"))
            else:
                rep.external_refs.add(ref)
    return rep


def check_live(rep: LintReport, api) -> list[Issue]:
    issues = []
    for ref in sorted(rep.external_refs):
        if not api.rule_exists(str(ref)):
            users = [r for r, d in rep.rules.items() if ref in d["refs"]]
            issues.append(Issue("error", "manager", None,
                                f"parent rule {ref} not found on manager (used by {users})"))
    return issues
