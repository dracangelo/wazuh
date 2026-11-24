from __future__ import annotations

import json

from ..models import Alert, Expected

# Top-level sections written by Wazuh itself; an execution id never legitimately originates there.
_EXCLUDED_SECTIONS = {"rule", "agent", "manager", "decoder", "cluster", "input", "location"}


def carries_exec_id(alert: Alert, exec_id: str) -> bool:
    """True when the alert's event payload (full_log, syscheck, data, ...) contains ``exec_id``."""
    payload = {k: v for k, v in alert.raw.items() if k not in _EXCLUDED_SECTIONS}
    return exec_id.lower() in json.dumps(payload, default=str).lower()


def alert_matches(alert: Alert, exp: Expected, exec_id: str | None = None) -> bool:
    """All specified criteria must hold; empty criteria are ignored. Level is a floor.

    With ``exp.correlation == "exec_id"`` the alert must also carry this execution's id; without an
    id nothing matches, so a missing id can never be mistaken for a pass.
    """
    if exp.rule_ids and alert.rule_id not in exp.rule_ids:
        return False
    if exp.rule_groups and not set(exp.rule_groups) & set(alert.rule_groups):
        return False
    if exp.mitre_ids and not set(exp.mitre_ids) & set(alert.mitre_ids):
        return False
    if alert.rule_level < exp.min_level:
        return False
    if exp.correlation == "exec_id":
        return bool(exec_id) and carries_exec_id(alert, exec_id)
    return True


def filter_matches(alerts: list[Alert], exp: Expected, exec_id: str | None = None) -> list[Alert]:
    return [a for a in alerts if alert_matches(a, exp, exec_id)]


def satisfied(alerts: list[Alert], exp: Expected, exec_id: str | None = None) -> bool:
    """Any matching alert satisfies a test, unless require_all demands every listed rule id fired."""
    matched = filter_matches(alerts, exp, exec_id)
    if not exp.require_all:
        return bool(matched)
    return set(exp.rule_ids) <= {a.rule_id for a in matched}


def missing_rules(alerts: list[Alert], exp: Expected, exec_id: str | None = None) -> list[str]:
    fired = {a.rule_id for a in filter_matches(alerts, exp, exec_id)}
    return [r for r in exp.rule_ids if r not in fired]
