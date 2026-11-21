from __future__ import annotations

from ..models import Alert, Expected


def alert_matches(alert: Alert, exp: Expected) -> bool:
    """All specified criteria must hold; empty criteria are ignored. Level is a floor."""
    if exp.rule_ids and alert.rule_id not in exp.rule_ids:
        return False
    if exp.rule_groups and not set(exp.rule_groups) & set(alert.rule_groups):
        return False
    if exp.mitre_ids and not set(exp.mitre_ids) & set(alert.mitre_ids):
        return False
    return alert.rule_level >= exp.min_level


def filter_matches(alerts: list[Alert], exp: Expected) -> list[Alert]:
    return [a for a in alerts if alert_matches(a, exp)]


def satisfied(alerts: list[Alert], exp: Expected) -> bool:
    """Any matching alert satisfies a test, unless require_all demands every listed rule id fired."""
    matched = filter_matches(alerts, exp)
    if not exp.require_all:
        return bool(matched)
    return set(exp.rule_ids) <= {a.rule_id for a in matched}


def missing_rules(alerts: list[Alert], exp: Expected) -> list[str]:
    fired = {a.rule_id for a in filter_matches(alerts, exp)}
    return [r for r in exp.rule_ids if r not in fired]
