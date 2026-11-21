"""Alert retrieval. The manager API does not serve alerts, so read them from the
Wazuh indexer (OpenSearch) or, if the runner is on the manager, from alerts.json."""
from __future__ import annotations

import json
import re
from abc import ABC, abstractmethod
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

import requests
import urllib3

from ..models import Alert

_TZ = re.compile(r"([+-]\d{2})(\d{2})$")
# search_after needs a total order; `id` (present on every Wazuh alert) breaks timestamp ties so a
# page boundary cannot silently swallow alerts that share a millisecond.
_SORT = [{"timestamp": {"order": "asc"}}, {"id": {"order": "asc", "unmapped_type": "keyword"}}]
DEFAULT_MAX_ALERTS = 5000
DEFAULT_PAGE_SIZE = 1000


def parse_ts(s: str) -> datetime:
    s = s.replace("Z", "+00:00")
    s = _TZ.sub(r"\1:\2", s)
    dt = datetime.fromisoformat(s)
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def parse_alert(doc: dict) -> Alert:
    rule = doc.get("rule", {})
    return Alert(
        id=str(doc.get("id", "")), timestamp=parse_ts(doc["timestamp"]), rule_id=str(rule.get("id", "")),
        rule_level=int(rule.get("level", 0)), rule_description=rule.get("description", ""),
        rule_groups=list(rule.get("groups", [])), mitre_ids=list(rule.get("mitre", {}).get("id", [])),
        agent_name=doc.get("agent", {}).get("name", ""), raw=doc,
    )


@dataclass(frozen=True)
class AlertBatch:
    """Alerts for one collection window plus how complete that collection is.

    ``truncated`` means the collector stopped at its cap, so the window may be missing alerts. The
    orchestrator turns that into ``ERROR``: an incomplete window must never be scored as ``FN``.
    """

    alerts: list[Alert]
    truncated: bool = False
    pages_fetched: int = 0
    max_alerts: int = DEFAULT_MAX_ALERTS
    reason: str | None = None


def _batch(alerts: list[Alert], pages: int, cap: int, truncated: bool) -> AlertBatch:
    reason = f"alert cap reached ({cap} alerts); the collection window is incomplete" if truncated else None
    return AlertBatch(alerts, truncated, pages, cap, reason)


class AlertCollector(ABC):
    @abstractmethod
    def fetch(self, agent_name: str, since: datetime, until: datetime) -> AlertBatch: ...


class IndexerAlertCollector(AlertCollector):
    """Reads alert documents from the indexer, one ``search_after`` page at a time."""

    def __init__(self, url, user, password, index_pattern="wazuh-alerts-4.x-*", verify_tls=False,
                 max_alerts=DEFAULT_MAX_ALERTS, page_size=DEFAULT_PAGE_SIZE):
        if max_alerts < 1 or page_size < 1:
            raise ValueError("alerts.max_alerts and alerts.page_size must be at least 1")
        self.url, self.auth, self.index, self.verify = url.rstrip("/"), (user, password), index_pattern, verify_tls
        self.max_alerts, self.page_size = int(max_alerts), int(page_size)
        if not verify_tls:
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    def fetch(self, agent_name, since, until) -> AlertBatch:
        alerts: list[Alert] = []
        pages, search_after, truncated = 0, None, False
        while True:
            remaining = self.max_alerts - len(alerts)
            # Ask for one document past the remaining budget: receiving it proves the window is truncated.
            body = {
                "size": min(self.page_size, remaining + 1), "sort": _SORT, "track_total_hits": False,
                "query": {"bool": {"filter": [
                    {"term": {"agent.name": agent_name}},
                    {"range": {"timestamp": {"gte": since.astimezone(timezone.utc).isoformat(),
                                             "lte": until.astimezone(timezone.utc).isoformat()}}},
                ]}},
            }
            if search_after is not None:
                body["search_after"] = search_after
            r = requests.post(f"{self.url}/{self.index}/_search", json=body, auth=self.auth,
                              verify=self.verify, timeout=30)
            r.raise_for_status()
            hits = r.json()["hits"]["hits"]
            pages += 1
            if not hits:
                break
            alerts.extend(parse_alert(h["_source"]) for h in hits[:remaining])
            if len(hits) > remaining:
                truncated = True
                break
            search_after = hits[-1].get("sort")
            if search_after is None:
                raise ValueError("indexer response has no sort values; cannot page with search_after")
            if len(hits) < body["size"]:
                break
        return _batch(alerts, pages, self.max_alerts, truncated)


class FileAlertCollector(AlertCollector):
    """Reads NDJSON alerts (e.g. /var/ossec/logs/alerts/alerts.json or a test fixture)."""

    def __init__(self, path: str | Path, max_alerts: int = DEFAULT_MAX_ALERTS):
        if max_alerts < 1:
            raise ValueError("alerts.max_alerts must be at least 1")
        self.path, self.max_alerts = Path(path), int(max_alerts)

    def fetch(self, agent_name, since, until) -> AlertBatch:
        out: list[Alert] = []
        truncated = False
        if self.path.exists():
            with open(self.path, encoding="utf-8") as fh:
                for line in fh:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        a = parse_alert(json.loads(line))
                    except (ValueError, KeyError):
                        continue
                    if a.agent_name != agent_name or not since <= a.timestamp <= until:
                        continue
                    if len(out) >= self.max_alerts:
                        truncated = True
                        break
                    out.append(a)
        return _batch(out, 1 if out else 0, self.max_alerts, truncated)


def build_collector(wazuh_cfg: dict) -> AlertCollector:
    a = wazuh_cfg["alerts"]
    cap = int(a.get("max_alerts", DEFAULT_MAX_ALERTS))
    if a.get("source") == "file":
        return FileAlertCollector(a["file_path"], max_alerts=cap)
    return IndexerAlertCollector(a["indexer_url"], a["indexer_user"], a["indexer_password"],
                                 a.get("index_pattern", "wazuh-alerts-4.x-*"),
                                 wazuh_cfg.get("verify_tls", False),
                                 max_alerts=cap, page_size=int(a.get("page_size", DEFAULT_PAGE_SIZE)))
