"""Alert retrieval. The manager API does not serve alerts, so read them from the
Wazuh indexer (OpenSearch) or, if the runner is on the manager, from alerts.json."""
from __future__ import annotations

import json
import re
from abc import ABC, abstractmethod
from datetime import datetime, timezone
from pathlib import Path

import requests
import urllib3

from ..models import Alert

_TZ = re.compile(r"([+-]\d{2})(\d{2})$")


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


class AlertCollector(ABC):
    @abstractmethod
    def fetch(self, agent_name: str, since: datetime, until: datetime) -> list[Alert]: ...


class IndexerAlertCollector(AlertCollector):
    def __init__(self, url, user, password, index_pattern="wazuh-alerts-4.x-*", verify_tls=False):
        self.url, self.auth, self.index, self.verify = url.rstrip("/"), (user, password), index_pattern, verify_tls
        if not verify_tls:
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    def fetch(self, agent_name, since, until):
        body = {
            "size": 1000, "sort": [{"timestamp": "asc"}],
            "query": {"bool": {"filter": [
                {"term": {"agent.name": agent_name}},
                {"range": {"timestamp": {"gte": since.astimezone(timezone.utc).isoformat(),
                                         "lte": until.astimezone(timezone.utc).isoformat()}}},
            ]}},
        }
        r = requests.post(f"{self.url}/{self.index}/_search", json=body, auth=self.auth,
                          verify=self.verify, timeout=30)
        r.raise_for_status()
        return [parse_alert(h["_source"]) for h in r.json()["hits"]["hits"]]


class FileAlertCollector(AlertCollector):
    """Reads NDJSON alerts (e.g. /var/ossec/logs/alerts/alerts.json or a test fixture)."""

    def __init__(self, path: str | Path):
        self.path = Path(path)

    def fetch(self, agent_name, since, until):
        out = []
        if not self.path.exists():
            return out
        with open(self.path, encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    a = parse_alert(json.loads(line))
                except (ValueError, KeyError):
                    continue
                if a.agent_name == agent_name and since <= a.timestamp <= until:
                    out.append(a)
        return out


def build_collector(wazuh_cfg: dict) -> AlertCollector:
    a = wazuh_cfg["alerts"]
    if a.get("source") == "file":
        return FileAlertCollector(a["file_path"])
    return IndexerAlertCollector(a["indexer_url"], a["indexer_user"], a["indexer_password"],
                                 a.get("index_pattern", "wazuh-alerts-4.x-*"), wazuh_cfg.get("verify_tls", False))
