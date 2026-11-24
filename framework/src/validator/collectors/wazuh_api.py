"""Wazuh manager REST API (port 55000): auth, agent status, rule existence checks."""
from __future__ import annotations

import requests
import urllib3


class WazuhAPI:
    def __init__(self, url: str, user: str, password: str, verify_tls: bool = False, timeout: int = 15):
        self.url, self.user, self.password = url.rstrip("/"), user, password
        self.verify, self.timeout, self._token = verify_tls, timeout, None
        if not verify_tls:
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    def _auth(self) -> str:
        r = requests.post(f"{self.url}/security/user/authenticate?raw=true", auth=(self.user, self.password),
                          verify=self.verify, timeout=self.timeout)
        r.raise_for_status()
        self._token = r.text.strip()
        return self._token

    def _get(self, path: str, **params) -> dict:
        for attempt in (1, 2):
            token = self._token or self._auth()
            r = requests.get(f"{self.url}{path}", headers={"Authorization": f"Bearer {token}"},
                             params=params, verify=self.verify, timeout=self.timeout)
            if r.status_code == 401 and attempt == 1:
                self._token = None
                continue
            r.raise_for_status()
            return r.json()
        raise RuntimeError("unreachable")

    def manager_info(self) -> dict:
        items = self._get("/manager/info").get("data", {}).get("affected_items", [])
        return items[0] if items else {}

    def agents(self) -> list[dict]:
        return self._get("/agents", limit=500).get("data", {}).get("affected_items", [])

    def agent_status(self, agent_name: str) -> str | None:
        for a in self.agents():
            if a.get("name") == agent_name:
                return a.get("status")
        return None

    def rule_exists(self, rule_id: str) -> bool:
        return bool(self._get("/rules", rule_ids=rule_id).get("data", {}).get("total_affected_items"))
