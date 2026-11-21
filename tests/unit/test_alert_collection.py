"""Offline alert-collection tests: fake indexer and file fixtures, no network and no Wazuh."""
import json
from datetime import datetime, timedelta, timezone

import requests

from validator.adapters.base import Adapter, Target
from validator.collectors import wazuh_alerts
from validator.collectors.wazuh_alerts import (
    AlertBatch,
    FileAlertCollector,
    IndexerAlertCollector,
)
from validator.models import ExecutionResult, Expected, TestCase, Verdict
from validator.orchestrator import Orchestrator
from validator.safety import SafetyPolicy
from validator.storage.database import connect
from validator.storage.repository import RunRepository

T0 = datetime(2026, 1, 1, 10, 0, tzinfo=timezone.utc)
SINCE, UNTIL = T0 - timedelta(minutes=1), T0 + timedelta(minutes=1)


class FakeResponse:
    def __init__(self, payload):
        self._payload = payload

    def raise_for_status(self):
        pass

    def json(self):
        return self._payload


class FakeIndexer:
    """Minimal OpenSearch _search: sorted docs, `size` limit and `search_after` continuation."""

    def __init__(self, count, rule_id="5712", fail_at_request=None):
        self.docs = [self._doc(i, rule_id) for i in range(count)]
        self.requests = []
        self.fail_at_request = fail_at_request

    @staticmethod
    def _doc(i, rule_id="5712"):
        ts = (T0 + timedelta(milliseconds=i)).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "+0000"
        return {
            "_source": {"id": f"a{i}", "timestamp": ts, "rule": {"id": rule_id, "level": 10},
                        "agent": {"name": "lab"}},
            "sort": [ts, f"a{i}"],
        }

    def post(self, url, json=None, **kwargs):
        self.requests.append(json)
        if self.fail_at_request == len(self.requests):
            raise requests.HTTPError("503 Server Error: indexer unavailable")
        after = json.get("search_after")
        start = 0
        if after is not None:
            positions = [n for n, d in enumerate(self.docs) if d["sort"] == after]
            start = positions[0] + 1 if positions else len(self.docs)
        return FakeResponse({"hits": {"hits": self.docs[start:start + json["size"]]}})


def install(monkeypatch, count, **kwargs):
    indexer = FakeIndexer(count, **kwargs)
    monkeypatch.setattr(wazuh_alerts.requests, "post", indexer.post)
    return indexer


def collector(**kwargs):
    options = {"max_alerts": 500, "page_size": 50} | kwargs
    return IndexerAlertCollector("https://indexer:9200", "u", "p", **options)


def test_search_after_collects_every_page_without_loss(monkeypatch):
    indexer = install(monkeypatch, 120)
    batch = collector().fetch("lab", SINCE, UNTIL)
    assert [a.id for a in batch.alerts] == [f"a{i}" for i in range(120)]
    assert not batch.truncated and batch.reason is None
    assert batch.pages_fetched == 3
    assert [r["size"] for r in indexer.requests] == [50, 50, 50]
    assert indexer.requests[1]["search_after"] == indexer.docs[49]["sort"]
    assert indexer.requests[2]["search_after"] == indexer.docs[99]["sort"]


def test_hitting_the_cap_is_reported_as_truncated(monkeypatch):
    install(monkeypatch, 120)
    batch = collector(max_alerts=60).fetch("lab", SINCE, UNTIL)
    assert [a.id for a in batch.alerts] == [f"a{i}" for i in range(60)]
    assert batch.truncated and batch.max_alerts == 60
    assert "cap" in batch.reason


def test_exact_cap_without_more_alerts_is_not_truncated(monkeypatch):
    install(monkeypatch, 60)
    batch = collector(max_alerts=60).fetch("lab", SINCE, UNTIL)
    assert len(batch.alerts) == 60
    assert not batch.truncated and batch.reason is None


def test_invalid_limits_are_refused():
    for kwargs in ({"max_alerts": 0}, {"page_size": 0}):
        try:
            collector(**kwargs)
        except ValueError:
            continue
        raise AssertionError(f"expected ValueError for {kwargs}")


def test_file_collector_applies_the_same_cap(tmp_path):
    path = tmp_path / "alerts.json"
    path.write_text("".join(json.dumps(FakeIndexer._doc(i)["_source"]) + "\n" for i in range(3)),
                    encoding="utf-8")
    full = FileAlertCollector(path).fetch("lab", SINCE, UNTIL)
    assert len(full.alerts) == 3 and not full.truncated
    capped = FileAlertCollector(path, max_alerts=2).fetch("lab", SINCE, UNTIL)
    assert len(capped.alerts) == 2 and capped.truncated and capped.reason


class TruncatingCollector:
    def __init__(self, batch):
        self.batch, self.calls = batch, 0

    def fetch(self, agent_name, since, until):
        self.calls += 1
        return self.batch


class OkAdapter(Adapter):
    def run(self, test, target):
        now = datetime.now(timezone.utc)
        return ExecutionResult(now, now, True, 0)


def run_once(tmp_path, collector):
    repo = RunRepository(connect(tmp_path / "db.sqlite"))
    orch = Orchestrator({"evaluation": {"default_timeout_seconds": 1, "poll_interval_seconds": 0}},
                        {"lab": Target("lab", "linux", "local", "lab")}, {"custom": OkAdapter()},
                        collector, repo, tmp_path / "evidence", sleep=lambda _: None,
                        policy=SafetyPolicy(lab_acknowledged=True))
    test = TestCase("t", "n", "T1110", "linux", "custom", "lab",
                    Expected(rule_ids=["5712"], timeout_seconds=1))
    return repo.results(orch.run([test], progress=lambda _: None))[0]


def test_truncated_collection_is_error_not_fn(tmp_path):
    batch = AlertBatch([], truncated=True, max_alerts=10,
                       reason="alert cap reached (10 alerts); the collection window is incomplete")
    collector = TruncatingCollector(batch)
    row = run_once(tmp_path, collector)
    assert row["verdict"] == Verdict.ERROR.value
    assert "truncated" in row["error"]
    assert collector.calls == 1


def test_http_error_on_later_page_is_error_not_fn(tmp_path, monkeypatch):
    # The first page holds only unrelated alerts, so a failure on page 2 must not yield a quiet FN.
    indexer = install(monkeypatch, 120, rule_id="9999", fail_at_request=2)
    row = run_once(tmp_path, collector())
    assert row["verdict"] == Verdict.ERROR.value
    assert "alert collection failed" in row["error"]
    assert "indexer unavailable" in row["error"]
    assert len(indexer.requests) == 2 and indexer.requests[1]["search_after"] is not None
