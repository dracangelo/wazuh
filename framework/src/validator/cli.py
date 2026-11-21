from __future__ import annotations

import argparse
import sys
from pathlib import Path

from .adapters.atomic import AtomicAdapter
from .adapters.base import Target
from .adapters.custom import CustomAdapter
from .collectors.wazuh_alerts import build_collector
from .collectors.wazuh_api import WazuhAPI
from .config import load_environments, load_settings, load_yaml, repo_root
from .evaluation.metrics import compute_metrics, coverage_matrix, write_coverage_csv
from .orchestrator import Orchestrator, load_catalog, select
from .rules_lint import check_live, lint_dir
from .regression.runner import run_regression
from .reporting import csv_report, html_report, json_report, pdf_report
from .storage.database import connect
from .storage.repository import RunRepository

REPORTERS = {"json": json_report, "csv": csv_report, "html": html_report, "pdf": pdf_report}


def _ctx():
    root, settings = repo_root(), load_settings()
    paths = {k: root / v for k, v in settings["paths"].items()}
    return root, settings, paths


def _orchestrator(settings, paths):
    targets = {n: Target.from_config(n, c) for n, c in load_environments()["targets"].items()}
    repo = RunRepository(connect(paths["database"]))
    adapters = {"atomic": AtomicAdapter(paths["atomic"]), "custom": CustomAdapter(paths["custom"])}
    return Orchestrator(settings, targets, adapters, build_collector(settings["wazuh"]), repo,
                        paths["evidence"]), repo


def _filters(a):
    return dict(ids=a.id or None, platform=a.platform, technique=a.technique, tag=a.tag, source=a.source)


def cmd_list(a):
    _, _, paths = _ctx()
    for t in select(load_catalog(paths["catalog"]), **_filters(a)):
        print(f"{t.id:<22} {t.technique:<12} {t.platform:<8} {t.source:<7} {'NEG' if t.negative else 'POS'}  {t.name}")


def cmd_lint(a):
    _, _, paths = _ctx()
    tests = load_catalog(paths["catalog"]) + load_catalog(paths["regression"])
    print(f"OK: {len(tests)} tests parsed")


def cmd_run(a):
    _, settings, paths = _ctx()
    orch, repo = _orchestrator(settings, paths)
    tests = select(load_catalog(paths["catalog"]), **_filters(a))
    if not tests:
        print("no tests matched"); return 2
    run_id = orch.run(tests, label=a.label)
    m = compute_metrics(repo.results(run_id))
    print(f"\nrun {run_id}: TP={m['tp']} FN={m['fn']} TN={m['tn']} FP={m['fp']} ERR={m['errors']} "
          f"detection_rate={m['detection_rate']}")
    return 1 if (m["fn"] or m["fp"] or m["errors"]) and a.strict else 0


def cmd_report(a):
    _, settings, paths = _ctx()
    repo = RunRepository(connect(paths["database"]))
    run_id = a.run_id or repo.latest_run_id()
    if not run_id:
        print("no completed runs"); return 2
    rows, run = repo.results(run_id), repo.get_run(run_id)
    for fmt in a.format:
        out = REPORTERS[fmt].write(run, rows, compute_metrics(rows), paths["reports"] / f"run-{run_id}.{fmt}")
        print("wrote", out)


def cmd_regress(a):
    _, settings, paths = _ctx()
    orch, repo = _orchestrator(settings, paths)
    run_id, base, rep = run_regression(orch, repo, paths["regression"], a.baseline)
    print(f"\nrun {run_id} vs baseline {base}: {len(rep.regressions)} regressions, "
          f"{len(rep.improvements)} improvements, {rep.unchanged} unchanged")
    for r in rep.regressions:
        print(f"  REGRESSION {r['test_id']}: {r['from']} -> {r['to']}")
    return 1 if rep.has_regressions else 0


def cmd_coverage(a):
    _, settings, paths = _ctx()
    techniques = load_yaml(paths["techniques"]).get("techniques", {})
    repo = RunRepository(connect(paths["database"]))
    rows = coverage_matrix(techniques, load_catalog(paths["catalog"]), repo.last_verdicts())
    write_coverage_csv(rows, paths["coverage"])
    for r in rows:
        print(f"{r['technique']:<12} {r['status']:<9} {r['name']}")


def cmd_rules_check(a):
    _, settings, paths = _ctx()
    rep = lint_dir(paths["rules"])
    issues = list(rep.issues)
    if a.live:
        w = settings["wazuh"]
        issues += check_live(rep, WazuhAPI(w["api_url"], w["api_user"], w["api_password"], w.get("verify_tls", False)))
    for i in issues:
        print(i)
    errs = sum(i.severity == "error" for i in issues)
    print(f"{len(rep.rules)} rules, {len(rep.external_refs)} external parents, {errs} errors, {len(issues) - errs} warnings")
    return 1 if errs else 0


def cmd_doctor(a):
    _, settings, paths = _ctx()
    w = settings["wazuh"]
    api = WazuhAPI(w["api_url"], w["api_user"], w["api_password"], w.get("verify_tls", False))
    targets = load_environments()["targets"]
    agents = {x["name"]: x["status"] for x in api.agents()}
    bad = 0
    for name, cfg in targets.items():
        status = agents.get(cfg.get("agent_name", name), "not registered")
        print(f"{name:<16} agent={status}")
        bad += status != "active"
    ids = {i for t in load_catalog(paths["catalog"]) for i in t.expected.rule_ids}
    for rid in sorted(ids):
        ok = api.rule_exists(rid)
        print(f"rule {rid:<8} {'loaded' if ok else 'MISSING'}")
        bad += not ok
    return 1 if bad else 0


def main(argv=None):
    p = argparse.ArgumentParser(prog="dv", description="Detection rule validation framework")
    sub = p.add_subparsers(dest="cmd", required=True)

    def filt(sp):
        sp.add_argument("--id", action="append"); sp.add_argument("--platform")
        sp.add_argument("--technique", help="prefix match, e.g. T1110"); sp.add_argument("--tag")
        sp.add_argument("--source", choices=["atomic", "custom"])

    s = sub.add_parser("list"); filt(s); s.set_defaults(fn=cmd_list)
    sub.add_parser("lint", help="validate catalog files").set_defaults(fn=cmd_lint)
    s = sub.add_parser("run"); filt(s); s.add_argument("--label"); s.add_argument("--strict", action="store_true")
    s.set_defaults(fn=cmd_run)
    s = sub.add_parser("report"); s.add_argument("--run-id", type=int)
    s.add_argument("--format", nargs="+", choices=list(REPORTERS), default=["json", "html"]); s.set_defaults(fn=cmd_report)
    s = sub.add_parser("regress"); s.add_argument("--baseline", type=int); s.set_defaults(fn=cmd_regress)
    sub.add_parser("coverage").set_defaults(fn=cmd_coverage)
    s = sub.add_parser("rules-check", help="lint Wazuh rule XML (add --live to verify parents on the manager)")
    s.add_argument("--live", action="store_true"); s.set_defaults(fn=cmd_rules_check)
    sub.add_parser("doctor", help="check Wazuh API, agents, and expected rules").set_defaults(fn=cmd_doctor)

    a = p.parse_args(argv)
    try:
        return a.fn(a) or 0
    except Exception as exc:
        print(f"error: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 3


if __name__ == "__main__":
    sys.exit(main())
