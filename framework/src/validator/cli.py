from __future__ import annotations

import argparse
import logging
import sys

from .adapters.atomic import AtomicAdapter
from .adapters.base import Target
from .adapters.custom import CustomAdapter
from .canary import PipelineCanary
from .collectors.wazuh_alerts import build_collector
from .collectors.wazuh_api import WazuhAPI
from .config import load_environments, load_settings, load_yaml, repo_root
from .evaluation.metrics import compute_metrics, coverage_matrix, coverage_summary, write_coverage_csv
from .fingerprint import live_versions, run_fingerprint
from .orchestrator import Orchestrator, load_catalog, select
from .regression.runner import run_regression
from .reporting import csv_report, html_report, json_report, pdf_report
from .rules_lint import check_live, lint_dir
from .safety import SafetyPolicy, blocked_reason
from .storage.database import connect
from .storage.repository import RunRepository

REPORTERS = {"json": json_report, "csv": csv_report, "html": html_report, "pdf": pdf_report}


def _ctx():
    root, settings = repo_root(), load_settings()
    paths = {k: root / v for k, v in settings["paths"].items()}
    return root, settings, paths


def _targets():
    return {n: Target.from_config(n, c) for n, c in load_environments()["targets"].items()}


def _pipeline_canary(settings, paths, policy, enabled=True):
    return PipelineCanary(settings, _targets(), build_collector(settings["wazuh"]), policy,
                          paths["custom"], enabled=None if enabled else False,
                          disabled_detail="disabled by --no-canary")


def _orchestrator(settings, paths, policy=None, canary_enabled=True):
    targets = _targets()
    repo = RunRepository(connect(paths["database"]))
    command_timeout = int(settings.get("evaluation", {}).get("command_timeout_seconds", 300))
    adapters = {"atomic": AtomicAdapter(paths["atomic"], default_timeout=command_timeout),
                "custom": CustomAdapter(paths["custom"], default_timeout=command_timeout)}
    policy = policy or SafetyPolicy.from_settings(settings)
    collector = build_collector(settings["wazuh"])
    canary = PipelineCanary(settings, targets, collector, policy, paths["custom"],
                            enabled=None if canary_enabled else False,
                            disabled_detail="disabled by --no-canary")
    return Orchestrator(settings, targets, adapters, collector, repo, paths["evidence"],
                        policy=policy, canary=canary,
                        run_meta=_run_meta(settings, paths)), repo


def _run_meta(settings, paths) -> dict:
    """Fingerprint of rules/catalog/simulations plus live manager/agent versions (best effort)."""
    live = {}
    w = settings.get("wazuh", {})
    if w.get("api_url"):
        live = live_versions(WazuhAPI(w["api_url"], w.get("api_user", ""), w.get("api_password", ""),
                                      w.get("verify_tls", False), timeout=8))
    return run_fingerprint(paths, live)


def _policy(settings, allow_destructive: bool):
    policy = SafetyPolicy.from_settings(settings)
    return policy.with_destructive() if allow_destructive else policy


def _setup_safety_log(paths):
    """Persist every safety decision next to the evidence, even for blocked runs."""
    log = logging.getLogger("validator.safety")
    if log.handlers:
        return
    paths["evidence"].mkdir(parents=True, exist_ok=True)
    handler = logging.FileHandler(paths["evidence"] / "safety.log", encoding="utf-8")
    handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(message)s"))
    log.addHandler(handler)
    log.setLevel(logging.INFO)



def _filters(a):
    return {"ids": a.id or None, "platform": a.platform, "technique": a.technique,
            "tag": a.tag, "source": a.source}


def cmd_list(a):
    _, _, paths = _ctx()
    for t in select(load_catalog(paths["catalog"]), **_filters(a)):
        print(f"{t.id:<22} {t.technique:<12} {t.platform:<8} {t.source:<7} {'NEG' if t.negative else 'POS'}  {t.name}")


def lint_catalog(tests, targets: dict, paths) -> list[str]:
    """Problems that would only surface at execution time: unknown target, platform mismatch,
    missing simulation script or atomic definition. Fails before anything runs."""
    problems = []
    for t in tests:
        tgt = targets.get(t.target)
        if tgt is None:
            problems.append(f"{t.id}: unknown target '{t.target}'")
        elif tgt.platform != t.platform:
            problems.append(f"{t.id}: test platform {t.platform} != target {t.target} platform {tgt.platform}")
        if t.source == "custom":
            script = t.simulation.get("script")
            if not script:
                problems.append(f"{t.id}: custom test has no simulation.script")
            elif not (paths["custom"] / script).is_file():
                problems.append(f"{t.id}: simulation script not found: {script}")
        else:
            tech = t.simulation.get("technique", t.technique)
            if not (paths["atomic"] / t.platform / tech / f"{tech}.yaml").is_file():
                problems.append(f"{t.id}: atomic definition not found for {t.platform}/{tech}")
    return problems


def cmd_lint(a):
    _, _, paths = _ctx()
    tests = load_catalog(paths["catalog"]) + load_catalog(paths["regression"])
    problems = lint_catalog(tests, _targets(), paths)
    for p in problems:
        print(f"ERROR {p}")
    if problems:
        print(f"{len(problems)} problems in {len(tests)} tests")
        return 1
    print(f"OK: {len(tests)} tests parsed and cross-checked")


def cmd_run(a):
    _, settings, paths = _ctx()
    policy = _policy(settings, a.allow_destructive)
    targets = {n: Target.from_config(n, c) for n, c in load_environments()["targets"].items()}
    tests = select(load_catalog(paths["catalog"]), **_filters(a))
    if not tests:
        print("no tests matched")
        return 2
    _setup_safety_log(paths)
    if a.dry_run:
        return _dry_run(tests, targets, policy)
    orch, repo = _orchestrator(settings, paths, policy, canary_enabled=not a.no_canary)
    try:
        run_id = orch.run(tests, label=a.label)
        run = repo.get_run(run_id) or {}
        rows = repo.results(run_id)
    finally:
        repo.conn.close()
    if run.get("status") == "inconclusive":
        print(f"run {run_id}: INCONCLUSIVE - {run.get('canary_detail')}")
        return 2
    m = compute_metrics(rows)
    print(f"\nrun {run_id}: TP={m['tp']} FN={m['fn']} TN={m['tn']} FP={m['fp']} ERR={m['errors']} "
          f"detection_rate={m['detection_rate']} "
          f"(TP by exec id={m['tp_exec_correlated']}, by window only={m['tp_window_only']})")
    return 1 if (m["fn"] or m["fp"] or m["errors"]) and a.strict else 0


def _dry_run(tests, targets, policy) -> int:
    """Show what would run, without building or executing any command."""
    print("DRY RUN - no command will be executed")
    print(f"lab acknowledgement: {'yes' if policy.lab_acknowledged else 'MISSING (DV_LAB_ACK=1)'}")
    print(f"destructive allowed: {'yes' if policy.allow_destructive else 'no'}")
    blocked = 0
    for t in tests:
        target = targets.get(t.target)
        where = "<unknown>" if target is None else f"{target.transport} {target.host or 'local'}"
        print(f"\n{t.id}  risk={t.risk}  target={t.target} ({where})")
        print(f"  source={t.source} simulation={t.simulation}")
        reason = blocked_reason(t, targets, policy)
        if reason:
            blocked += 1
            print(f"  BLOCKED: {reason}")
        else:
            print("  safety: allowed")
    print(f"\n{len(tests)} tests, {blocked} blocked")
    return 1 if blocked else 0


def cmd_report(a):
    _, _settings, paths = _ctx()
    repo = RunRepository(connect(paths["database"]))
    run_id = a.run_id or repo.latest_run_id(status="completed")
    if not run_id:
        print("no completed runs")
        return 2
    rows, run = repo.results(run_id), repo.get_run(run_id)
    if run is None:
        print(f"run {run_id} does not exist")
        return 2
    if run.get("status") != "completed":
        detail = f" ({run.get('canary_detail')})" if run.get("canary_detail") else ""
        print(f"run {run_id} is {str(run.get('status')).upper()}{detail}; "
              "a partial run is not reported as a result")
        return 2
    for fmt in a.format:
        out = REPORTERS[fmt].write(run, rows, compute_metrics(rows), paths["reports"] / f"run-{run_id}.{fmt}")
        print("wrote", out)


def cmd_regress(a):
    _, settings, paths = _ctx()
    _setup_safety_log(paths)
    policy = _policy(settings, a.allow_destructive)
    orch, repo = _orchestrator(settings, paths, policy, canary_enabled=not a.no_canary)
    try:
        run_id, base, rep = run_regression(orch, repo, paths["regression"], a.baseline)
        run = repo.get_run(run_id) or {}
    finally:
        repo.conn.close()
    if rep is None:
        print(f"run {run_id}: {str(run.get('status')).upper()} - {run.get('canary_detail') or 'no comparison made'}")
        return 2
    print(f"\nrun {run_id} vs baseline {base}: {len(rep.regressions)} regressions, "
          f"{len(rep.improvements)} improvements, {len(rep.inconclusive)} inconclusive, "
          f"{len(rep.changed)} changed, {rep.unchanged} unchanged "
          f"({len(rep.new_tests)} new, {len(rep.missing_tests)} missing)")
    ctx = rep.context or {}
    for d in ctx.get("experiment_changed", []):
        print(f"  WARNING: {d['key']} differs from the baseline - not a like-for-like comparison")
    for d in ctx.get("subject_changed", []):
        print(f"  note: {d['key']} changed since the baseline (the rules under test)")
    if ctx.get("unknown"):
        print(f"  note: baseline has no fingerprint for: {', '.join(ctx['unknown'])}")
    if rep.definition_changed:
        print(f"  WARNING: test definition changed since the baseline: {', '.join(rep.definition_changed)}")
    for r in rep.regressions:
        print(f"  REGRESSION   {r['test_id']}: {r['from']} -> {r['to']}"
              f"{'  (definition changed)' if r.get('definition_changed') else ''}")
    for r in rep.inconclusive:
        print(f"  INCONCLUSIVE {r['test_id']}: {r['from']} -> {r['to']} ({r['kind']}) {r.get('reason', '')}")
    for r in rep.changed:
        print(f"  CHANGED      {r['test_id']}: {r['from']} -> {r['to']}")
    for tid in rep.missing_tests:
        print(f"  MISSING      {tid}: in baseline, not in this run")
    return 1 if (rep.has_regressions or rep.has_operational_failures) else 0


def cmd_canary(a):
    _, settings, paths = _ctx()
    policy = _policy(settings, a.allow_destructive)
    _setup_safety_log(paths)
    outcome = _pipeline_canary(settings, paths, policy).check()
    print(f"canary {outcome.status}: {outcome.detail}")
    return 0 if outcome.status in ("ok", "skipped") else 2


def cmd_coverage(a):
    _, _settings, paths = _ctx()
    techniques = load_yaml(paths["techniques"]).get("techniques", {})
    repo = RunRepository(connect(paths["database"]))
    rows = coverage_matrix(techniques, load_catalog(paths["catalog"]), repo.last_verdicts())
    write_coverage_csv(rows, paths["coverage"])
    for r in rows:
        print(f"{r['technique']:<12} {r['status']:<13} {r['passed']}/{r['positive_tests']}  {r['name']}")
    s = coverage_summary(rows)
    print(f"\nvalidated {s['techniques_validated']}/{s['techniques_with_positive_tests']} techniques with "
          f"positive tests ({s['techniques_in_scope']} in scope); "
          f"{s['positive_tests_passed']}/{s['positive_tests']} positive tests last passed")
    print(f"by status: {s['by_status']}")
    print(s["scope_note"])


def cmd_replay(a):
    from .replay import ReplayEngine
    _, _, paths = _ctx()
    tests = select(load_catalog(paths["catalog"]), **_filters(a))
    if not tests:
        print("no tests matched")
        return 2

    engine = ReplayEngine.from_ndjson(a.alerts)
    summary = engine.replay_catalog(tests)

    if a.json:
        print(json.dumps(summary.as_dict(), indent=2))
    else:
        print(f"\nReplay Summary: Total={summary.total_tests} TP={summary.true_positives} "
              f"FN={summary.false_negatives} TN={summary.true_negatives} "
              f"FP={summary.false_positives} ERR={summary.errors}")
        for res in summary.results:
            color = "\033[32m" if res.verdict.value in ("TP", "TN") else "\033[31m"
            print(f"  [{color}{res.verdict.value}\033[0m] {res.test.id}: {res.test.name}")

    return 0 if summary.passed else 1



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
        sp.add_argument("--id", action="append")
        sp.add_argument("--platform")
        sp.add_argument("--technique", help="prefix match, e.g. T1110")
        sp.add_argument("--tag")
        sp.add_argument("--source", choices=["atomic", "custom"])

    s = sub.add_parser("list")
    filt(s)
    s.set_defaults(fn=cmd_list)

    sub.add_parser("lint", help="validate catalog files").set_defaults(fn=cmd_lint)

    s = sub.add_parser("run")
    filt(s)
    s.add_argument("--label")
    s.add_argument("--strict", action="store_true")
    s.add_argument("--dry-run", action="store_true",
                   help="show target, risk and simulation, execute nothing")
    s.add_argument("--allow-destructive", action="store_true",
                   help="opt in to risk: high tests on a disposable lab")
    s.add_argument("--no-canary", action="store_true",
                   help="skip the pipeline canary (recorded as skipped; verdicts are then unverified)")
    s.set_defaults(fn=cmd_run)

    s = sub.add_parser("report")
    s.add_argument("--run-id", type=int)
    s.add_argument("--format", nargs="+", choices=list(REPORTERS), default=["json", "html"])
    s.set_defaults(fn=cmd_report)

    s = sub.add_parser("regress")
    s.add_argument("--baseline", type=int)
    s.add_argument("--allow-destructive", action="store_true")
    s.add_argument("--no-canary", action="store_true")
    s.set_defaults(fn=cmd_regress)

    s = sub.add_parser("canary", help="run only the pipeline canary")
    s.add_argument("--allow-destructive", action="store_true")
    s.set_defaults(fn=cmd_canary)

    sub.add_parser("coverage").set_defaults(fn=cmd_coverage)

    s = sub.add_parser("replay", help="replay alerts from an NDJSON file against test catalog")
    filt(s)
    s.add_argument("--alerts", required=True, help="path to NDJSON alerts file")
    s.add_argument("--json", action="store_true", help="output summary as JSON")
    s.set_defaults(fn=cmd_replay)

    s = sub.add_parser("rules-check",
                       help="lint Wazuh rule XML (add --live to verify parents on the manager)")
    s.add_argument("--live", action="store_true")
    s.set_defaults(fn=cmd_rules_check)

    sub.add_parser("doctor", help="check Wazuh API, agents, and expected rules").set_defaults(fn=cmd_doctor)

    a = p.parse_args(argv)
    try:
        return a.fn(a) or 0
    except Exception as exc:  # CLI boundary: report any failure with a non-zero status
        print(f"error: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 3


if __name__ == "__main__":
    sys.exit(main())
