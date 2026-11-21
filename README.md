# detection-rules

Validate Wazuh (and Sigma) detections by **running real attack simulations in a lab** and checking
that the expected alerts fire - and that benign activity doesn't.

```
catalog test ─▶ adapter (atomic | custom) ─▶ target (local/SSH) ─▶ Wazuh agent ─▶ manager ─▶ indexer
      │                                                                                         │
      └──────────── verdict TP/FN/TN/FP ◀── evaluator/matcher ◀── alert collector ◀─────────────┘
                         │
                  SQLite + evidence/ ─▶ reports (json/csv/html/pdf) · regression diff · coverage matrix
```

## Quick start
```bash
cd framework && python -m venv .venv && . .venv/bin/activate
pip install -e ".[dev]"            # add ,pdf for PDF reports
pytest                             # no lab needed
export WAZUH_API_USER=... WAZUH_API_PASSWORD=... WAZUH_INDEXER_USER=... WAZUH_INDEXER_PASSWORD=...
$EDITOR config/environments.yaml   # your LAB hosts + Wazuh agent names
export DV_LAB_ACK=1                # acknowledge this is a disposable lab (required by the safety gate)
dv lint && dv rules-check          # catalog + Wazuh rule XML lint (offline)
dv rules-check --live && dv doctor # parents exist on manager, agents active, expected rules loaded
dv list --platform linux
dv run --technique T1110 --dry-run  # show target, risk and simulation; executes nothing
dv run --technique T1110 --label smoke
dv report --format html json
dv regress                         # re-runs tests/regression, diffs vs previous regression run
dv coverage                        # writes mappings/coverage-matrix.csv
```

## Layout notes
- `test-catalog/**.yaml` - test definitions (one test or a `tests:` list). Schema: see `models.TestCase`.
- `atomic/<platform>/<Txxxx>/<Txxxx>.yaml` - Atomic Red Team definitions; copy the ones you use from
  redcanaryco/atomic-red-team. A benign T1136.001 sample is included.
- `rules/wazuh/linux/` - custom Linux rules, IDs 100100-100699 (see its README for deploy steps,
  auditd rules, and agent config). `rules/wazuh/examples/` holds non-deployed reference XML.
- `custom-simulations/` - our scripts. `lib/dv_safety.sh` gives every run unique resource names and
  ownership-tracked, idempotent cleanup; the adapter prepends it automatically.
- `tests/unit|integration` - pytest. `tests/positive|negative` - fixture alert streams.
  `tests/regression` - catalog-format tests re-run by `dv regress`.
- `framework/src/validator/config.py` - small addition to the original tree (config loading).

## Verdicts
TP attack detected · FN **coverage gap** · TN benign stayed quiet · FP noisy rule · ERROR simulation or
collection failed (never counted as a pass).

## Safety model

Lab only. Run simulations on disposable VMs with a dedicated, least-privileged runner account; never
against production.

Before any simulation command is built, the Python execution layer checks every test centrally
(`framework/src/validator/safety.py`):

- **Lab acknowledgement is mandatory.** Set `safety.lab_acknowledged: true` in
  `config/settings.yaml` or export `DV_LAB_ACK=1` for the process. Without it every test is `ERROR`
  and no command runs.
- **Targets must be inside the lab.** SSH targets are accepted only when every resolved address is
  in `safety.allowed_cidrs`; public addresses are refused. Hostnames must additionally appear in
  `safety.allowed_hostnames`, so DNS cannot silently point a test at an unexpected system. There is
  no command-line flag that overrides these checks.
- **Risk gating.** Each test carries `risk: low|medium|high` (default `medium`). `high` tests - those
  that create accounts, write to system paths, or edit crontabs/units - run only with
  `--allow-destructive` (or `safety.allow_destructive: true`).
- **Decisions are recorded** in `evidence/safety.log`, including tests that were blocked. Preflight
  runs before the first command, so one unsafe target stops the run rather than executing the safe
  tests first.
- **Simulations are unique and self-owning.** Every execution gets an id (`DV_EXEC_ID`). Accounts,
  files, units and temp directories derive from it, pre-existing resources are refused rather than
  overwritten, and cleanup removes only resources whose creation the run recorded. Cleanup runs on
  `EXIT/INT/TERM/HUP`, is idempotent, and reports failures on stderr (stored as evidence).
- **Every command has a timeout** (`evaluation.command_timeout_seconds`, or `simulation.timeout`).
  Outcomes are classified as `ok`, `command_failed`, `timeout`, `connection_failed` or
  `setup_failed`; a failed simulation is `ERROR`, never `FN`.

Rule IDs in the sample catalog depend on your Wazuh version - confirm with `dv doctor`.

## Offline checks
The test suite needs no Wazuh, no SSH and no lab: `cd framework && pytest`. CI also runs `dv lint`
(catalog schema, duplicate test IDs), `dv rules-check` (unique rule IDs, levels, regexes, parents),
ruff, and a shell syntax check. Live detection results are never produced by CI.
