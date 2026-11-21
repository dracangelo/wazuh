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
dv lint && dv rules-check          # catalog + Wazuh rule XML lint (offline)
dv rules-check --live && dv doctor # parents exist on manager, agents active, expected rules loaded
dv list --platform linux
dv run --technique T1110 --label smoke
dv report --format html json
dv regress                         # re-runs tests/regression, diffs vs previous regression run
dv coverage                        # writes mappings/coverage-matrix.csv
```

## Layout notes
- `test-catalog/**.yaml` - test definitions (one test or a `tests:` list). Schema: see `models.TestCase`.
- `atomic/<platform>/<Txxxx>/<Txxxx>.yaml` - Atomic Red Team definitions; copy the ones you use from
  redcanaryco/atomic-red-team. A benign T1136.001 sample is included.
- `rules/wazuh/linux/` - 64 custom rules (see its README for deploy steps, auditd rules, and agent config).
- `custom-simulations/` - our scripts. They refuse non-private target addresses.
- `tests/unit|integration` - pytest. `tests/positive|negative` - fixture alert streams.
  `tests/regression` - catalog-format tests re-run by `dv regress`.
- `framework/src/validator/config.py` - small addition to the original tree (config loading).

## Verdicts
TP attack detected · FN **coverage gap** · TN benign stayed quiet · FP noisy rule · ERROR simulation or
collection failed (never counted as a pass).

## Safety
Lab only. Run simulations on disposable VMs with dedicated runner accounts; never against production.
Rule IDs in the sample catalog depend on your Wazuh version - confirm with `dv doctor`.
