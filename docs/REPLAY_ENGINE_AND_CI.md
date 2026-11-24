# Alert Replay Engine, Continuous Integration & Test Automation

This document explains the Offline Alert Replay Engine, automated test runners, and continuous integration workflows.

---

## 1. Offline Alert Replay Engine (`dv replay`)

### Purpose
In modern detection engineering, waiting for VMs to spin up or managing fragile network connections slows down testing. The **Replay Engine** allows scoring detection rules offline against JSON/NDJSON alert fixtures in milliseconds.

### Mechanics
1. **Alert Parsing**: Ingests NDJSON streams containing raw Wazuh or OpenSearch alert documents.
2. **Catalog Scoring**: Replays the stream against test catalog definitions in `test-catalog/**.yaml`.
3. **Automated Metrics**:
   - Asserts True Positives (`TP`) for positive attack simulations.
   - Asserts True Negatives (`TN`) for negative / benign simulations.
   - Flags False Positives (`FP`) if a rule is noisy and alerts on benign input.
   - Flags False Negatives (`FN`) if an expected alert is missing from the stream.

### Usage Commands
```bash
# Replay against positive alert sample for a specific technique
dv replay --alerts tests/positive/alerts_replay_sample.ndjson --technique T1059

# Replay against specific test ID with JSON output for CI parsing
dv replay --alerts tests/positive/alerts_replay_sample.ndjson --id LIN-R100401 --json

# Replay through a playbook directly
python3 scripts/playbook.py defense-evasion --replay tests/positive/alerts_replay_sample.ndjson
```

---

## 2. Test Automation Scripts

The repository includes two automation scripts located in `scripts/`:

### 1. `scripts/run_tests.sh`
The primary verification script. It executes:
1. Shell script syntax validation across all custom simulations (`bash -n`).
2. Catalog schema & target validation (`dv lint`).
3. Wazuh XML rule structure, IDs, regexes, and parent hierarchy checks (`dv rules-check`).
4. Full Python unit test suite via `pytest`.

```bash
# Run all checks (default)
./scripts/run_tests.sh --all

# Run only catalog and rule XML linting
./scripts/run_tests.sh --lint

# Run pytest unit tests with verbose output
./scripts/run_tests.sh --unit -v

# Run dry-run simulation for a specific technique
DV_LAB_ACK=1 ./scripts/run_tests.sh --technique T1059 --dry-run
```

### 2. `scripts/rerun_loop.sh`
A continuous file-watching loop for real-time rule development:
- Watches `rules/`, `test-catalog/`, `custom-simulations/`, and `tests/`.
- Uses `inotifywait` if available; otherwise polls modification timestamps.
- Automatically re-runs `./scripts/run_tests.sh --all` whenever any file is saved.

```bash
# Launch background watch daemon
./scripts/rerun_loop.sh
```

---

## 3. GitHub Actions CI/CD Pipeline

The static workflow in [`.github/workflows/validate.yml`](../.github/workflows/validate.yml) runs on every push and pull request:

```yaml
name: validate
on: [push, pull_request]
jobs:
  static:
    runs-on: ubuntu-latest
    defaults: {run: {working-directory: framework}}
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with: {python-version: "3.12"}
      - run: pip install -e ".[dev]"
      - run: ruff check src ../tests
      - run: dv lint            # catalog schema + duplicate ids
      - run: dv rules-check     # Wazuh rule XML lint
      - run: pytest             # 140+ unit + integration tests
      - run: bash -n ../custom-simulations/*/*.sh ../custom-simulations/lib/*.sh
```

