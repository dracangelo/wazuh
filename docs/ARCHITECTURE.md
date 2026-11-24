# System Architecture & Technical Design

This document details the architectural foundation, execution lifecycle, safety enforcement, and data flows of the detection validation framework.

---

## 1. High-Level Architecture

The framework operates as a closed-loop validation engine:

```
[ Test Catalog (YAML) ]
           │
           ▼
[ Adapter Engine ] ──(Atomic Red Team / Custom Shell / PowerShell)──▶ [ Lab Target ]
           │                                                                 │
           │ (Captures started_at / finished_at & exec_id)                   ▼
           │                                                      [ Wazuh Agent Telemetry ]
           ▼                                                                 │
[ Alert Collector ] ◀──(OpenSearch Indexer / NDJSON Replay)──────────────────┘
           │
           ▼
[ Evaluator & Matcher ] ──▶ [ SQLite Results DB ] ──▶ [ Reports & Web Dashboard ]
```

### Components

1. **Test Catalog (`test-catalog/`)**:
   - Declarative YAML definitions mapping specific test cases to target platforms, MITRE ATT&CK techniques, simulation scripts, and expected Wazuh rule IDs.
2. **Adapters (`framework/src/validator/adapters/`)**:
   - `atomic.py`: Invokes Atomic Red Team YAML tests.
   - `custom.py`: Executes custom scripts from `custom-simulations/` over SSH or locally, injecting the safety harness (`dv_safety.sh`).
3. **Safety Engine (`framework/src/validator/safety.py`)**:
   - Enforces execution boundaries, ensuring tests run strictly on authorized lab environments and private IP networks.
4. **Collectors (`framework/src/validator/collectors/`)**:
   - `IndexerAlertCollector`: Queries the Wazuh indexer (OpenSearch/Elasticsearch) using pagination (`search_after`) across the simulation time window.
   - `FileAlertCollector`: Ingests raw NDJSON log files directly.
5. **Replay Engine (`framework/src/validator/replay.py`)**:
   - Decoupled offline evaluator scoring test definitions against pre-recorded alert streams without live agents.
6. **Evaluator & Matcher (`framework/src/validator/evaluation/`)**:
   - Matches collected alerts against expected criteria: rule ID, severity levels, rule groups, and MITRE IDs.
   - Computes formal detection verdicts:
     - **`TP` (True Positive)**: Positive test generated expected alert(s).
     - **`FN` (False Negative)**: Expected alert was not raised (Detection Gap).
     - **`TN` (True Negative)**: Negative test stayed completely quiet.
     - **`FP` (False Positive)**: Negative test raised an alert (Noisy/Over-broad Rule).
     - **`ERROR`**: Simulation crashed, connection dropped, or alert collection failed.

---

## 2. Telemetry Pipeline & Rule Correlation

To avoid false correlations in noisy lab environments with concurrent tests, the framework employs **Execution Correlation**:

1. **Unique Execution ID (`DV_EXEC_ID`)**:
   - Before executing a simulation, the adapter generates a cryptographically random, timestamped suffix: e.g. `dv261124-9123-5819`.
2. **Telemetry Stamping**:
   - Custom simulations stamp created resources, command lines, or syslog messages with this execution token.
   - For Linux auditd, rules match on the unique argument strings or temporary filenames.
3. **Strict Window Correlation**:
   - The alert collector requests only alerts where `since <= alert.timestamp <= until`.
   - The evaluator strictly binds the received alert's payload to the recorded `exec_id`. If `correlation: exec_id` is set and an alert was generated without the matching token, it is flagged as uncorrelated and not scored as a false positive.

---

## 3. Safety Model & Defenses

Live attack simulations pose inherent operational risks. The framework prevents catastrophic misuse through four defensive layers:

```
                  Simulation Request
                          │
                          ▼
             [ 1. Lab Acknowledgment ] ────(Missing)────▶ BLOCKED (Error 64)
                          │ (DV_LAB_ACK=1)
                          ▼
             [ 2. Target IP Validation ] ──(Public IP)──▶ BLOCKED (Non-Lab Target)
                          │ (RFC 1918 Private)
                          ▼
             [ 3. Destructive Guard ] ───(High Risk)───▶ BLOCKED (Needs --allow-destructive)
                          │ (Permitted)
                          ▼
             [ 4. Manifest Cleanup ] ────▶ Automated Idempotent Deletion
```

- **Layer 1: Acknowledgment Gate**: Every run checks `DV_LAB_ACK=1` or `safety.lab_acknowledged: true`.
- **Layer 2: Target Validation**: `dv_require_lab_host` strictly checks against RFC1918 private IPv4 blocks (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, `127.0.0.0/8`).
- **Layer 3: Destructive Action Gate**: Any test flagged with `risk: high` in its catalog YAML is blocked unless `--allow-destructive` is passed.
- **Layer 4: Manifest Tracking**: `custom-simulations/lib/dv_safety.sh` writes every created resource to a temporary manifest file (`/tmp/dv_manifest_XXXXXX`) with mode `0600`. An exit trap automatically runs cleanup upon completion, failure, or termination signals (`SIGINT`, `SIGTERM`, `SIGHUP`).

