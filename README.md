# Wazuh Detection Engineering & Attack Simulation Framework

A comprehensive, production-grade detection engineering framework to **develop, compile, simulate, and automatically validate Wazuh and Sigma detection rules** across Linux, Windows, Cloud, Containers, and Network IDS environments.

```
┌─────────────────┐       ┌─────────────────┐       ┌─────────────────┐       ┌──────────────────┐
│   Threat Intel  │ ────▶ │  Sigma / Wazuh  │ ────▶ │ Attack Playbook │ ────▶ │  Target Sensors  │
│  & MITRE ATT&CK │       │   Rule Engine   │       │   Simulations   │       │  Linux/Win/Cloud │
└─────────────────┘       └─────────────────┘       └─────────────────┘       └──────────────────┘
                                                                                        │
                                                                                        ▼
┌─────────────────┐       ┌─────────────────┐       ┌─────────────────┐       ┌──────────────────┐
│ Web Dashboard / │ ◀──── │  TP / TN / FP   │ ◀──── │ Alert Evaluator │ ◀──── │   Wazuh Server   │
│ Coverage Matrix │       │    Verdicts     │       │   & Matcher     │       │ Manager/Indexer  │
└─────────────────┘       └─────────────────┘       └─────────────────┘       └──────────────────┘
```

---

## 🌟 Key Capabilities

1. **Multi-Domain Detection Engine (183 Rules)**
   - **Linux**: Authentication, sudo privilege escalation, persistence, auditd execution, memory dumping, defense evasion (`0100`–`0600`).
   - **Windows**: Sysmon process creation, PowerShell script-block logging, privilege use, COM hijacking, timestomping, ADS, and registry evasion (`0700`–`0930`).
   - **Cloud**: AWS CloudTrail root login without MFA, CloudTrail tampering, Azure Entra ID risky sign-ins, GCP IAM privilege escalation (`0610`).
   - **Containers & Kubernetes**: Host Docker socket access, privileged containers, and service account secret token exfiltration (`0630`).
   - **Network IDS / Suricata**: Cobalt Strike malleable C2 profiles, BishopFox Sliver C2 communication, and DNS tunneling (`0650`).

2. **Automated Threat Playbooks (`scripts/playbook.py`)**
   - Threat-specific simulation playbooks (`smoke`, `credential-access`, `defense-evasion`, `execution`, `discovery`, `persistence`, `cloud`, `container`, `network-ids`, and `all`).

3. **Offline Alert Replay Engine (`dv replay`)**
   - Score detection logic offline against captured alert streams without standing up live VMs or active Wazuh clusters.

4. **Automated Rule Exporter & Wazuh Deployer (`scripts/deploy_rules.py`)**
   - Validates XML syntax, backs up existing manager configurations, deploys via SSH/SCP or the Wazuh REST API, and reloads services automatically.

5. **Automatic Sigma-to-Wazuh Compiler (`scripts/compile_sigma.py`)**
   - Compiles Sigma YAML rules directly into Wazuh XML rules with automatic parent-child linking, PCRE2 regex translations, and MITRE mapping.

6. **Interactive Detection Dashboard (`scripts/dashboard.py`)**
   - Web application displaying the MITRE ATT&CK coverage heatmap, live execution terminal, and one-click playbook runners.

7. **Continuous Test Automation (`scripts/run_tests.sh` & `scripts/rerun_loop.sh`)**
   - Automated runner and background watch daemon for instant feedback during detection rule development.

---

## 🚀 Quick Start Guide

### 1. Prerequisites & Environment Setup
```bash
# Clone and enter directory
cd /path/to/detection

# Set up virtual environment and install framework
cd framework && python3 -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
cd ..
```

### 2. Verify Repository Health & Run Unit Tests
```bash
# Run all offline syntax checks, catalog linting, and 140+ unit tests
./scripts/run_tests.sh --all
```

### 3. Launch Interactive Web Dashboard
```bash
python3 scripts/dashboard.py --port 8888
# Open http://localhost:8888 in your browser
```

### 4. Run Threat Simulation Playbooks (Dry-Run / Live)
```bash
# List all available playbooks
python3 scripts/playbook.py list

# Dry-run the Credential Access Playbook (safe mode)
DV_LAB_ACK=1 python3 scripts/playbook.py credential-access

# Replay an alert stream offline through the Defense Evasion playbook
python3 scripts/playbook.py defense-evasion --replay tests/positive/alerts_replay_sample.ndjson
```

---

## 📖 Detailed Documentation

Comprehensive documentation guides are available in the [`docs/`](docs/) directory:

- [**docs/ARCHITECTURE.md**](docs/ARCHITECTURE.md): System architecture, telemetry pipeline, correlation mechanics, and safety gates.
- [**docs/PLAYBOOKS_AND_SIMULATIONS.md**](docs/PLAYBOOKS_AND_SIMULATIONS.md): Guide to the 81+ attack simulation scenarios and Atomic Red Team tests.
- [**docs/RULES_AND_DEPLOYMENT.md**](docs/RULES_AND_DEPLOYMENT.md): Complete Wazuh and Sigma rule reference, deployment procedures, and compiler usage.
- [**docs/REPLAY_ENGINE_AND_CI.md**](docs/REPLAY_ENGINE_AND_CI.md): Offline alert replay testing, continuous integration, and automated test loops.

---

## 🛡️ Safety Model

Simulating cyberattacks requires strict safety boundaries to prevent running tests against unintended environments:
1. **Lab Acknowledgment Gate**: Live executions require `DV_LAB_ACK=1` in the environment or `safety.lab_acknowledged: true` in `framework/config/settings.yaml`.
2. **Private Network Boundaries**: Simulations refuse to connect to targets outside RFC1918 private CIDR blocks (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, `127.0.0.0/8`).
3. **Idempotent Resource Tracking**: All custom simulations use `custom-simulations/lib/dv_safety.sh` to record generated files, accounts, and directories in a per-execution manifest, guaranteeing cleanup on completion or interruption.
4. **Destructive Guard**: High-risk tests (e.g. shadow file access or setuid creation) require the explicit `--allow-destructive` flag.

---

## 📊 Coverage Matrix

To inspect your current MITRE ATT&CK coverage matrix:
```bash
dv coverage
# Output matrix is saved to mappings/coverage-matrix.csv
```
Viewing the matrix in the web dashboard displays techniques color-coded by test verdicts:
- **`COVERED`**: Attack simulations detected as True Positives (TP) and benign actions passed as True Negatives (TN).
- **`PARTIAL`**: Some positive tests detected, but coverage gaps remain.
- **`GAP`**: Positive tests did not trigger expected alerts (False Negatives).
