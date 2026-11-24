# Threat Playbooks & Attack Simulations Guide

This guide details the threat playbooks, simulation scenarios, and Atomic Red Team test suites available in the repository.

---

## 1. Playbook Directory (`scripts/playbook.py`)

The playbook runner organizes simulation tests into functional threat scenarios. You can run any playbook in **Dry-Run mode** (default), **Live execution mode** (`--execute`), or **Offline Replay mode** (`--replay <file.ndjson>`).

### Available Playbooks

| Playbook | MITRE Techniques | Key Scenarios Covered |
|---|---|---|
| `smoke` | Markers | Verifies syslog, FIM, auditd, and web log ingestion before trusting detection verdicts. |
| `credential-access` | T1003, T1110 | Exercises `/etc/shadow` reads, SSH brute-force attempts, memory dumping (`gcore`), and Windows failed logons. |
| `defense-evasion` | T1070, T1562, T1564 | Tests log deletion/tampering, firewall disabling/flushing, SELinux alteration, and timestomping. |
| `execution` | T1059, T1105, T1095 | Tests `/tmp` binaries, ncat interactive shells, inline scripting reverse shells, piped downloads (`curl \| sh`), and PowerShell. |
| `discovery` | T1082, T1033, T1087, T1046, T1482 | Exercises single benign recon vs multi-command recon bursts and network port probes. |
| `persistence` | T1136, T1098, T1053, T1543 | Simulates user creation, crontab/service manipulation, and administrative group modifications. |
| `cloud` | T1078.004, T1562.001, T1098 | Simulates CloudTrail root logins, Azure risky sign-in, GCP IAM changes. |
| `container` | T1611, T1610, T1552.007 | Host docker socket access, privileged containers, K8s tokens. |
| `network-ids` | T1071.001, T1071.004 | Suricata alerts for Cobalt Strike, Sliver, and DNS tunneling. |
| `all` | Full Catalog | Runs all 81+ tests across the platform. |

---

## 2. Custom Simulations (`custom-simulations/`)

Custom simulations are self-cleaning shell scripts designed specifically to exercise custom Wazuh rules:

### Linux Scenarios (`rules-lab/scenarios.sh`)
- `exec_tmp`: Copies `/usr/bin/true` to `/tmp/dv_payload` and executes it (Tests Rule `100401`).
- `benign_exec`: Normal binary execution from standard `$PATH` (Negative test for `100401`).
- `download_tmp`: Simulates `curl` downloading a payload into `/tmp/` (Tests Rule `100402`).
- `nc_exec`: Runs `nc` with command execution (`-e /bin/true`) (Tests Rule `100404`).
- `scanner`: Runs security scanning tools like `nmap -V` (Tests Rule `100405`).
- `find_suid`: Enumerates setuid binaries (`find /usr/bin -perm -4000`) (Tests Rule `100406`).
- `history_tamper`: Removes `.bash_history` (Tests Rule `100407`).
- `recon_burst`: Rapidly executes 10 system discovery commands within seconds (Tests Rule `100409`).
- `recon_few`: Runs 3 discovery commands (Negative test proving burst rule does not alert on normal use).
- `suid_chmod`: Sets setuid bit on a temporary test binary (Tests Rule `100421`).
- `script_reverse_shell`: Inline Python reverse shell syntax simulation (Tests Rule `100427`).
- `download_pipe_shell`: Simulates `curl ... | sh` command piping (Tests Rule `100428`).
- `mem_dump_attempt`: Simulates memory extraction with `gcore` (Tests Rule `100429`).
- `firewall_flush`: Simulates `iptables -F` (Tests Rule `100504`).
- `auditctl_tamper`: Simulates audit daemon tampering via `auditctl` (Tests Rule `100506`).

### Cloud & Container Scenarios
- `custom-simulations/cloud/cloud_anomaly_sim.sh`:
  - `aws_root_login`: Generates AWS CloudTrail console login without MFA.
  - `aws_stop_trail`: Simulates CloudTrail shutdown event.
  - `azure_risky_login`: Simulates Azure Entra ID risky sign-in event.
  - `gcp_set_iam`: Generates GCP Audit event granting administrative `roles/owner`.
- `custom-simulations/container/container_escape_sim.sh`:
  - `docker_sock`: Simulates host `/var/run/docker.sock` inspection.
  - `priv_container`: Simulates container creation with `--privileged` flags.
  - `k8s_token`: Simulates access to Kubernetes secret serviceaccount tokens.
- `custom-simulations/network/pcap_replay.sh`:
  - `cobalt_strike`: Generates malleable C2 HTTP profile requests.
  - `sliver`: Generates BishopFox Sliver C2 HTTP session requests.
  - `dns_tunnel`: Simulates high-entropy multi-label DNS query exfiltration.

---

## 3. Atomic Red Team Test Suites (`atomic/`)

The framework integrates Atomic Red Team tests with automatic resource tracking:

- **`atomic/linux/`**:
  - `T1003.007`: Process memory dump via `gcore`.
  - `T1033`: Current user discovery (Negative test against burst detection).
  - `T1070.003`: Command history removal.
  - `T1082`: System information discovery.
  - `T1136.001`: Local account creation.
  - `T1548.001`: Setuid bit manipulation on temporary files.
  - `T1548.003`: Sudo privilege enumeration (`sudo -l`).
  - `T1562.004`: Benign firewall listing (Negative test).
  - `T1574.006`: `LD_PRELOAD` shared library hijacking.

- **`atomic/windows/`**:
  - `T1046`: Network service discovery via `Test-NetConnection`.
  - `T1059.001`: Benign Base64-encoded PowerShell command.
  - `T1070.001`: Windows event log enumeration (Negative test).
  - `T1070.006`: File timestomping.
  - `T1087.001`: Local account discovery (`net user`).
  - `T1564.004`: Alternate Data Stream (ADS) creation.

