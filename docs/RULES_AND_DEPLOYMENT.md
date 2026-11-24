# Detection Rules, Deployment & Sigma Compiler Manual

This manual details the Wazuh detection rules, the deployment automation utility, and the Sigma-to-Wazuh compiler.

---

## 1. Wazuh Rule ID Allocation Matrix

The framework uses dedicated, conflict-free rule ID spaces reserved for this project:

| Rule Range | Directory | Description & Telemetry Source |
|---|---|---|
| `100100`–`100199` | `rules/wazuh/linux/0100_dv_validation.xml` | Pipeline health markers (syslog, FIM, auditd, web). |
| `100200`–`100299` | `rules/wazuh/linux/0200_dv_auth.xml` | Authentication: sshd brute force, direct root, sudo setuid. |
| `100300`–`100399` | `rules/wazuh/linux/0300_dv_persistence.xml` | Persistence: UID 0 accounts, cron, syscheck FIM on critical files. |
| `100400`–`100499` | `rules/wazuh/linux/0400_dv_execution_auditd.xml` | Execution: /tmp exec, reverse shells, offensive tooling, memory dump. |
| `100500`–`100599` | `rules/wazuh/linux/0500_dv_defense_evasion.xml` | Defense evasion: logging stopped, firewall flush, SELinux disable. |
| `100600`–`100609` | `rules/wazuh/linux/0600_dv_web.xml` | Web application attacks: Shellshock, traversal, Log4Shell, SQLi. |
| `100610`–`100629` | `rules/wazuh/linux/0610_dv_cloud.xml` | Cloud infrastructure: AWS CloudTrail, Azure Entra ID, GCP IAM. |
| `100630`–`100649` | `rules/wazuh/linux/0630_dv_container.xml` | Container breakout: Docker socket access, privileged containers. |
| `100650`–`100679` | `rules/wazuh/linux/0650_dv_network_suricata.xml`| Network IDS: Suricata EVE alerts for Cobalt Strike, Sliver C2. |
| `100700`–`100709` | `rules/wazuh/windows/0700_dv_win_validation.xml`| Windows validation markers (Sysmon, Security, Application). |
| `100710`–`100749` | `rules/wazuh/windows/0710_dv_win_bases.xml` | Windows base rules (Sysmon 1, 3, 8, 10, 11, 13, 15, PowerShell 4104). |
| `100750`–`100799` | `rules/wazuh/windows/0750_dv_win_auth.xml` | Windows authentication & privileged group membership changes. |
| `100800`–`100849` | `rules/wazuh/windows/0800_dv_win_persistence.xml` | Windows persistence: Run keys, Startup folders, scheduled tasks. |
| `100850`–`100869` | `rules/wazuh/windows/0850_dv_win_execution.xml` | Windows execution: Encoded PowerShell, LOLBins, remote threads. |
| `100870`–`100899` | `rules/wazuh/windows/0870_dv_win_discovery.xml` | Windows discovery: Domain discovery, ADS, timestomping. |
| `100900`–`100929` | `rules/wazuh/windows/0900_dv_win_credential_access.xml` | Windows credentials: LSASS dump, SAM export, DCSync. |
| `100930`–`100949` | `rules/wazuh/windows/0930_dv_win_defense_evasion.xml`| Windows defense evasion: Wevtutil log clear, firewall off, auditpol. |

---

## 2. Automated Rule Deployer (`scripts/deploy_rules.py`)

The rule deployer automates the testing, backup, upload, and reloading of detection rules:

### Capabilities
1. **Pre-flight Linting**: Invokes `dv rules-check` before touching any remote system.
2. **Automated Manager Backup**: Creates a timestamped snapshot of `/var/ossec/etc/rules/` on the manager.
3. **Rollback on Error**: If `/var/ossec/bin/wazuh-analysisd -t` reports syntax or parent errors on the manager, rules are rolled back to the backup automatically.

### Usage Commands
```bash
# 1. Package all custom rules into an export archive
./scripts/deploy_rules.py --export wazuh-rules-latest.tar.gz

# 2. Dry-run SSH deployment to lab manager
./scripts/deploy_rules.py --deploy-ssh 10.0.0.10 --dry-run

# 3. Live SSH deployment with automatic service restart
./scripts/deploy_rules.py --deploy-ssh 10.0.0.10 --ssh-user root

# 4. Live API deployment via Wazuh Manager REST API
WAZUH_API_PASSWORD=SecretPassword ./scripts/deploy_rules.py --deploy-api https://10.0.0.10:55000
```

---

## 3. Sigma-to-Wazuh Rule Compiler (`scripts/compile_sigma.py`)

The compiler translates Sigma YAML detection definitions into native Wazuh XML rules:

### Mapping Rules
- **Parent IDs**:
  - Linux `process_creation` ➔ Parent ID `100400` (auditd `dv_exec`).
  - Windows `process_creation` ➔ Parent ID `100712` (Sysmon 1).
- **Fields**:
  - `Image` ➔ `audit.exe` (Linux) or `win.eventdata.image` (Windows).
  - `CommandLine` ➔ `audit.execve` (Linux) or `win.eventdata.commandLine` (Windows).
- **Severity Levels**:
  - `low` ➔ Level 5
  - `medium` ➔ Level 8
  - `high` ➔ Level 11
  - `critical` ➔ Level 14

### Usage Commands
```bash
# Compile a single Sigma rule to stdout
python3 scripts/compile_sigma.py --sigma rules/sigma/linux/reverse_shell_indicators.yml

# Compile all Windows Sigma rules to a target XML file starting at rule ID 100950
python3 scripts/compile_sigma.py --all --platform windows --start-id 100950 --output /tmp/compiled_win.xml
```

