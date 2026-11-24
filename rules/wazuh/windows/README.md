# Wazuh Windows rules (IDs 100700-100999)

| File | Range | Covers | Needs |
|---|---|---|---|
| `0700_dv_win_validation.xml` | 100700-100706 | Pipeline markers: Application-log canary, Sysmon canary, failed-logon canary, FIM create/modify/delete + lifecycle | Application/Security/Sysmon channels, syscheck |
| `0710_dv_win_bases.xml` | 100710-100722 | Level-0 bases: Security 4624/4625/4698, Sysmon 1/3/8/10/11/13/15/19-21, PowerShell 4104, System 7045 | audit policy, Sysmon, script-block logging |
| `0750_dv_win_auth.xml` | 100750-100754 | Brute force, success after brute force, off-hours RDP, account creation, privileged group adds | Security log / audit policy |
| `0800_dv_win_persistence.xml` | 100800-100813 | Services, scheduled tasks, Run keys, Startup folders, WMI subscriptions, IFEO/Winlogon/AppInit, accessibility binaries, RDP enable, FIM | Sysmon 13, FIM, Security 4698 |
| `0850_dv_win_execution.xml` | 100850-100872 | Office spawning shells, certutil/bitsadmin/mshta/regsvr32/rundll32, encoded/obfuscated PowerShell, wmic, net account changes, recon burst, masquerading, remote threads, PsExec, LOLBin egress, PowerSploit names, .NET in memory, WinRM, schtasks | Sysmon 1/3/8, PowerShell 4104 |
| `0870_dv_win_discovery.xml` | 100873-100878 | Domain/account/network discovery, remote session and remote command use, timestomping, alternate data streams, COM CLSID hijack | Sysmon 1/13/15, PowerShell 4104 |
| `0900_dv_win_credential_access.xml` | 100900-100908 | LSASS access and dumps, SAM/SECURITY/SYSTEM hive export, NTDS/shadow copies, Kerberoasting, stored credentials, Mimikatz syntax, DCSync | Sysmon 10/1, Security 4769/4662 |
| `0930_dv_win_defense_evasion.xml` | 100930-100942 | Log clearing, Defender and firewall tampering, AMSI bypass, Sysmon/Wazuh service tampering, shadow-copy deletion, UAC bypass, audit policy changes | Security/System/Defender logs, Sysmon 1/13 |

## Deploy
1. Manager: copy `0*_dv_win_*.xml` to `/var/ossec/etc/rules/` (with the Linux rules), `chown wazuh:wazuh`, restart the manager.
2. Agents: merge `agent-config/ossec_agent_snippet.xml` and run `agent-config/audit_policy.ps1` elevated. Install Sysmon with a configuration that logs events 1, 3, 8, 10, 11, 13, 15 and 19-21.
3. Verify: `dv rules-check` offline, then `dv rules-check --live` and `dv doctor` against the manager.

## Notes
- Event 15 (alternate data streams) exists only if the Sysmon configuration enables FileCreateStreamHash.
- 4104 rules (100868, 100869, 100875, 100937) require script-block logging, enabled by `audit_policy.ps1`.
- Windows FIM markers match `dv_fim_test*.txt` under the monitored directories in the agent snippet; add other directories in `ossec_agent_snippet.xml` before relying on the FIM rules.
- `dv rules-check` cannot confirm field names (`win.eventdata.*`) or Sysmon event availability; compare against a real alert JSON from your Sysmon/Wazuh versions.
