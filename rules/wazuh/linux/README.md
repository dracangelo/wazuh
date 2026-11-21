# Wazuh Linux rules (IDs 100100-100699)

| File | Range | Covers | Needs |
|---|---|---|---|
| `0100_dv_validation.xml` | 100100-100112 | Pipeline health markers (FIM lifecycle, syslog, auditd, web). Run first with `dv run --tag smoke --strict` | FIM, syslog, auditd, web log |
| `0200_dv_auth.xml` | 100200-100209 | sshd/sudo/su: root login, success after brute force, off-hours, service-account login, sudo shells, sudo setuid | stock sshd/sudo rules |
| `0300_dv_persistence.xml` | 100300-100324 | UID 0 accounts, privileged group adds, cron, critical-file FIM (passwd, sudoers, sshd_config, authorized_keys, systemd, ld.so.preload, PAM, shell init, setuid, temp-dir exec drops, web shells) | syscheck config |
| `0400_dv_execution_auditd.xml` | 100400-100426 | Exec from /tmp, download-to-tmp, netcat/socat shells, offensive tools, SUID enumeration, history tampering, recon bursts, shell network connects, setuid chmod, kmod, ptrace, memfd, shadow reads, log deletion | auditd + `audit/99-dv.rules` |
| `0500_dv_defense_evasion.xml` | 100500-100503 | Logging/audit/firewall stopped, SELinux permissive, audit disabled | auditd + syslog |
| `0600_dv_web.xml` | 100600-100605 | Scanners, Shellshock, traversal, web shell, Log4Shell, SQLi | apache/nginx access log |

## Rule IDs
IDs 100100-100699 are reserved for the Linux rule set in this directory. A rule ID must be unique
across every deployed file; `dv rules-check` enforces that (and runs in CI). Non-deployed reference
XML belongs in `rules/wazuh/examples/` (named `*.xml.example` so it is not scanned as deployable).

## Deploy
1. Manager: copy `0*_dv_*.xml` to `/var/ossec/etc/rules/`, `chown wazuh:wazuh`, run `/var/ossec/bin/wazuh-logtest` to try samples, then restart the manager.
2. Agents: merge `agent-config/ossec_agent_snippet.xml`; install `agent-config/audit/99-dv.rules` into `/etc/audit/rules.d/` and run `augenrules --load`.
3. Check: `dv rules-check` (offline lint) and `dv rules-check --live` (parent rules exist on your manager).

## Caveats
- Parent rule IDs (5303, 5402, 5715, 5902, 31100, ...) and a few syscheck field names (`syscheck.perm`, `syscheck.perm_after`) can differ between Wazuh versions. `dv rules-check --live` verifies parents; confirm field names against a real alert JSON.
- Volume: `dv_exec` records every command from login sessions. Start on lab hosts and measure before production.
- Rules marked level 7-9 are meant for triage and correlation, not paging.
