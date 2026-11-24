# Sigma reference rules

These are portable Sigma versions of the behaviours covered by `rules/wazuh/` and the catalog.
They are **reference material, not deployed**: this framework validates Wazuh detections end to end
and does not convert, deploy or score Sigma rules. `tests/unit/test_sigma_rules.py` only checks that
each file is structurally valid and uniquely identified, so a syntax mistake fails CI.

## Rules

| File | Log source | Wazuh equivalent | ATT&CK |
|---|---|---|---|
| `linux/reverse_shell_indicators.yml` | process_creation | 100403, 100404, 100420 | T1059.004, T1071 |
| `linux/systemd_service_creation.yml` | process_creation | 100315 | T1543.002 |
| `linux/ld_preload_injection.yml` | process_creation | 100414 | T1574.006 |
| `linux/ssh_port_forwarding.yml` | process_creation | 100415 | T1572 |
| `linux/sensitive_file_symlink.yml` | process_creation | 100416 | T1003.008 |
| `linux/sudo_privilege_enumeration.yml` | process_creation | 100417 | T1548.003 |
| `linux/crontab_modification.yml` | process_creation | 100302, 100314 | T1053.003 |
| `linux/history_clearing.yml` | process_creation | 100407 | T1070.003 |
| `linux/kernel_module_load.yml` | process_creation | 100422 | T1547.006 |
| `linux/package_manager_suspicious.yml` | process_creation | — | — |
| `linux/sensitive_file_access.yml` | process_creation | 100425 | T1003.008 |
| `linux/ssh_authorized_keys_modification.yml` | file_event | 100313 | T1098.004 |
| `linux/useradd_local_account.yml` | process_creation | 100300 | T1136.001 |
| `linux/user_modification.yml` | process_creation | 100301 | T1098 |
| `windows/clear_event_logs.yml` | process_creation | 100930-100932 | T1070.001 |
| `windows/domain_discovery.yml` | process_creation | 100873 | T1087.002, T1018, T1482 |
| `windows/remote_session_execution.yml` | process_creation | 100874 | T1021.001, T1021.006 |
| `windows/timestomp.yml` | process_creation | 100875, 100878 | T1070.006 |
| `windows/alternate_data_stream.yml` | file_event | 100876 | T1564.004 |
| `windows/account_creation.yml` | process_creation | 100753 | T1136.001 |
| `windows/certutil_download.yml` | process_creation | 100851 | T1105 |
| `windows/disable_windows_defender.yml` | process_creation | 100933-100935 | T1562.001 |
| `windows/lsass_dump.yml` | process_creation | 100900, 100901 | T1003.001 |
| `windows/mimikatz_indicators.yml` | process_creation | 100907 | T1003 |
| `windows/mshta_suspicious.yml` | process_creation | 100853 | T1218.005 |
| `windows/powershell_encoded_command.yml` | process_creation | 100856 | T1059.001 |
| `windows/registry_run_key.yml` | registry_set | 100805 | T1547.001 |
| `windows/rundll32_suspicious.yml` | process_creation | 100855 | T1218.011 |
| `windows/scheduled_task_creation.yml` | process_creation | 100872 | T1053.005 |
| `windows/service_creation.yml` | process_creation | 100800, 100801 | T1543.003 |
| `windows/suspicious_powershell_download.yml` | process_creation | 100857 | T1059.001, T1105 |
| `windows/suspicious_whoami_net.yml` | process_creation | 100860, 100862 | T1033, T1082 |
| `windows/wmi_event_subscription.yml` | process_creation | 100807 | T1546.003 |

`—` means there is no direct Wazuh counterpart; the Sigma rule is a reference only.

## Adding a rule

1. Use a new UUID (`uuidgen`) for `id`; duplicates fail the test.
2. Keep `status: experimental` until it has been tried against real telemetry.
3. Use a Sigma-supported `logsource` and a `condition` in `detection`.
4. Tag the technique as `attack.t####` or `attack.t####.###`, and update the table above.
