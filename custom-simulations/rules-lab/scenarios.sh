#!/usr/bin/env bash
# Benign, self-cleaning scenarios that exercise rules/wazuh/linux/*. Run ON a lab target, from an
# interactive session (SSH) so auditd records a login uid. Needs passwordless sudo for some scenarios.
# Usage: scenarios.sh <scenario>
#
# Every resource name is unique per execution (see settings: DV_EXEC_ID) and every created resource is
# recorded so cleanup removes only what this run created. A pre-existing account or path is never
# touched; the scenario refuses to run instead.
if ! declare -F dv_cleanup >/dev/null 2>&1; then
  . "$(dirname "$0")/../lib/dv_safety.sh" 2>/dev/null || { echo "dv_safety.sh not found" >&2; exit 1; }
fi
set -u
S="${1:?scenario required}"
SUF="$(dv_suffix)"
U="dv_grp_${SUF}"
W="$(dv_tmpdir)" || exit 1

case "$S" in
  exec_tmp)        cp "$(command -v true)" "$W/dv_payload" && "$W/dv_payload" ;;
  benign_exec)     /usr/bin/env true ;;
  download_tmp)    curl -s -m 3 -o "$W/dl" http://127.0.0.1:9/dv || true ;;
  nc_exec)         NC="$(command -v ncat || command -v nc || true)"; [ -n "$NC" ] || { echo "no nc/ncat" >&2; exit 3; }
                   "$NC" -w 1 -e /bin/true 127.0.0.1 9 2>/dev/null || true ;;
  scanner)         command -v nmap >/dev/null || { echo "nmap not installed" >&2; exit 3; }; nmap -V >/dev/null ;;
  find_suid)       find /usr/bin -maxdepth 1 -perm -4000 >/dev/null 2>&1 ;;
  history_tamper)  touch "$W/.bash_history"; rm -f "$W/.bash_history" ;;
  recon_burst)     for c in whoami id "uname -a" hostname "ip a" "ss -tan" w who "last -n 3" id; do $c >/dev/null 2>&1 || true; done ;;
  recon_few)       whoami >/dev/null; id >/dev/null; hostname >/dev/null ;;
  suid_chmod)      cp "$(command -v true)" "$W/suid_test" && chmod u+s "$W/suid_test" ;;
  shadow_read)     sudo -n cat /etc/shadow >/dev/null ;;
  log_delete)      L="/var/log/dv_${SUF}.log"
                   dv_sudo_file "$L" "# dv test ${SUF}" 0644 || exit 1
                   sleep 1
                   sudo -n rm -f "$L" ;;
  priv_group)      G=sudo; getent group sudo >/dev/null || G=wheel
                   dv_own_user "$U" || exit 1
                   sudo -n usermod -aG "$G" "$U" ;;
  cron_edit)       B="$(dv_backup_crontab)" || exit 1
                   { cat "$B"; echo "# dv test ${SUF}"; } | crontab - || exit 1
                   sleep 1 ;;
  fim_sudoers)     F="/etc/sudoers.d/dv_${SUF}"
                   dv_sudo_file "$F" "# dv test ${SUF}" 0440 || exit 1
                   sleep 3; sudo -n rm -f "$F" ;;
  fim_cron)        F="/etc/cron.d/dv_${SUF}"
                   dv_sudo_file "$F" "# dv test ${SUF}" 0644 || exit 1
                   sleep 3; sudo -n rm -f "$F" ;;
  fim_systemd)     F="/etc/systemd/system/dv_${SUF}.service"
                   dv_sudo_file "$F" "[Unit]
Description=dv test ${SUF}" 0644 || exit 1
                   sleep 3; sudo -n rm -f "$F" ;;
  fim_authkeys)    AK="$HOME/.ssh/authorized_keys"
                   mkdir -p "$HOME/.ssh" || exit 1
                   B=""
                   if [ -e "$AK" ]; then
                     B="$(dv_backup "$AK")" || exit 1
                   else
                     dv_own_file "$AK" "" || exit 1
                   fi
                   echo "# dv test ${SUF}" >>"$AK"; sleep 3
                   if [ -n "$B" ]; then cp -p "$B" "$AK"; else : >"$AK"; fi ;;
  marker_syslog)   logger -p auth.notice -t dv_canary "DV_CANARY id=$(date +%s)-${SUF}" ;;
  marker_audit)    [ -e /etc/dv_audit_marker ] || { echo "provision first: sudo touch /etc/dv_audit_marker" >&2; exit 4; }
                   date | sudo -n tee -a /etc/dv_audit_marker >/dev/null ;;
  *) echo "unknown scenario: $S" >&2; exit 2 ;;
esac
echo "scenario $S done (exec ${SUF})"
