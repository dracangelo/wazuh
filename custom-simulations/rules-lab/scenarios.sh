#!/usr/bin/env bash
# Benign, self-cleaning scenarios that exercise rules/wazuh/linux/*. Run ON a lab target, from an
# interactive session (SSH) so auditd records a login uid. Needs passwordless sudo for some scenarios.
# Usage: scenarios.sh <scenario>
set -u
S="${1:?scenario required}"
W="$(mktemp -d /tmp/dv_XXXXXX)"
cleanup() { rm -rf "$W"; sudo -n userdel dv_grp_test >/dev/null 2>&1 || true; }
trap cleanup EXIT

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
  log_delete)      sudo -n sh -c 'touch /var/log/dv_test.log; rm -f /var/log/dv_test.log' ;;
  priv_group)      G=sudo; getent group sudo >/dev/null || G=wheel
                   sudo -n useradd -M -N -r dv_grp_test && sudo -n usermod -aG "$G" dv_grp_test ;;
  cron_edit)       crontab -l >"$W/cron.bak" 2>/dev/null || true
                   { cat "$W/cron.bak"; echo "# dv_test"; } | crontab -; sleep 1
                   if [ -s "$W/cron.bak" ]; then crontab "$W/cron.bak"; else crontab -r; fi ;;
  fim_sudoers)     printf '# dv test\n' | sudo -n tee /etc/sudoers.d/dv_test >/dev/null
                   sudo -n chmod 0440 /etc/sudoers.d/dv_test; sleep 3; sudo -n rm -f /etc/sudoers.d/dv_test ;;
  fim_cron)        sudo -n sh -c 'echo "# dv test" > /etc/cron.d/dv_test; sleep 3; rm -f /etc/cron.d/dv_test' ;;
  fim_systemd)     sudo -n sh -c 'printf "[Unit]\nDescription=dv test\n" > /etc/systemd/system/dv_test.service; sleep 3; rm -f /etc/systemd/system/dv_test.service' ;;
  fim_authkeys)    mkdir -p "$HOME/.ssh"; touch "$HOME/.ssh/authorized_keys"
                   cp "$HOME/.ssh/authorized_keys" "$W/ak.bak"
                   echo "# dv test" >> "$HOME/.ssh/authorized_keys"; sleep 3
                   cp "$W/ak.bak" "$HOME/.ssh/authorized_keys" ;;
  marker_syslog)   logger -p auth.notice -t dv_canary "DV_CANARY id=$(date +%s)" ;;
  marker_audit)    [ -e /etc/dv_audit_marker ] || { echo "provision first: sudo touch /etc/dv_audit_marker" >&2; exit 4; }
                   date | sudo -n tee -a /etc/dv_audit_marker >/dev/null ;;
  *) echo "unknown scenario: $S" >&2; exit 2 ;;
esac
echo "scenario $S done"
