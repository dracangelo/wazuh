# shellcheck shell=bash
# Shared safety and cleanup helpers for dv simulations.
#
# The framework prepends this file to every custom simulation (see adapters/custom.py) and exports
# DV_EXEC_ID / DV_TEST_ID. Everything a script creates through these helpers is recorded in a
# per-execution manifest, and cleanup removes only resources whose creation this execution observed.
# Cleanup is idempotent, runs on EXIT/INT/TERM/HUP, and reports failures on stderr (the framework
# stores stderr as evidence).
#
# Rules:
#   * never overwrite or remove a pre-existing path, account, crontab or unit;
#   * prefer a unique name derived from dv_suffix;
#   * use dv_own_* / dv_sudo_file so ownership is recorded before you use the resource.

DV_EXEC_ID="${DV_EXEC_ID:-dv$(date -u +%y%m%d%H%M%S)-$$-$RANDOM}"
DV_TEST_ID="${DV_TEST_ID:-manual}"
DV_CLEANUP_DONE="${DV_CLEANUP_DONE:-0}"

if [ -n "${DV_MANIFEST:-}" ]; then
  : >"$DV_MANIFEST" 2>/dev/null || DV_MANIFEST=/dev/null
else
  # mktemp: unpredictable name, mode 0600, never follows a pre-planted symlink.
  DV_MANIFEST="$(mktemp "${TMPDIR:-/tmp}/dv_manifest_XXXXXX" 2>/dev/null)" || DV_MANIFEST=/dev/null
fi

dv_log() { printf 'dv[%s] %s\n' "$DV_TEST_ID" "$*" >&2; }

_dv_record() { printf '%s\n' "$1" >>"$DV_MANIFEST" 2>/dev/null || dv_log "WARN: cannot record $1"; }

# Filesystem/account-safe suffix for this execution (no separators, no leading dash).
dv_suffix() { printf '%s' "${DV_EXEC_ID//[^A-Za-z0-9]/}"; }

# dv_require_lab_host HOST - exit 64 unless HOST is localhost or a literal private/loopback IPv4.
# Anchored on purpose: a glob such as "10.*" would also accept the public name 10.evil.example.
dv_require_lab_host() {
  local h="${1:-}"
  local octet='(25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])'
  if [ "$h" = localhost ]; then return 0; fi
  if [[ "$h" =~ ^(127|10)(\.${octet}){3}$ ]] ||
     [[ "$h" =~ ^192\.168(\.${octet}){2}$ ]] ||
     [[ "$h" =~ ^172\.(1[6-9]|2[0-9]|3[01])(\.${octet}){2}$ ]]; then
    return 0
  fi
  echo "refusing non-lab target: $h" >&2
  exit 64
}

# Unique private temp dir, removed by cleanup.
dv_tmpdir() {
  local d
  d="$(mktemp -d "${TMPDIR:-/tmp}/dv_tmp_$(dv_suffix)_XXXXXX")" || return 1
  _dv_record "dir:$d"
  printf '%s' "$d"
}

# dv_own_file PATH [CONTENT] - create PATH only if it does not already exist.
dv_own_file() {
  local path="$1" content="${2-}"
  if [ -e "$path" ]; then
    dv_log "refusing to touch pre-existing $path"
    return 1
  fi
  printf '%s' "$content" >"$path" || return 1
  _dv_record "file:$path"
}

# dv_sudo_file PATH CONTENT [MODE] - root-owned file, refused if PATH already exists.
dv_sudo_file() {
  local path="$1" content="$2" mode="${3:-0644}"
  if sudo -n sh -c 'test -e "$1"' _ "$path"; then
    dv_log "refusing to touch pre-existing $path"
    return 1
  fi
  printf '%s\n' "$content" | sudo -n tee "$path" >/dev/null || return 1
  _dv_record "file:$path"
  sudo -n chmod "$mode" "$path"
}

# dv_own_user NAME - create a system account only if it does not already exist.
dv_own_user() {
  local user="$1"
  if getent passwd "$user" >/dev/null 2>&1; then
    dv_log "refusing: account $user already exists"
    return 1
  fi
  sudo -n useradd -M -N -r "$user" || return 1
  _dv_record "user:$user"
}

# dv_backup PATH - private copy of a user-owned file; printed on stdout.
dv_backup() {
  local path="$1" backup
  backup="$(mktemp "${TMPDIR:-/tmp}/dv_backup_XXXXXX")" || return 1
  cp -p "$path" "$backup" 2>/dev/null || { rm -f "$backup"; return 1; }
  _dv_record "restore:$path:$backup"
  printf '%s' "$backup"
}

# dv_backup_crontab - snapshot the current user's crontab; printed path is restored by cleanup.
dv_backup_crontab() {
  local backup
  backup="$(mktemp "${TMPDIR:-/tmp}/dv_crontab_XXXXXX")" || return 1
  crontab -l >"$backup" 2>/dev/null || : >"$backup"
  _dv_record "crontab:$backup"
  printf '%s' "$backup"
}

# Remove only resources recorded in this execution's manifest. Safe to run repeatedly.
dv_cleanup() {
  [ "$DV_CLEANUP_DONE" = 1 ] && return 0
  DV_CLEANUP_DONE=1
  [ -f "$DV_MANIFEST" ] || return 0

  local rc=0 line kind rest path backup
  while IFS= read -r line; do
    [ -n "$line" ] || continue
    kind="${line%%:*}"
    rest="${line#*:}"
    case "$kind" in
      file)
        [ -e "$rest" ] || continue
        if ! rm -f -- "$rest" 2>/dev/null && ! sudo -n rm -f -- "$rest" 2>/dev/null; then
          dv_log "CLEANUP FAILED: could not remove $rest"
          rc=1
        fi
        ;;
      dir)
        [ -d "$rest" ] || continue
        # an interrupted chattr test can leave an immutable file that rm cannot remove
        command -v chattr >/dev/null 2>&1 && chattr -R -i -- "$rest" 2>/dev/null
        rm -rf -- "$rest" 2>/dev/null || { dv_log "CLEANUP FAILED: could not remove $rest"; rc=1; }
        ;;
      user)
        getent passwd "$rest" >/dev/null 2>&1 || continue
        sudo -n userdel "$rest" 2>/dev/null || { dv_log "CLEANUP FAILED: could not delete account $rest"; rc=1; }
        ;;
      restore)
        path="${rest%%:*}"
        backup="${rest#*:}"
        if [ -e "$backup" ]; then
          cp -p "$backup" "$path" 2>/dev/null || { dv_log "CLEANUP FAILED: could not restore $path"; rc=1; }
          rm -f "$backup"
        fi
        ;;
      crontab)
        if [ -s "$rest" ]; then
          crontab "$rest" 2>/dev/null || { dv_log "CLEANUP FAILED: could not restore crontab"; rc=1; }
        else
          crontab -r 2>/dev/null || true   # no crontab existed before this run
        fi
        rm -f "$rest"
        ;;
      *)
        dv_log "WARN: unknown manifest entry $line"
        ;;
    esac
  done <"$DV_MANIFEST"

  rm -f "$DV_MANIFEST" 2>/dev/null || true
  return "$rc"
}

_dv_on_exit() {
  local status=$?
  if ! dv_cleanup; then
    dv_log "cleanup incomplete"
    [ "$status" -eq 0 ] && status=70
  fi
  exit "$status"
}

trap _dv_on_exit EXIT
trap 'dv_log "signal INT received"; exit 130' INT
trap 'dv_log "signal TERM received"; exit 143' TERM
trap 'dv_log "signal HUP received"; exit 129' HUP
