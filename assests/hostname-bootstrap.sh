#!/usr/bin/env bash
set -euo pipefail

# -----------------------------------------------------------------------------
# assets/hostname-bootstrap.sh
#
# Purpose:
#   Interactive-only hostname setup.
#   - Always asks user for hostname via /dev/tty (never reads from piped stdin).
#   - If empty -> keep current hostname (no changes).
#   - If provided -> set hostname immediately (hostnamectl + /etc/hostname).
#   - Best-effort update /etc/hosts (replace 127.0.1.1 line or add it).
#
# NOTE: Provided "AS IS", without any warranties. Use at your own risk.
# -----------------------------------------------------------------------------

LOG_FILE="${LOG_FILE:-/var/log/edge-hostname-bootstrap.log}"

ts()  { date '+%F %T'; }
log() { echo "$(ts) $*" | tee -a "$LOG_FILE"; }
die() { log "ERROR: $*"; exit 1; }

require_root() { [[ ${EUID:-$(id -u)} -eq 0 ]] || die "Run as root"; }

read_tty() {
  local __var="$1" __prompt="$2" __v=""
  [[ -e /dev/tty ]] || die "/dev/tty not available (no TTY) — hostname step is interactive-only"
  read -rp "$__prompt" __v </dev/tty || true
  printf -v "$__var" '%s' "$__v"
}

current_hostname() {
  hostnamectl --static 2>/dev/null || hostname -s 2>/dev/null || hostname 2>/dev/null || true
}

is_valid_hostname() {
  # Simple RFC-ish check:
  # - labels: [a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?
  # - total <= 253
  # - allow dots
  local h="${1:-}"
  [[ -n "$h" ]] || return 1
  [[ "${#h}" -le 253 ]] || return 1
  [[ "$h" =~ ^[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?(\.[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*$ ]]
}

update_hosts() {
  local new="$1"
  local hosts="/etc/hosts"

  [[ -f "$hosts" ]] || return 0

  # If 127.0.1.1 exists, replace its hostname field with new hostname
  if grep -qE '^[[:space:]]*127\.0\.1\.1[[:space:]]+' "$hosts"; then
    # Replace whole line "127.0.1.1  something" -> "127.0.1.1  new"
    sed -i -E "s|^[[:space:]]*127\.0\.1\.1[[:space:]]+.*$|127.0.1.1\t${new}|" "$hosts" || true
  else
    # Add a standard line
    echo -e "127.0.1.1\t${new}" >>"$hosts"
  fi
}

main() {
  require_root
  : >"$LOG_FILE"

  local cur new
  cur="$(current_hostname)"
  log "Current hostname: ${cur:-"(unknown)"}"

  echo
  echo "Hostname setup (interactive)"
  echo "  Current: ${cur:-"(unknown)"}"
  echo "  Enter new hostname (leave empty to keep current)."
  echo

  read_tty new "New hostname: "

  if [[ -z "${new}" ]]; then
    log "No hostname entered — keeping current (${cur})"
    echo "SKIP"
    exit 0
  fi

  if ! is_valid_hostname "$new"; then
    die "Invalid hostname: '$new' (letters/digits/dashes, dot-separated labels)."
  fi

  log "Applying hostname: ${new}"

  # hostnamectl is preferred
  if command -v hostnamectl >/dev/null 2>&1; then
    hostnamectl set-hostname "$new" >>"$LOG_FILE" 2>&1 || die "hostnamectl failed"
  else
    echo "$new" >/etc/hostname
    hostname "$new" >>"$LOG_FILE" 2>&1 || true
  fi

  # Ensure /etc/hostname matches
  echo "$new" >/etc/hostname

  # Best-effort /etc/hosts update
  update_hosts "$new"

  log "Hostname applied: $new"
  echo "OK"
}

main "$@"
