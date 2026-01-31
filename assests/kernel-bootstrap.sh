#!/usr/bin/env bash
set -euo pipefail

# -----------------------------------------------------------------------------
# assets/kernel-tuning-apply.sh
#
# Purpose:
#   Run your upstream kernel/network tuning script and PRESERVE its output
#   (the big "Run / Why this tier / Planned / Before->After / Files..." blocks),
#   while also saving everything into a log file.
#
# Behavior:
#   - Streams upstream output to console (no "quiet" mode).
#   - Also writes full output to LOG_FILE.
#   - On failure, tries to extract BACKUP_DIR from output and prints the exact
#     rollback command (the same as upstream suggests).
#
# Usage:
#   sudo bash kernel-tuning-apply.sh
#   LOG_FILE=/var/log/edge-kernel-tuning.log sudo bash kernel-tuning-apply.sh
#
# NOTE: Provided "AS IS", without any warranties. Use at your own risk.
# -----------------------------------------------------------------------------

UPSTREAM_URL="https://raw.githubusercontent.com/akadorkin/vps-network-tuning-script/main/initial.sh"
LOG_FILE="${LOG_FILE:-/var/log/edge-kernel-tuning.log}"

ts()  { date '+%F %T'; }
die() { echo "$(ts) ERROR: $*" >&2; exit 1; }

require_root() { [[ ${EUID:-$(id -u)} -eq 0 ]] || die "Run as root"; }

main() {
  require_root
  mkdir -p "$(dirname "$LOG_FILE")" || true
  : >"$LOG_FILE"

  # We capture stdout+stderr into a temp file too, to parse backup dir on error.
  local tmp_out
  tmp_out="$(mktemp -t edge-kernel-tuning.XXXXXX.log)"
  trap 'rm -f "$tmp_out" >/dev/null 2>&1 || true' EXIT

  echo "$(ts) Kernel tuning apply start"
  echo "$(ts) Upstream: $UPSTREAM_URL"
  echo "$(ts) Log file: $LOG_FILE"
  echo

  set +e
  # IMPORTANT: keep upstream formatting, show it to console, and log it.
  # Use bash -s -- apply exactly like your command.
  curl -fsSL "$UPSTREAM_URL" \
    | bash -s -- apply 2>&1 \
    | tee -a "$LOG_FILE" | tee "$tmp_out"
  rc=${PIPESTATUS[1]}
  set -e

  if [[ $rc -eq 0 ]]; then
    echo
    echo "$(ts) OK kernel tuning applied"
    echo "$(ts) Log: $LOG_FILE"
    exit 0
  fi

  echo
  echo "$(ts) ERROR upstream apply failed (exit code=$rc)" >&2

  # Try to extract backup dir from output:
  # e.g. "OK Applied. Backup: /root/edge-tuning-backup-20260131-204159"
  local backup_dir
  backup_dir="$(grep -Eo '/root/edge-tuning-backup-[0-9]{8}-[0-9]{6}' "$tmp_out" | tail -n1 || true)"

  if [[ -n "${backup_dir:-}" ]]; then
    echo "$(ts) Detected backup dir: $backup_dir" >&2
    echo "$(ts) Rollback command:" >&2
    echo "sudo BACKUP_DIR=${backup_dir} bash rollback" >&2
  else
    echo "$(ts) Could not detect BACKUP_DIR from output." >&2
    echo "$(ts) Check the log and follow the upstream rollback hint if present:" >&2
    echo "  $LOG_FILE" >&2
  fi

  exit "$rc"
}

main "$@"
