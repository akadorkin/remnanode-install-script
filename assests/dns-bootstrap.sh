#!/usr/bin/env bash
set -euo pipefail

# -----------------------------------------------------------------------------
# assets/dns-switcher-apply.sh
#
# Purpose:
#   Run upstream dns-switcher reliably when this script itself is started via pipe
#   (e.g. curl ... | sudo bash). Upstream uses `read -p` which needs a TTY to show
#   prompts. We attach it to /dev/tty in interactive mode.
#
# Modes:
#   1) Non-interactive (recommended for automation):
#        DNS_PROFILE=1..5 -> auto "y" + choose profile, quiet, prints "OK"
#   2) Interactive:
#        DNS_PROFILE empty -> user sees prompts and types, because stdin/out is /dev/tty
#
# NOTE: Provided "AS IS", without any warranties. Use at your own risk.
# -----------------------------------------------------------------------------

UPSTREAM_URL="https://raw.githubusercontent.com/AndreyTimoschuk/dns-switcher/main/dns-switcher.sh"
WORKDIR="/tmp/dns-switcher"
SCRIPT_PATH="${WORKDIR}/dns-switcher.sh"

LOG_FILE="${LOG_FILE:-/var/log/edge-dns-switcher.log}"
DNS_PROFILE="${DNS_PROFILE:-}" # 1..5 or empty (interactive)

ts()  { date '+%F %T'; }
log() { echo "$(ts) $*" | tee -a "$LOG_FILE" >/dev/null; }  # log only
die() { echo "$(ts) ERROR: $*" | tee -a "$LOG_FILE" >&2; exit 1; }

require_root() { [[ ${EUID:-$(id -u)} -eq 0 ]] || die "Run as root"; }

cleanup() { rm -rf "$WORKDIR" >/dev/null 2>&1 || true; }
trap cleanup EXIT

download_upstream() {
  mkdir -p "$WORKDIR"
  curl -fsSL "$UPSTREAM_URL" -o "$SCRIPT_PATH" || die "Failed to download dns-switcher"
  chmod +x "$SCRIPT_PATH"
}

run_non_interactive() {
  # Feed answers to upstream:
  # 1) confirm "y"
  # 2) profile number
  #
  # All output -> log, console -> OK
  [[ "$DNS_PROFILE" =~ ^[1-5]$ ]] || die "DNS_PROFILE must be 1..5 (got: '$DNS_PROFILE')"

  : >"$LOG_FILE"
  log "DNS switcher apply start (profile ${DNS_PROFILE})"
  log "Downloading dns-switcher"
  log "Running dns-switcher (non-interactive)"

  # Send y + profile
  # Force upstream to run even when stdin is not TTY
  { printf "y\n%s\n" "$DNS_PROFILE"; } | bash "$SCRIPT_PATH" >>"$LOG_FILE" 2>&1 || {
    echo "FAIL (see log: $LOG_FILE)" >&2
    exit 1
  }

  echo "OK"
}

run_interactive() {
  # Attach upstream to /dev/tty so prompts ALWAYS show.
  # This solves the "no prompt when running via pipe" problem.
  [[ -e /dev/tty ]] || die "/dev/tty not available (no TTY). Use DNS_PROFILE=1..5 instead."

  : >"$LOG_FILE"
  log "DNS switcher apply start (interactive)"
  log "Downloading dns-switcher"
  log "Running dns-switcher (interactive on /dev/tty)"

  # We still log everything, but also show it live to user.
  # stdin/out bound to tty, stderr too.
  # tee goes to both console and log.
  bash "$SCRIPT_PATH" </dev/tty > >(tee -a "$LOG_FILE") 2> >(tee -a "$LOG_FILE" >&2)
}

main() {
  require_root
  download_upstream

  if [[ -n "$DNS_PROFILE" ]]; then
    run_non_interactive
  else
    run_interactive
  fi
}

main "$@"
