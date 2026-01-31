#!/usr/bin/env bash
set -euo pipefail

# -----------------------------------------------------------------------------
# assets/dns-bootstrap.sh
#
# Purpose:
#   Run upstream dns-switcher reliably even when THIS script is started via pipe
#   (e.g. curl ... | sudo bash).
#
# Key behavior you asked for:
#   ✅ If DNS_SWITCHER=1 and DNS_PROFILE is set (e.g. 1) -> NO prompts, NO waiting,
#      no noisy output to console (only a short OK/FAIL), full output goes to log.
#
#   ✅ If DNS_SWITCHER=1 but DNS_PROFILE is empty -> run INTERACTIVE on /dev/tty
#      so prompts are visible and user can choose 1..5 manually.
#
# Env:
#   DNS_SWITCHER=1|0     (default: 1)
#   DNS_PROFILE=1..5     (default: empty -> interactive)
#   QUIET=1|0            (default: 1)  # quiet console in non-interactive mode
#   LOG_FILE=...         (default below)
#
# Upstream:
#   https://github.com/AndreyTimoschuk/dns-switcher
#
# NOTE: Provided "AS IS", without any warranties. Use at your own risk.
# -----------------------------------------------------------------------------

UPSTREAM_URL="https://raw.githubusercontent.com/AndreyTimoschuk/dns-switcher/main/dns-switcher.sh"
WORKDIR="/tmp/dns-switcher"
SCRIPT_PATH="${WORKDIR}/dns-switcher.sh"

LOG_FILE="${LOG_FILE:-/var/log/vps-edge-dns-switcher.log}"

DNS_SWITCHER="${DNS_SWITCHER:-1}"   # 1/0
DNS_PROFILE="${DNS_PROFILE:-}"      # 1..5 or empty (interactive)
QUIET="${QUIET:-1}"                 # 1/0 (only affects non-interactive console noise)

ts() { date '+%F %T'; }

# log to file only (no console spam)
log() { echo "$(ts) $*" >>"$LOG_FILE"; }

die() {
  echo "$(ts) ERROR: $*" | tee -a "$LOG_FILE" >&2
  exit 1
}

require_root() { [[ ${EUID:-$(id -u)} -eq 0 ]] || die "Run as root"; }

cleanup() { rm -rf "$WORKDIR" >/dev/null 2>&1 || true; }
trap cleanup EXIT

download_upstream() {
  mkdir -p "$WORKDIR"
  curl -fsSL "$UPSTREAM_URL" -o "$SCRIPT_PATH" || die "Failed to download dns-switcher"
  chmod +x "$SCRIPT_PATH" || true
}

run_non_interactive() {
  [[ "$DNS_PROFILE" =~ ^[1-5]$ ]] || die "DNS_PROFILE must be 1..5 (got: '$DNS_PROFILE')"

  : >"$LOG_FILE"
  log "DNS switcher apply start (non-interactive)"
  log "Upstream: $UPSTREAM_URL"
  log "Profile: $DNS_PROFILE"

  # Feed answers to upstream:
  # 1) confirm "y"
  # 2) profile number
  #
  # IMPORTANT: send ALL output to log; console is just OK/FAIL (if QUIET=1).
  if { printf "y\n%s\n" "$DNS_PROFILE"; } | bash "$SCRIPT_PATH" >>"$LOG_FILE" 2>&1; then
    if [[ "$QUIET" == "1" ]]; then
      echo "OK"
    else
      echo "$(ts) OK dns-switcher applied (profile $DNS_PROFILE) (log: $LOG_FILE)"
    fi
  else
    echo "FAIL (see log: $LOG_FILE)" >&2
    exit 1
  fi
}

run_interactive() {
  [[ -e /dev/tty ]] || die "/dev/tty not available (no TTY). Use DNS_PROFILE=1..5 instead."

  : >"$LOG_FILE"
  log "DNS switcher apply start (interactive)"
  log "Upstream: $UPSTREAM_URL"

  # Attach upstream to /dev/tty so prompts ALWAYS show (fixes pipe-run prompt issues)
  # Also tee everything to log for later debugging.
  bash "$SCRIPT_PATH" </dev/tty > >(tee -a "$LOG_FILE") 2> >(tee -a "$LOG_FILE" >&2)
}

main() {
  require_root

  # allow disabling DNS step fully
  if [[ "${DNS_SWITCHER}" != "1" ]]; then
    echo "SKIP"
    exit 0
  fi

  download_upstream

  # ✅ Your rule:
  # if DNS_SWITCHER=1 and DNS_PROFILE is provided (e.g. 1) -> skip prompts entirely.
  if [[ -n "${DNS_PROFILE}" ]]; then
    run_non_interactive
  else
    run_interactive
  fi
}

main "$@"
