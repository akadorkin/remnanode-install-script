#!/usr/bin/env bash
set -euo pipefail

# -----------------------------------------------------------------------------
# assests/tailscale-bootstrap.sh
#
# Purpose:
#   - Install Tailscale using official install.sh (if missing)
#   - Ensure tailscaled enabled+started
#   - ALWAYS ask for auth key interactively (hidden input) via /dev/tty
#   - Run:
#       curl -fsSL https://tailscale.com/install.sh | sh
#       tailscale up --auth-key=... --advertise-exit-node
#   - Print Tailscale IPv4 + MagicDNS name (best-effort)
#
# NOTE: Provided "AS IS", without any warranties. Use at your own risk.
# -----------------------------------------------------------------------------

# ---------- minimal output helpers ----------
say()  { echo "$*"; }
err()  { echo "ERROR: $*" >&2; }

require_root() {
  [[ ${EUID:-$(id -u)} -eq 0 ]] || { err "Run as root"; exit 1; }
}

need_tty() {
  [[ -e /dev/tty ]] || {
    err "No /dev/tty (no interactive terminal)."
    err "Run this asset from an interactive session (SSH console)."
    exit 1
  }
}

read_tty_silent() {
  local __var="$1" __prompt="$2" __v=""
  # shellcheck disable=SC2162
  read -rsp "$__prompt" __v </dev/tty || true
  echo >/dev/tty || true
  printf -v "$__var" '%s' "$__v"
}

tailscale_ip4() {
  command -v tailscale >/dev/null 2>&1 || return 0
  tailscale ip -4 2>/dev/null | head -n1 || true
}

tailscale_dnsname() {
  command -v tailscale >/dev/null 2>&1 || return 0
  if command -v jq >/dev/null 2>&1 && tailscale status --json >/dev/null 2>&1; then
    tailscale status --json 2>/dev/null | jq -r '.Self.DNSName // empty' 2>/dev/null | sed 's/\.$//' || true
  else
    # fallback (best-effort, not perfect)
    tailscale status 2>/dev/null | awk 'NR==1{print $2}' | sed 's/\.$//' || true
  fi
}

main() {
  require_root
  need_tty
  export DEBIAN_FRONTEND=noninteractive

  # Ask auth key first (your requirement)
  local TS_AUTHKEY=""
  echo >/dev/tty
  echo "Paste Tailscale auth key (tskey-auth-...), input hidden:" >/dev/tty
  read_tty_silent TS_AUTHKEY "TS_AUTHKEY: "
  if [[ -z "${TS_AUTHKEY}" ]]; then
    err "Auth key is empty — abort"
    exit 1
  fi

  # Install tailscale if missing
  if ! command -v tailscale >/dev/null 2>&1; then
    # Exactly your pipeline logic, but not chained to avoid hiding errors
    curl -fsSL https://tailscale.com/install.sh | sh
  fi

  # Ensure daemon is enabled and running
  systemctl enable --now tailscaled >/dev/null 2>&1 || true

  # Bring up tailscale with auth key (non-hanging)
  # Note: do NOT print key; do NOT store key on disk.
  tailscale up --auth-key="${TS_AUTHKEY}" --advertise-exit-node

  local ip dns
  ip="$(tailscale_ip4)"
  dns="$(tailscale_dnsname)"

  echo
  say "✅ Tailscale is up"
  say "🧅  Tailscale IPv4: ${ip:-not assigned}"
  say "🔗 MagicDNS:        ${dns:-unknown}"
}

main "$@"