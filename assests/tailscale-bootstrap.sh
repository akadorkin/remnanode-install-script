#!/usr/bin/env bash
set -euo pipefail

# -----------------------------------------------------------------------------
# assests/tailscale-bootstrap.sh
#
# Purpose:
#   - sysctl forwarding + rp_filter
#   - enable GRO + rx-udp-gro-forwarding (best-effort)
#   - install tailscale (if missing) using official install.sh
#   - ALWAYS ask for auth key interactively (hidden input) via /dev/tty
#   - run tailscale up with auth key (no URL, no hanging in pipe)
#   - print tailscale IPv4 + MagicDNS if available
#
# NOTE: Provided "AS IS", without any warranties. Use at your own risk.
# -----------------------------------------------------------------------------

# ---------- OUTPUT HELPERS ----------
log()  { echo -e "\033[1;36m==>\033[0m $*"; }
ok()   { echo -e "\033[1;32m✔\033[0m $*"; }
warn() { echo -e "\033[1;33m!\033[0m $*"; }
err()  { echo -e "\033[1;31m✖\033[0m $*"; }

runq() {
  local msg="$1"; shift
  echo -n "   $msg … "
  if "$@" >/dev/null 2>&1; then
    echo "ok"
  else
    echo "fail"
    return 1
  fi
}

require_root() { [[ ${EUID:-$(id -u)} -eq 0 ]] || { err "Run as root"; exit 1; }; }

need_tty() {
  [[ -e /dev/tty ]] || {
    err "No /dev/tty (no interactive terminal). This asset requires interactive auth key input."
    err "Run it from an interactive SSH session (not from a non-interactive pipe without TTY)."
    exit 1
  }
}

read_tty_silent() {
  # usage: read_tty_silent VAR "Prompt: "
  local __var="$1" __prompt="$2" __v=""
  # shellcheck disable=SC2162
  read -rsp "$__prompt" __v </dev/tty || true
  echo >/dev/tty || true
  printf -v "$__var" '%s' "$__v"
}

export DEBIAN_FRONTEND=noninteractive

TAILSCALE_LOG="/var/log/install-tailscale.log"
SYSCTL_FILE="/etc/sysctl.d/99-tailscale-forwarding.conf"
UP_LOG="/tmp/tailscale-up.log"

get_default_iface() {
  ip route show default 2>/dev/null | awk '/default/ {print $5; exit}' || true
}

tailscale_ip4() {
  tailscale ip -4 2>/dev/null | head -n1 || true
}

tailscale_dnsname() {
  # Best-effort: show MagicDNS name if available
  if command -v jq >/dev/null 2>&1; then
    tailscale status --json 2>/dev/null | jq -r '.Self.DNSName // empty' 2>/dev/null | sed 's/\.$//' || true
  else
    tailscale status 2>/dev/null | awk 'NR==1{print $2}' | sed 's/\.$//' || true
  fi
}

main() {
  require_root
  need_tty

  log "Preparing system for Tailscale (IP forwarding + UDP GRO)"

  install -m 0644 /dev/stdin "$SYSCTL_FILE" <<'EOF_SYSCTL'
net.ipv4.ip_forward=1
net.ipv6.conf.all.forwarding=1
net.ipv4.conf.all.rp_filter=0
net.ipv4.conf.default.rp_filter=0
EOF_SYSCTL

  runq "sysctl --system" sysctl --system

  local INTERNET_IFACE
  INTERNET_IFACE="$(get_default_iface)"
  if [[ -n "${INTERNET_IFACE:-}" ]]; then
    if command -v ethtool >/dev/null 2>&1; then
      runq "ethtool gro on"            ethtool -K "${INTERNET_IFACE}" gro on || true
      runq "ethtool rx-udp-gro-fwd on" ethtool -K "${INTERNET_IFACE}" rx-udp-gro-forwarding on || true
    else
      warn "ethtool not installed — skipping GRO tweaks"
    fi
  else
    warn "Could not detect default interface — skipping GRO tweaks"
  fi

  :> "$TAILSCALE_LOG"
  if ! command -v tailscale >/dev/null 2>&1; then
    log "Installing tailscale"
    runq "install tailscale" bash -lc "curl -fsSL https://tailscale.com/install.sh | sh >>'$TAILSCALE_LOG' 2>&1"
  else
    ok "tailscale already installed — skipping"
  fi

  runq "enable tailscaled" systemctl enable --now tailscaled || true

  # --- ALWAYS ask for auth key interactively ---
  local TS_AUTHKEY=""
  echo >/dev/tty
  echo "Paste Tailscale auth key from admin console (input hidden):" >/dev/tty
  read_tty_silent TS_AUTHKEY "TS_AUTHKEY: "
  if [[ -z "${TS_AUTHKEY}" ]]; then
    err "Auth key is empty — abort"
    exit 1
  fi

  log "Running tailscale up (auth key, non-hanging)"
  :> "$UP_LOG"
  set +e
  # Important: auth-key path works reliably in non-tty pipelines too.
  tailscale up \
    --auth-key="${TS_AUTHKEY}" \
    --advertise-exit-node \
    --ssh \
    2>&1 | tee "$UP_LOG"
  local rc=${PIPESTATUS[0]}
  set -e

  if [[ $rc -ne 0 ]]; then
    err "tailscale up failed (rc=$rc). See: $UP_LOG"
    tail -n 80 "$UP_LOG" || true
    exit "$rc"
  fi

  local ip dns
  ip="$(tailscale_ip4)"
  dns="$(tailscale_dnsname)"

  ok "Tailscale is up"
  echo "🧅  Tailscale IPv4: ${ip:-not assigned}"
  echo "🔗 MagicDNS:        ${dns:-unknown}"
  echo
  echo "Logs:"
  echo "  • Tailscale install: $TAILSCALE_LOG"
  echo "  • tailscale up:      $UP_LOG"
}

main "$@"