#!/usr/bin/env bash
set -euo pipefail

# tailscale-setup.sh
# Extracted from your old "working" script:
# - sysctl forwarding + rp_filter
# - enable GRO + rx-udp-gro-forwarding (best-effort)
# - install tailscale (if missing) with official install.sh (log to file)
# - run `tailscale up --advertise-exit-node --ssh`, print auth URL if present
# - wait for Enter, then show tailscale IPv4
#
# Note: this script keeps the original behavior (Enter wait, URL extraction).
# It does NOT try to be "smart" beyond that; it mirrors the old logic.

# ------------- OUTPUT HELPERS (same style as old) -------------
log() { echo -e "\033[1;36m==>\033[0m $*"; }
ok()  { echo -e "\033[1;32m✔\033[0m $*"; }
warn(){ echo -e "\033[1;33m!\033[0m $*"; }
err() { echo -e "\033[1;31m✖\033[0m $*"; }

runq(){
  local msg="$1"; shift
  echo -n "   $msg … "
  if "$@" >/dev/null 2>&1; then
    echo "ok"
  else
    echo "fail"
    return 1
  fi
}

require_root(){ [[ ${EUID:-$(id -u)} -eq 0 ]] || { err "Run as root"; exit 1; }; }
read_tty(){ local __var="$1" __prompt="$2" __v=""; read -rp "$__prompt" __v </dev/tty || true; printf -v "$__var" '%s' "$__v"; }

require_root
export DEBIAN_FRONTEND=noninteractive

# ------------- CONFIG -------------
TAILSCALE_LOG="/var/log/install-tailscale.log"
SYSCTL_FILE="/etc/sysctl.d/99-tailscale-forwarding.conf"

# ------------- HELPERS -------------
get_default_iface() {
  # matches your old script (simple)
  ip route show default 2>/dev/null | awk '/default/ {print $5; exit}' || true
}

tailscale_ip4() {
  tailscale ip -4 2>/dev/null || true
}

# ------------- MAIN -------------
log "Preparing system for Tailscale (IP forwarding + UDP GRO)"

install -m 0644 /dev/stdin "$SYSCTL_FILE" <<'EOF_SYSCTL'
net.ipv4.ip_forward=1
net.ipv6.conf.all.forwarding=1
net.ipv4.conf.all.rp_filter=0
net.ipv4.conf.default.rp_filter=0
EOF_SYSCTL

runq "sysctl --system" sysctl --system

INTERNET_IFACE="$(get_default_iface)"
if [[ -n "${INTERNET_IFACE:-}" ]]; then
  if command -v ethtool >/dev/null 2>&1; then
    runq "ethtool gro on"              ethtool -K "${INTERNET_IFACE}" gro on || true
    runq "ethtool rx-udp-gro-fwd on"   ethtool -K "${INTERNET_IFACE}" rx-udp-gro-forwarding on || true
  else
    warn "ethtool not installed — skipping GRO tweaks"
  fi
else
  warn "Could not detect default interface — skipping GRO tweaks"
fi

:> "$TAILSCALE_LOG"
if ! command -v tailscale >/dev/null 2>&1; then
  log "Installing tailscale"
  # exactly as in old script: install.sh -> sh, log to file
  runq "install tailscale" bash -lc "curl -fsSL https://tailscale.com/install.sh | sh >>'$TAILSCALE_LOG' 2>&1"
else
  ok "tailscale already installed — skipping"
fi

log "Running tailscale up (waiting for auth)"
set +e
tailscale up --advertise-exit-node --ssh | tee /tmp/tailscale-up.log
set -e

TAILSCALE_URL="$(grep -Eo 'https://login\.tailscale\.com/[a-zA-Z0-9/_-]+' /tmp/tailscale-up.log | head -n1 || true)"
if [[ -n "$TAILSCALE_URL" ]]; then
  echo "🔗 Open to authorize: $TAILSCALE_URL"
else
  echo "⚠️ Auth URL not found. If the device is already authorized — OK."
  echo "   If not, run manually:"
  echo "   tailscale up --advertise-exit-node --ssh"
fi

read_tty _ "Press Enter after authorizing this device in Tailscale… "

TS_IP="$(tailscale_ip4)"
echo "🧅  Tailscale IPv4: ${TS_IP:-not assigned}"

echo
echo "Done."
echo "Logs:"
echo "  • Tailscale install: $TAILSCALE_LOG"
echo "  • tailscale up:      /tmp/tailscale-up.log"
