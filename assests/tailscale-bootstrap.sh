#!/usr/bin/env bash
set -euo pipefail

# tailscale-setup.sh
# Extracted from your old "working" script + fixes:
# - ensure tailscaled is enabled+started (so it survives reboot)
# - if no /dev/tty (running via pipe/CI), don't hang on Enter:
#   print auth URL (if any) and wait a bit for IPv4 to appear.

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

read_tty(){
  local __var="$1" __prompt="$2" __v=""
  if [[ -e /dev/tty ]]; then
    read -rp "$__prompt" __v </dev/tty || true
  else
    __v=""
  fi
  printf -v "$__var" '%s' "$__v"
}

require_root
export DEBIAN_FRONTEND=noninteractive

# ------------- CONFIG -------------
TAILSCALE_LOG="/var/log/install-tailscale.log"
SYSCTL_FILE="/etc/sysctl.d/99-tailscale-forwarding.conf"
UP_LOG="/tmp/tailscale-up.log"

# ------------- HELPERS -------------
has_tty() { [[ -e /dev/tty ]]; }

get_default_iface() {
  ip route show default 2>/dev/null | awk '/default/ {print $5; exit}' || true
}

tailscale_ip4() {
  command -v tailscale >/dev/null 2>&1 || return 0
  tailscale ip -4 2>/dev/null | head -n1 || true
}

ensure_tailscaled_running() {
  # Make tailscale survive reboot.
  if command -v systemctl >/dev/null 2>&1; then
    # do not fail hard here
    systemctl enable --now tailscaled >/dev/null 2>&1 || systemctl enable --now tailscale >/dev/null 2>&1 || true
  fi
}

wait_for_ip() {
  local max="${1:-90}" i ip=""
  for ((i=0; i<max; i++)); do
    ip="$(tailscale_ip4)"
    if [[ -n "${ip:-}" ]]; then
      echo "$ip"
      return 0
    fi
    sleep 1
  done
  return 1
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

ensure_tailscaled_running

log "Running tailscale up (waiting for auth)"
set +e
tailscale up --advertise-exit-node --ssh 2>&1 | tee "$UP_LOG"
set -e

TAILSCALE_URL="$(grep -Eo 'https://login\.tailscale\.com/[a-zA-Z0-9/_-]+' "$UP_LOG" | head -n1 || true)"
if [[ -n "$TAILSCALE_URL" ]]; then
  echo "🔗 Open to authorize: $TAILSCALE_URL"
else
  echo "⚠️ Auth URL not found. If the device is already authorized — OK."
  echo "   If not, run manually:"
  echo "   tailscale up --advertise-exit-node --ssh"
fi

if has_tty; then
  read_tty _ "Press Enter after authorizing this device in Tailscale… "
  TS_IP="$(tailscale_ip4)"
else
  warn "No /dev/tty — won't wait for Enter. Waiting up to 90s for IPv4…"
  TS_IP="$(wait_for_ip 90 || true)"
fi

if [[ -n "${TS_IP:-}" ]]; then
  echo "🧅  Tailscale IPv4: ${TS_IP}"
else
  echo "🧅  Tailscale IPv4: not assigned"
  echo "Hint:"
  echo "  - check daemon: systemctl status tailscaled"
  echo "  - re-run: tailscale up --advertise-exit-node --ssh"
fi

echo
echo "Done."
echo "Logs:"
echo "  • Tailscale install: $TAILSCALE_LOG"
echo "  • tailscale up:      $UP_LOG"