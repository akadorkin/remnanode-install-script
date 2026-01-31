#!/usr/bin/env bash
set -euo pipefail

# assets/tailscale-bootstrap.sh
#
# 1) Делает sysctl для forwarding + rp_filter
# 2) Включает GRO + rx-udp-gro-forwarding (best-effort)
# 3) Ставит tailscale (если нет)
# 4) Включает и запускает tailscaled через systemd (чтобы после ребута точно поднимался)
# 5) Запускает: tailscale up --advertise-exit-node --ssh
# 6) Печатает URL (если есть), ждёт Enter (ИНТЕРАКТИВНО), потом печатает IPv4
#
# Поведение намеренно "как в твоём монолите": без авто-режимов и без переменных.

# ------------- OUTPUT HELPERS (same style as your old) -------------
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
UP_LOG="/tmp/tailscale-up.log"

# ------------- HELPERS -------------
get_default_iface() {
  ip route show default 2>/dev/null | awk '/default/ {print $5; exit}' || true
}

tailscale_ip4() {
  tailscale ip -4 2>/dev/null | head -n1 || true
}

ensure_tailscaled() {
  # ВАЖНО: чтобы после ребута tailscale поднимался, демон должен быть enabled.
  if command -v systemctl >/dev/null 2>&1; then
    runq "enable tailscaled" systemctl enable tailscaled 2>/dev/null || systemctl enable tailscale 2>/dev/null || true
    runq "start tailscaled"  systemctl start  tailscaled 2>/dev/null || systemctl start  tailscale 2>/dev/null || true
  else
    warn "systemctl not found — cannot enable tailscaled on boot"
  fi
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

ensure_tailscaled

log "Running tailscale up (waiting for auth)"
set +e
# ВАЖНО: как у тебя — выводим в консоль и в лог
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

read_tty _ "Press Enter after authorizing this device in Tailscale… "

TS_IP="$(tailscale_ip4)"
echo "🧅  Tailscale IPv4: ${TS_IP:-not assigned}"

# На всякий — ещё раз гарантируем service state (после up prefs уже сохранены)
ensure_tailscaled

echo
echo "Done."
echo "Logs:"
echo "  • Tailscale install: $TAILSCALE_LOG"
echo "  • tailscale up:      $UP_LOG"

if command -v systemctl >/dev/null 2>&1; then
  echo
  echo "Service:"
  echo "  • enabled: $(systemctl is-enabled tailscaled 2>/dev/null || systemctl is-enabled tailscale 2>/dev/null || echo '?')"
  echo "  • active:  $(systemctl is-active  tailscaled 2>/dev/null || systemctl is-active  tailscale 2>/dev/null || echo '?')"
fi