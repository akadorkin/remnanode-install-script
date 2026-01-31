#!/usr/bin/env bash
set -euo pipefail

# -----------------------------------------------------------------------------
# assets/ufw-setup.sh
#
# Purpose:
#   - Detect WAN interface automatically
#   - UFW reset
#   - Default: deny incoming / allow outgoing (WAN outgoing = ALL)
#   - WAN: allow ONLY 443/tcp + 443/udp inbound
#   - tailscale0: allow ALL in/out
#   - Docker bridges: allow ALL in/out (best-effort)
#   - Ensure forwarding works (DEFAULT_FORWARD_POLICY=ACCEPT)
#   - Enable UFW now + on reboot
#
# NOTE: Provided "AS IS", without any warranties. Use at your own risk.
# -----------------------------------------------------------------------------

LOG_FILE="${LOG_FILE:-/var/log/edge-ufw-setup.log}"
OPEN_WAN_443="${OPEN_WAN_443:-1}"                 # 1/0
ALLOW_DOCKER_BRIDGES="${ALLOW_DOCKER_BRIDGES:-1}" # 1/0
TAILSCALE_IFACE="${TAILSCALE_IFACE:-tailscale0}"

ts()  { date '+%F %T'; }
log() { echo "$(ts) $*" | tee -a "$LOG_FILE"; }
die() { log "ERROR: $*"; exit 1; }

require_root() {
  [[ ${EUID:-$(id -u)} -eq 0 ]] || die "Run as root"
}

detect_wan_iface() {
  # Most reliable first
  ip route get 8.8.8.8 2>/dev/null \
    | awk '{for(i=1;i<=NF;i++) if($i=="dev"){print $(i+1); exit}}' \
    | head -n1 || true
}

detect_wan_iface_fallback() {
  ip route show default 2>/dev/null | awk '/default/ {print $5; exit}' || true
}

ensure_ufw() {
  if command -v ufw >/dev/null 2>&1; then
    return 0
  fi
  log "Installing ufw"
  export DEBIAN_FRONTEND=noninteractive
  apt-get -y -qq update >>"$LOG_FILE" 2>&1 || true
  apt-get -y -qq install ufw >>"$LOG_FILE" 2>&1 || die "ufw install failed"
}

set_forward_policy() {
  if [[ -f /etc/default/ufw ]]; then
    if grep -q '^DEFAULT_FORWARD_POLICY=' /etc/default/ufw; then
      sed -i 's/^DEFAULT_FORWARD_POLICY=.*/DEFAULT_FORWARD_POLICY="ACCEPT"/' /etc/default/ufw
    else
      echo 'DEFAULT_FORWARD_POLICY="ACCEPT"' >> /etc/default/ufw
    fi
  fi
}

allow_wan_rules() {
  local wan="$1"

  log "WAN interface: ${wan}"

  # Explicitly allow ALL outbound on WAN
  log "Allow ALL outbound traffic on WAN (${wan})"
  ufw allow out on "${wan}" >/dev/null 2>&1 || true

  # Restrict inbound to 443 only
  if [[ "${OPEN_WAN_443}" == "1" ]]; then
    log "Allow inbound 443/tcp + 443/udp on WAN (${wan})"
    ufw allow in on "${wan}" to any port 443 proto tcp >/dev/null 2>&1 || true
    ufw allow in on "${wan}" to any port 443 proto udp >/dev/null 2>&1 || true
  else
    log "Inbound WAN ports disabled (OPEN_WAN_443=0)"
  fi
}

allow_tailscale() {
  log "Allow ALL in/out on ${TAILSCALE_IFACE}"
  ufw allow in  on "${TAILSCALE_IFACE}" >/dev/null 2>&1 || true
  ufw allow out on "${TAILSCALE_IFACE}" >/dev/null 2>&1 || true
}

allow_docker_bridges() {
  [[ "${ALLOW_DOCKER_BRIDGES}" == "1" ]] || return 0

  local ifaces
  ifaces="$(ip -o link show 2>/dev/null | awk -F': ' '$2 ~ /^(docker0|br-)/ {print $2}' || true)"

  if [[ -z "$ifaces" ]]; then
    log "No Docker bridges found"
    return 0
  fi

  log "Allow ALL in/out on Docker bridges: ${ifaces}"
  local ifc
  for ifc in $ifaces; do
    ufw allow in  on "$ifc" >/dev/null 2>&1 || true
    ufw allow out on "$ifc" >/dev/null 2>&1 || true
  done
}

enable_on_boot() {
  cat >/etc/cron.d/enable-ufw <<'EOF'
@reboot root ufw --force enable && ufw reload
EOF
}

main() {
  require_root
  : >"$LOG_FILE"

  log "UFW setup start"

  ensure_ufw
  set_forward_policy

  local wan=""
  wan="$(detect_wan_iface)"
  [[ -n "$wan" ]] || wan="$(detect_wan_iface_fallback)"
  [[ -n "$wan" ]] || die "Failed to detect WAN interface"

  log "Detected WAN interface: ${wan}"

  log "Resetting UFW"
  ufw --force reset >/dev/null 2>&1 || true
  ufw default deny incoming  >/dev/null 2>&1 || true
  ufw default allow outgoing >/dev/null 2>&1 || true

  allow_wan_rules "$wan"
  allow_tailscale
  allow_docker_bridges

  enable_on_boot

  log "Enabling UFW"
  ufw --force enable >/dev/null 2>&1 || true

  echo
  echo "================ UFW SUMMARY ================"
  echo "WAN iface:     ${wan}"
  echo "WAN inbound:   $([[ "${OPEN_WAN_443}" == "1" ]] && echo "443/tcp + 443/udp only" || echo "DENY ALL")"
  echo "WAN outbound:  ALLOW ALL"
  echo "Tailscale:     ${TAILSCALE_IFACE} allow all in/out"
  echo "Docker br:     $([[ "${ALLOW_DOCKER_BRIDGES}" == "1" ]] && echo "allow all (if present)" || echo "skip")"
  echo
  ufw status verbose || true
  echo
  echo "Log: ${LOG_FILE}"
  echo "============================================"
  echo

  log "Done."
}

main "$@"
