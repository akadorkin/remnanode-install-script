#!/usr/bin/env bash
set -Eeuo pipefail

###############################################################################
# vps-edge-run.sh
#
# Runner that orchestrates small "assets" scripts (download + execute).
#
# NOTE: Provided "AS IS", without any warranties. Use at your own risk.
###############################################################################

###############################################################################
# Colors + logging
###############################################################################
LOG_TS="${EDGE_LOG_TS:-1}"
ts() { [[ "$LOG_TS" == "1" ]] && date +"%Y-%m-%d %H:%M:%S" || true; }
_is_tty() { [[ -t 1 ]]; }

c_reset=$'\033[0m'
c_dim=$'\033[2m'
c_bold=$'\033[1m'
c_red=$'\033[31m'
c_yel=$'\033[33m'
c_grn=$'\033[32m'
c_cyan=$'\033[36m'

color() { local code="$1"; shift; _is_tty && printf "%s%s%s" "$code" "$*" "$c_reset" || printf "%s" "$*"; }
_pfx() { _is_tty && printf "%s%s%s" "${c_dim}" "$(ts) " "${c_reset}" || true; }

ok()   { _pfx; color "$c_grn" "✅ OK";    printf " %s\n" "$*"; }
info() { _pfx; color "$c_cyan" "ℹ️ ";     printf " %s\n" "$*"; }
warn() { _pfx; color "$c_yel" "⚠️  WARN"; printf " %s\n" "$*"; }
err()  { _pfx; color "$c_red" "🛑 ERROR"; printf " %s\n" "$*"; }
die()  { err "$*"; exit 1; }

hdr() { echo; color "$c_bold$c_cyan" "$*"; echo; }

###############################################################################
# Root / sudo
###############################################################################
need_root() {
  if [[ "${EUID:-$(id -u)}" -eq 0 ]]; then return 0; fi
  die "Not root. Run like: curl ... | sudo bash -s -- apply [flags]"
}

###############################################################################
# Args
###############################################################################
CMD="${1:-}"; shift || true

ARG_USER=""

ARG_REBOOT="0"          # 0/none/skip = no reboot by default in this runner
ARG_TIMEZONE="Europe/Moscow"

ARG_APT_BOOTSTRAP="1"
ARG_DNS_SWITCHER="0"
ARG_DNS_PROFILE=""      # if empty -> interactive in upstream script

ARG_TAILSCALE="0"
ARG_REMNANODE="0"
ARG_SSH_HARDEN="0"
ARG_OPEN_WAN_443="0"
ARG_KERNEL_TUNE="1"
ARG_PRINT_SUMMARY="1"

# Optional: stop on kernel tune failure (default: continue if it "looks applied")
ARG_STRICT_KERNEL="0"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --user=*)         ARG_USER="${1#*=}"; shift ;;
    --reboot=*)       ARG_REBOOT="${1#*=}"; shift ;;
    --timezone=*)     ARG_TIMEZONE="${1#*=}"; shift ;;

    --apt-bootstrap=*)   ARG_APT_BOOTSTRAP="${1#*=}"; shift ;;
    --dns-switcher=*)    ARG_DNS_SWITCHER="${1#*=}"; shift ;;
    --dns-profile=*)     ARG_DNS_PROFILE="${1#*=}"; shift ;;
    --tailscale=*)       ARG_TAILSCALE="${1#*=}"; shift ;;
    --remnanode=*)       ARG_REMNANODE="${1#*=}"; shift ;;
    --ssh-harden=*)      ARG_SSH_HARDEN="${1#*=}"; shift ;;
    --open-wan-443=*)    ARG_OPEN_WAN_443="${1#*=}"; shift ;;
    --kernel-tune=*)     ARG_KERNEL_TUNE="${1#*=}"; shift ;;
    --print-summary=*)   ARG_PRINT_SUMMARY="${1#*=}"; shift ;;
    --strict-kernel=*)   ARG_STRICT_KERNEL="${1#*=}"; shift ;;

    --user)         ARG_USER="${2:-}"; shift 2 ;;
    --reboot)       ARG_REBOOT="${2:-}"; shift 2 ;;
    --timezone)     ARG_TIMEZONE="${2:-}"; shift 2 ;;
    --apt-bootstrap)   ARG_APT_BOOTSTRAP="${2:-}"; shift 2 ;;
    --dns-switcher)    ARG_DNS_SWITCHER="${2:-}"; shift 2 ;;
    --dns-profile)     ARG_DNS_PROFILE="${2:-}"; shift 2 ;;
    --tailscale)       ARG_TAILSCALE="${2:-}"; shift 2 ;;
    --remnanode)       ARG_REMNANODE="${2:-}"; shift 2 ;;
    --ssh-harden)      ARG_SSH_HARDEN="${2:-}"; shift 2 ;;
    --open-wan-443)    ARG_OPEN_WAN_443="${2:-}"; shift 2 ;;
    --kernel-tune)     ARG_KERNEL_TUNE="${2:-}"; shift 2 ;;
    --print-summary)   ARG_PRINT_SUMMARY="${2:-}"; shift 2 ;;
    --strict-kernel)   ARG_STRICT_KERNEL="${2:-}"; shift 2 ;;

    -h|--help|help)
      CMD="help"; shift ;;
    *)
      die "Unknown arg: $1"
      ;;
  esac
done

usage() {
  cat <<'EOF'
Usage:
  curl -fsSL https://raw.githubusercontent.com/akadorkin/remnanode-install-script/main/vps-edge-run.sh | sudo bash -s -- apply [flags]
  curl -fsSL https://raw.githubusercontent.com/akadorkin/remnanode-install-script/main/vps-edge-run.sh | sudo bash -s -- status

Flags:
  --user <name>            Create/ensure user + sudo NOPASSWD + docker group + copy SSH keys + /opt rw
  --timezone <TZ>          Default: Europe/Moscow
  --reboot 0|skip|none|5m  Default: 0 (no reboot)

  --dns-switcher 0|1       Run dns-switcher (interactive if --dns-profile not set)
  --dns-profile 1..5       Auto-answer choice (still auto "y")

  --tailscale 0|1
  --remnanode 0|1
  --ssh-harden 0|1
  --open-wan-443 0|1       Open WAN 443 tcp/udp; outgoing from WAN allowed all; tailscale allow all

  --kernel-tune 0|1        Run kernel tuning bootstrap (default 1)
  --strict-kernel 0|1      If 1: fail hard on kernel bootstrap non-zero exit

Examples:
  ... | sudo bash -s -- apply --user akadorkin --tailscale=1 --reboot=0 --dns-switcher=1 --dns-profile=1 --remnanode=1 --ssh-harden=1 --open-wan-443=1
EOF
}

###############################################################################
# Asset URLs (your repo)
###############################################################################
ASSETS_BASE="https://raw.githubusercontent.com/akadorkin/remnanode-install-script/refs/heads/main/assests"

URL_APT="${URL_APT:-$ASSETS_BASE/apt-bootstrap.sh}"
URL_DNS="${URL_DNS:-$ASSETS_BASE/dns-bootstrap.sh}"
URL_KERNEL="${URL_KERNEL:-$ASSETS_BASE/kernel-bootstrap.sh}"
URL_PRINT_SUMMARY="${URL_PRINT_SUMMARY:-$ASSETS_BASE/print-summary.sh}"
URL_REMNANODE="${URL_REMNANODE:-$ASSETS_BASE/remnanode-bootstrap.sh}"
URL_SSH="${URL_SSH:-$ASSETS_BASE/ssh-bootstrap.sh}"
URL_TAILSCALE="${URL_TAILSCALE:-$ASSETS_BASE/tailscale-bootstrap.sh}"
URL_UFW="${URL_UFW:-$ASSETS_BASE/ufw-bootstrap.sh}"
URL_USER="${URL_USER:-$ASSETS_BASE/user-setup.sh}"
URL_ZSH="${URL_ZSH:-$ASSETS_BASE/zsh-bootstrap.sh}"

###############################################################################
# Logs
###############################################################################
LOG_DIR="/var/log"
LOG_APT="${LOG_DIR}/vps-edge-apt.log"
LOG_DNS="${LOG_DIR}/vps-edge-dns-switcher.log"
LOG_TS="${LOG_DIR}/vps-edge-tailscale.log"
LOG_UFW="${LOG_DIR}/vps-edge-ufw.log"
LOG_USER="${LOG_DIR}/vps-edge-user.log"
LOG_ZSH="${LOG_DIR}/vps-edge-zsh.log"
LOG_REMNANODE="${LOG_DIR}/vps-edge-remnanode.log"
LOG_SSH="${LOG_DIR}/vps-edge-ssh.log"
LOG_KERNEL="${LOG_DIR}/vps-edge-tuning.log"
LOG_SUMMARY="${LOG_DIR}/vps-edge-summary.log"
LOG_ERR="${LOG_DIR}/vps-edge-error.log"

touch "$LOG_APT" "$LOG_DNS" "$LOG_TS" "$LOG_UFW" "$LOG_USER" "$LOG_ZSH" "$LOG_REMNANODE" "$LOG_SSH" "$LOG_KERNEL" "$LOG_SUMMARY" "$LOG_ERR" 2>/dev/null || true

###############################################################################
# Helpers
###############################################################################
host_short() { hostname -s 2>/dev/null || hostname; }

ext_ip() {
  curl -fsSL --max-time 4 https://api.ipify.org 2>/dev/null \
    || curl -fsSL --max-time 4 ifconfig.me 2>/dev/null \
    || true
}

country_flag() {
  local cc="${1:-}"
  cc="${cc^^}"
  if [[ ! "$cc" =~ ^[A-Z]{2}$ ]]; then printf "🏳️"; return 0; fi
  awk -v cc="$cc" 'BEGIN{
    o1 = index("ABCDEFGHIJKLMNOPQRSTUVWXYZ", substr(cc,1,1)) - 1
    o2 = index("ABCDEFGHIJKLMNOPQRSTUVWXYZ", substr(cc,2,1)) - 1
    printf "%c%c", 0x1F1E6 + o1, 0x1F1E6 + o2
  }'
}

geo_lookup() {
  # outputs: CC|COUNTRY|REGION|CITY|ORG
  if command -v jq >/dev/null 2>&1; then
    local ip="${1:-}" out
    out="$(curl -fsSL --max-time 4 "https://ipinfo.io/${ip}/json" 2>/dev/null || true)"
    if [[ -n "$out" ]]; then
      local cc region city org country
      cc="$(printf "%s" "$out" | jq -r '.country // empty' 2>/dev/null || true)"
      region="$(printf "%s" "$out" | jq -r '.region // empty' 2>/dev/null || true)"
      city="$(printf "%s" "$out" | jq -r '.city // empty' 2>/dev/null || true)"
      org="$(printf "%s" "$out" | jq -r '.org // empty' 2>/dev/null || true)"
      country="$cc"
      if [[ -n "$cc" || -n "$city" || -n "$org" ]]; then
        printf "%s|%s|%s|%s|%s" "${cc:-}" "${country:-}" "${region:-}" "${city:-}" "${org:-}"
        return 0
      fi
    fi
  fi
  printf "||||"
}

tailscale_ip4() { command -v tailscale >/dev/null 2>&1 && tailscale ip -4 2>/dev/null | head -n1 || true; }
tailscale_magicdns() {
  command -v tailscale >/dev/null 2>&1 || return 0
  if command -v jq >/dev/null 2>&1 && tailscale status --json >/dev/null 2>&1; then
    tailscale status --json 2>/dev/null | jq -r '.Self.DNSName // empty' 2>/dev/null | sed 's/\.$//' || true
  else
    tailscale status 2>/dev/null | awk 'NR==1{print $2}' | sed 's/\.$//' || true
  fi
}

wan_iface_detect() {
  ip route get 8.8.8.8 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="dev") print $(i+1)}' | head -n1 \
    || ip route show default 2>/dev/null | awk '/default/ {print $5; exit}' \
    || true
}

download_asset() {
  local name="$1" url="$2" out="$3"
  mkdir -p "$(dirname "$out")"
  if curl -fsSL "$url" -o "$out" >>"$LOG_ERR" 2>&1; then
    chmod +x "$out" >>"$LOG_ERR" 2>&1 || true
    return 0
  fi
  return 1
}

run_asset() {
  local name="$1" url="$2" log_file="$3"; shift 3
  local tmp="/tmp/vps-edge-assets/${name}.sh"
  mkdir -p /tmp/vps-edge-assets
  : >"$log_file" || true

  info "Running asset: ${name}"
  if ! download_asset "$name" "$url" "$tmp"; then
    warn "Failed to download ${name}: ${url}"
    return 1
  fi

  # First try: pass args
  set +e
  bash "$tmp" "$@" >>"$log_file" 2>&1
  local rc=$?
  set -e

  # Fallback: if it likely doesn't accept args, try no-args (only if args were provided)
  if [[ $rc -ne 0 && $# -gt 0 ]]; then
    set +e
    bash "$tmp" >>"$log_file" 2>&1
    local rc2=$?
    set -e
    [[ $rc2 -eq 0 ]] && rc=0
  fi

  if [[ $rc -eq 0 ]]; then
    ok "${name} finished"
  else
    warn "${name} exited with code=${rc} (see ${log_file})"
  fi
  return "$rc"
}

print_start_banner() {
  local ip gl cc country region city org flag
  ip="$(ext_ip)"; [[ -n "$ip" ]] || ip="?"
  gl="$(geo_lookup "$ip")"
  cc="${gl%%|*}"
  country="$(echo "$gl" | cut -d'|' -f2)"
  region="$(echo "$gl" | cut -d'|' -f3)"
  city="$(echo "$gl" | cut -d'|' -f4)"
  org="$(echo "$gl" | cut -d'|' -f5)"
  flag="$(country_flag "$cc")"
  WAN_IP="$ip"
  GEO_CC="$cc"
  GEO_COUNTRY="$country"
  GEO_REGION="$region"
  GEO_CITY="$city"
  GEO_PROVIDER="$org"
  GEO_FLAG="$flag"

  hdr "🏁 Start"
  echo "  ${GEO_FLAG:-🏳️} ${WAN_IP:-?} — ${GEO_CITY:-?}, ${GEO_REGION:-?}, ${GEO_CC:-?} — ${GEO_PROVIDER:-?}"
}

maybe_reboot() {
  local r="${ARG_REBOOT:-0}"
  case "$r" in
    0|no|none|skip|"")
      warn "Reboot disabled (--reboot=${r})"
      ;;
    30s|30sec|30)
      warn "Reboot in 30 seconds"
      shutdown -r +0.5 >/dev/null 2>&1 || shutdown -r now
      ;;
    5m|5min|300)
      warn "Reboot in 5 minutes"
      shutdown -r +5 >/dev/null 2>&1 || shutdown -r now
      ;;
    *)
      warn "Reboot in ${r}"
      shutdown -r +"${r}" >/dev/null 2>&1 || shutdown -r now
      ;;
  esac
}

###############################################################################
# Apply / Status
###############################################################################
apply_cmd() {
  need_root

  export EDGE_USER="${ARG_USER}"
  export EDGE_TIMEZONE="${ARG_TIMEZONE}"
  export EDGE_DNS_PROFILE="${ARG_DNS_PROFILE}"
  export EDGE_OPEN_WAN_443="${ARG_OPEN_WAN_443}"

  print_start_banner

  # 1) APT baseline (no docker here — as you requested)
  if [[ "${ARG_APT_BOOTSTRAP}" == "1" ]]; then
    hdr "📦 Packages"
    run_asset "apt-bootstrap" "$URL_APT" "$LOG_APT" || true
  fi

  # 2) DNS switcher
  if [[ "${ARG_DNS_SWITCHER}" == "1" ]]; then
    hdr "🌐 DNS switcher (early)"
    # Expectation: dns-bootstrap.sh handles:
    # - download upstream dns-switcher
    # - auto "y"
    # - if EDGE_DNS_PROFILE empty -> interactive
    run_asset "dns-bootstrap" "$URL_DNS" "$LOG_DNS" || true
    ok "dns-switcher applied (see ${LOG_DNS})"
  fi

  # 3) Tailscale
  if [[ "${ARG_TAILSCALE}" == "1" ]]; then
    hdr "🧠 Tailscale (early)"
    run_asset "tailscale-bootstrap" "$URL_TAILSCALE" "$LOG_TS" || true
    local tsip tsdns
    tsip="$(tailscale_ip4)"
    tsdns="$(tailscale_magicdns)"
    [[ -n "$tsip" ]] && ok "tailscale ip: $tsip" || warn "tailscale ip not detected"
    [[ -n "$tsdns" ]] && ok "MagicDNS: $tsdns" || true
  fi

  # 4) User setup (password generation + sudo nopasswd + docker group + copy ssh keys + /opt rw)
  if [[ -n "${ARG_USER:-}" ]]; then
    hdr "👤 User setup"
    run_asset "user-setup" "$URL_USER" "$LOG_USER" || true
    ok "user-setup done (see ${LOG_USER})"
  fi

  # 5) Zsh
  hdr "💅 Zsh"
  run_asset "zsh-bootstrap" "$URL_ZSH" "$LOG_ZSH" || true

  # 6) Kernel tune (external)
  if [[ "${ARG_KERNEL_TUNE}" == "1" ]]; then
    hdr "🧠 Kernel + system tuning"
    set +e
    run_asset "kernel-bootstrap" "$URL_KERNEL" "$LOG_KERNEL"
    local rc=$?
    set -e

    # If the tuning script returns non-zero but log contains "OK Applied." – treat as applied-ish
    if [[ $rc -ne 0 ]]; then
      if grep -qE 'OK Applied\.' "$LOG_KERNEL" 2>/dev/null; then
        warn "kernel bootstrap returned non-zero, but log says OK Applied. Continuing."
      else
        if [[ "${ARG_STRICT_KERNEL}" == "1" ]]; then
          err "kernel bootstrap failed (strict mode). See: $LOG_KERNEL"
          exit 1
        fi
        warn "kernel bootstrap failed; continuing (see $LOG_KERNEL)"
      fi
    else
      ok "kernel bootstrap applied (see $LOG_KERNEL)"
    fi

    # Print the nice block to terminal (like you wanted)
    echo
    sed -n '1,220p' "$LOG_KERNEL" 2>/dev/null || true
  fi

  # 7) UFW (WAN 443 tcp/udp, outgoing all; tailscale allow all)
  if [[ "${ARG_OPEN_WAN_443}" == "1" || "${ARG_TAILSCALE}" == "1" ]]; then
    hdr "🧱 Firewall (UFW)"
    export EDGE_WAN_IFACE="${EDGE_WAN_IFACE:-$(wan_iface_detect)}"
    run_asset "ufw-bootstrap" "$URL_UFW" "$LOG_UFW" || true
    ok "ufw-bootstrap done (see ${LOG_UFW})"
  fi

  # 8) remnanode
  if [[ "${ARG_REMNANODE}" == "1" ]]; then
    hdr "🧩 remnanode"
    run_asset "remnanode-bootstrap" "$URL_REMNANODE" "$LOG_REMNANODE" || true
    ok "remnanode-bootstrap done (see ${LOG_REMNANODE})"
  fi

  # 9) SSH hardening + fail2ban + recidive
  if [[ "${ARG_SSH_HARDEN}" == "1" ]]; then
    hdr "🔐 SSH hardening + fail2ban"
    run_asset "ssh-bootstrap" "$URL_SSH" "$LOG_SSH" || true
    ok "ssh-bootstrap done (see ${LOG_SSH})"
  fi

  # 10) Print final summary (your “огнище” block)
  if [[ "${ARG_PRINT_SUMMARY}" == "1" ]]; then
    hdr "🧾 Summary"
    export EDGE_SUMMARY_HOST="$(host_short)"
    export EDGE_SUMMARY_WAN_IP="${WAN_IP:-}"
    export EDGE_SUMMARY_GEO_CITY="${GEO_CITY:-}"
    export EDGE_SUMMARY_GEO_REGION="${GEO_REGION:-}"
    export EDGE_SUMMARY_GEO_CC="${GEO_CC:-}"
    export EDGE_SUMMARY_GEO_FLAG="${GEO_FLAG:-}"
    export EDGE_SUMMARY_PROVIDER="${GEO_PROVIDER:-}"
    export EDGE_SUMMARY_TAILSCALE_IP="$(tailscale_ip4 || true)"
    export EDGE_SUMMARY_MAGICDNS="$(tailscale_magicdns || true)"
    export EDGE_SUMMARY_USER="${ARG_USER:-}"
    export EDGE_LOG_APT="$LOG_APT"
    export EDGE_LOG_DNS="$LOG_DNS"
    export EDGE_LOG_TAILSCALE="$LOG_TS"
    export EDGE_LOG_UFW="$LOG_UFW"
    export EDGE_LOG_USER="$LOG_USER"
    export EDGE_LOG_ZSH="$LOG_ZSH"
    export EDGE_LOG_REMNANODE="$LOG_REMNANODE"
    export EDGE_LOG_SSH="$LOG_SSH"
    export EDGE_LOG_KERNEL="$LOG_KERNEL"
    export EDGE_LOG_ERR="$LOG_ERR"

    run_asset "print-summary" "$URL_PRINT_SUMMARY" "$LOG_SUMMARY" || true
    cat "$LOG_SUMMARY" 2>/dev/null || true
  fi

  maybe_reboot
}

status_cmd() {
  need_root
  hdr "📊 Status"
  row() { printf "%-14s | %s\n" "$1" "${2:-}"; }

  row "Host"        "$(host_short)"
  row "WAN iface"   "$(wan_iface_detect)"
  row "WAN IP"      "$(ext_ip || true)"
  if command -v tailscale >/dev/null 2>&1; then
    row "Tailscale IP" "$(tailscale_ip4 || true)"
    row "MagicDNS"     "$(tailscale_magicdns || true)"
  fi
  if command -v ufw >/dev/null 2>&1; then
    row "UFW" "$(ufw status 2>/dev/null | head -n1 || true)"
  fi
  if command -v docker >/dev/null 2>&1; then
    row "Docker" "$(docker --version 2>/dev/null || true)"
    row "remnanode" "$(docker ps --format '{{.Names}} {{.Status}}' 2>/dev/null | awk '$1=="remnanode"{ $1=""; sub(/^ /,""); print "Up " $0 }' | head -n1 || echo "-")"
  fi
  echo
  echo "Logs:"
  echo "  - APT:       $LOG_APT"
  echo "  - DNS:       $LOG_DNS"
  echo "  - Tailscale: $LOG_TS"
  echo "  - UFW:       $LOG_UFW"
  echo "  - User:      $LOG_USER"
  echo "  - Zsh:       $LOG_ZSH"
  echo "  - Remnanode: $LOG_REMNANODE"
  echo "  - SSH:       $LOG_SSH"
  echo "  - Kernel:    $LOG_KERNEL"
  echo "  - Summary:   $LOG_SUMMARY"
  echo "  - Error:     $LOG_ERR"
}

###############################################################################
# Main
###############################################################################
case "$CMD" in
  apply)   apply_cmd ;;
  status)  status_cmd ;;
  ""|help|-h|--help) usage; exit 0 ;;
  *)
    usage
    exit 1
    ;;
esac
