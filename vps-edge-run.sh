#!/usr/bin/env bash
set -Eeuo pipefail

###############################################################################
# vps-edge-run.sh (assets-based orchestrator)
#
# Usage:
#   curl -fsSL https://raw.githubusercontent.com/akadorkin/remnanode-install-script/main/vps-edge-run.sh | sudo bash -s -- apply [flags]
#
# Flags (apply):
#   --user <name>            or --user=<name>
#   --timezone <TZ>          or --timezone=<TZ>   (default: Europe/Moscow)
#   --reboot 0|skip|none     or --reboot=<...>    (default: 0 = no reboot)
#
#   --dns-switcher 0|1       (default: 0)
#   --dns-profile 1..5       (default: 1)
#
#   --tailscale 0|1          (default: 0)
#   --remnanode 0|1          (default: 0)
#   --ssh-harden 0|1         (default: 0)
#   --open-wan-443 0|1       (default: 0)
#
# Notes:
# - All heavy logic lives in assets/*.sh scripts.
# - Kernel tuning upstream may exit with code=1 even after successful apply.
#   We treat success by log signature: "OK Applied. Backup:".
###############################################################################

# -------------------- Colors / logging --------------------
_is_tty() { [[ -t 1 ]]; }
c_reset=$'\033[0m'
c_dim=$'\033[2m'
c_bold=$'\033[1m'
c_red=$'\033[31m'
c_yel=$'\033[33m'
c_grn=$'\033[32m'
c_cyan=$'\033[36m'

ts() { date +"%Y-%m-%d %H:%M:%S"; }

color() { local code="$1"; shift; _is_tty && printf "%s%s%s" "$code" "$*" "$c_reset" || printf "%s" "$*"; }
_pfx() { _is_tty && printf "%s%s%s" "${c_dim}" "$(ts) " "${c_reset}" || printf "%s " "$(ts)"; }

ok()   { _pfx; color "$c_grn" "✅ OK";    printf " %s\n" "$*"; }
info() { _pfx; color "$c_cyan" "ℹ️ ";     printf " %s\n" "$*"; }
warn() { _pfx; color "$c_yel" "⚠️  WARN"; printf " %s\n" "$*"; }
err()  { _pfx; color "$c_red" "🛑 ERROR"; printf " %s\n" "$*"; }
die()  { err "$*"; exit 1; }

hdr() { echo; color "$c_bold$c_cyan" "$*"; echo; }

need_root() {
  [[ "${EUID:-$(id -u)}" -eq 0 ]] || die "Run as root (use sudo)."
}

host_short() { hostname -s 2>/dev/null || hostname; }

# -------------------- Default logs --------------------
LOG_DIR="/var/log"
LOG_APT="${LOG_DIR}/vps-edge-apt.log"
LOG_DNS="${LOG_DIR}/vps-edge-dns-switcher.log"
LOG_TS="${LOG_DIR}/vps-edge-tailscale.log"
LOG_USER="${LOG_DIR}/vps-edge-user.log"
LOG_ZSH="${LOG_DIR}/vps-edge-zsh.log"
LOG_TUNE="${LOG_DIR}/vps-edge-tuning.log"
LOG_UFW="${LOG_DIR}/vps-edge-ufw.log"
LOG_REMNA="${LOG_DIR}/vps-edge-remnanode.log"
LOG_SSH="${LOG_DIR}/vps-edge-ssh.log"
LOG_SUMMARY="${LOG_DIR}/vps-edge-summary.log"
LOG_ERR="${LOG_DIR}/vps-edge-error.log"

mkdir -p "$LOG_DIR" >/dev/null 2>&1 || true
touch "$LOG_APT" "$LOG_DNS" "$LOG_TS" "$LOG_USER" "$LOG_ZSH" "$LOG_TUNE" "$LOG_UFW" "$LOG_REMNA" "$LOG_SSH" "$LOG_SUMMARY" "$LOG_ERR" 2>/dev/null || true

# -------------------- Asset URLs (your repo) --------------------
URL_APT="${URL_APT:-https://raw.githubusercontent.com/akadorkin/remnanode-install-script/refs/heads/main/assests/apt-bootstrap.sh}"
URL_DNS="${URL_DNS:-https://raw.githubusercontent.com/akadorkin/remnanode-install-script/refs/heads/main/assests/dns-bootstrap.sh}"
URL_KERNEL="${URL_KERNEL:-https://raw.githubusercontent.com/akadorkin/remnanode-install-script/refs/heads/main/assests/kernel-bootstrap.sh}"
URL_PRINT_SUMMARY="${URL_PRINT_SUMMARY:-https://raw.githubusercontent.com/akadorkin/remnanode-install-script/refs/heads/main/assests/print-summary.sh}"
URL_REMNANODE="${URL_REMNANODE:-https://raw.githubusercontent.com/akadorkin/remnanode-install-script/refs/heads/main/assests/remnanode-bootstrap.sh}"
URL_SSH="${URL_SSH:-https://raw.githubusercontent.com/akadorkin/remnanode-install-script/refs/heads/main/assests/ssh-bootstrap.sh}"
URL_TS="${URL_TS:-https://raw.githubusercontent.com/akadorkin/remnanode-install-script/refs/heads/main/assests/tailscale-bootstrap.sh}"
URL_UFW="${URL_UFW:-https://raw.githubusercontent.com/akadorkin/remnanode-install-script/refs/heads/main/assests/ufw-bootstrap.sh}"
URL_USER="${URL_USER:-https://raw.githubusercontent.com/akadorkin/remnanode-install-script/refs/heads/main/assests/user-setup.sh}"
URL_ZSH="${URL_ZSH:-https://raw.githubusercontent.com/akadorkin/remnanode-install-script/refs/heads/main/assests/zsh-bootstrap.sh}"

# -------------------- Runtime helpers --------------------
ext_ip() {
  curl -fsSL --max-time 3 https://api.ipify.org 2>/dev/null \
    || curl -fsSL --max-time 3 ifconfig.me 2>/dev/null \
    || true
}

geo_lookup() {
  # prints: CC|COUNTRY|REGION|CITY|ORG  (best-effort)
  command -v jq >/dev/null 2>&1 || { echo "||||"; return 0; }
  local ip="${1:-}"
  local out=""
  out="$(curl -fsSL --max-time 3 "https://ipinfo.io/${ip}/json" 2>/dev/null || true)"
  if [[ -n "$out" ]]; then
    local cc region city org
    cc="$(printf "%s" "$out" | jq -r '.country // empty' 2>/dev/null || true)"
    region="$(printf "%s" "$out" | jq -r '.region // empty' 2>/dev/null || true)"
    city="$(printf "%s" "$out" | jq -r '.city // empty' 2>/dev/null || true)"
    org="$(printf "%s" "$out" | jq -r '.org // empty' 2>/dev/null || true)"
    printf "%s|%s|%s|%s|%s" "${cc:-}" "${cc:-}" "${region:-}" "${city:-}" "${org:-}"
    return 0
  fi
  echo "||||"
}

country_flag() {
  local cc="${1:-}"
  cc="${cc^^}"
  if [[ ! "$cc" =~ ^[A-Z]{2}$ ]]; then
    printf "🏳️"
    return 0
  fi
  awk -v cc="$cc" 'BEGIN{
    o1 = ord(substr(cc,1,1))
    o2 = ord(substr(cc,2,1))
    cp1 = 0x1F1E6 + o1 - 65
    cp2 = 0x1F1E6 + o2 - 65
    printf "%c%c", cp1, cp2
  }
  function ord(c){ return index("ABCDEFGHIJKLMNOPQRSTUVWXYZ", c)+64 }'
}

run_asset() {
  # run_asset <name> <url> <logfile>
  local name="$1" url="$2" logfile="$3"
  local tmp="/tmp/${name}.sh"

  info "Running asset: ${name}"
  {
    echo "----- $(ts) asset=${name} url=${url} -----"
  } >>"$logfile" 2>/dev/null || true

  if ! curl -fsSL "$url" -o "$tmp" >>"$logfile" 2>&1; then
    warn "${name}: download failed (${url})"
    return 2
  fi
  chmod +x "$tmp" >>"$logfile" 2>&1 || true

  # Run asset (inherit env); keep stdout in terminal + in log
  set +e
  bash "$tmp" 2>&1 | tee -a "$logfile"
  local rc=${PIPESTATUS[0]}
  set -e

  return "$rc"
}

tailscale_ip4() {
  command -v tailscale >/dev/null 2>&1 || return 0
  tailscale ip -4 2>/dev/null | head -n1 || true
}
tailscale_magicdns() {
  command -v tailscale >/dev/null 2>&1 || return 0
  if command -v jq >/dev/null 2>&1 && tailscale status --json >/dev/null 2>&1; then
    tailscale status --json 2>/dev/null | jq -r '.Self.DNSName // empty' 2>/dev/null | sed 's/\.$//' || true
  else
    tailscale status 2>/dev/null | awk 'NR==1{print $2}' | sed 's/\.$//' || true
  fi
}

# -------------------- Args / defaults --------------------
CMD="${1:-}"; shift || true

ARG_USER=""
ARG_TIMEZONE="Europe/Moscow"
ARG_REBOOT="0"

ARG_DNS_SWITCHER="0"
ARG_DNS_PROFILE="1"

ARG_TAILSCALE="0"
ARG_REMNANODE="0"
ARG_SSH_HARDEN="0"
ARG_OPEN_WAN_443="0"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --user=*)          ARG_USER="${1#*=}"; shift ;;
    --timezone=*)      ARG_TIMEZONE="${1#*=}"; shift ;;
    --reboot=*)        ARG_REBOOT="${1#*=}"; shift ;;

    --dns-switcher=*)  ARG_DNS_SWITCHER="${1#*=}"; shift ;;
    --dns-profile=*)   ARG_DNS_PROFILE="${1#*=}"; shift ;;

    --tailscale=*)     ARG_TAILSCALE="${1#*=}"; shift ;;
    --remnanode=*)     ARG_REMNANODE="${1#*=}"; shift ;;
    --ssh-harden=*)    ARG_SSH_HARDEN="${1#*=}"; shift ;;
    --open-wan-443=*)  ARG_OPEN_WAN_443="${1#*=}"; shift ;;

    --user)          ARG_USER="${2:-}"; shift 2 ;;
    --timezone)      ARG_TIMEZONE="${2:-}"; shift 2 ;;
    --reboot)        ARG_REBOOT="${2:-}"; shift 2 ;;

    --dns-switcher)  ARG_DNS_SWITCHER="${2:-}"; shift 2 ;;
    --dns-profile)   ARG_DNS_PROFILE="${2:-}"; shift 2 ;;

    --tailscale)     ARG_TAILSCALE="${2:-}"; shift 2 ;;
    --remnanode)     ARG_REMNANODE="${2:-}"; shift 2 ;;
    --ssh-harden)    ARG_SSH_HARDEN="${2:-}"; shift 2 ;;
    --open-wan-443)  ARG_OPEN_WAN_443="${2:-}"; shift 2 ;;
    *)
      die "Unknown arg: $1"
      ;;
  esac
done

usage() {
  cat <<'EOF'
Usage:
  apply:
    curl -fsSL https://raw.githubusercontent.com/akadorkin/remnanode-install-script/main/vps-edge-run.sh | sudo bash -s -- apply [flags]

  status:
    curl -fsSL https://raw.githubusercontent.com/akadorkin/remnanode-install-script/main/vps-edge-run.sh | sudo bash -s -- status

Flags:
  --user <name>
  --timezone <TZ>                (default: Europe/Moscow)
  --reboot 0|skip|none|30s|5m     (default: 0)

  --dns-switcher 0|1             (default: 0)
  --dns-profile 1..5             (default: 1)

  --tailscale 0|1                (default: 0)
  --remnanode 0|1                (default: 0)
  --ssh-harden 0|1               (default: 0)
  --open-wan-443 0|1             (default: 0)
EOF
}

# -------------------- Summary runner (always best-effort) --------------------
SUMMARY_RAN="0"
run_summary_best_effort() {
  [[ "$SUMMARY_RAN" == "1" ]] && return 0
  SUMMARY_RAN="1"

  # Export logs + key facts for summary asset
  export EDGE_LOG_APT="$LOG_APT"
  export EDGE_LOG_DNS="$LOG_DNS"
  export EDGE_LOG_TS="$LOG_TS"
  export EDGE_LOG_USER="$LOG_USER"
  export EDGE_LOG_ZSH="$LOG_ZSH"
  export EDGE_LOG_TUNE="$LOG_TUNE"
  export EDGE_LOG_UFW="$LOG_UFW"
  export EDGE_LOG_REMNANODE="$LOG_REMNA"
  export EDGE_LOG_SSH="$LOG_SSH"
  export EDGE_LOG_SUMMARY="$LOG_SUMMARY"
  export EDGE_LOG_ERR="$LOG_ERR"

  export EDGE_USER="${ARG_USER}"
  export EDGE_TIMEZONE="${ARG_TIMEZONE}"
  export EDGE_DNS_SWITCHER="${ARG_DNS_SWITCHER}"
  export EDGE_DNS_PROFILE="${ARG_DNS_PROFILE}"
  export EDGE_TAILSCALE="${ARG_TAILSCALE}"
  export EDGE_REMNANODE="${ARG_REMNANODE}"
  export EDGE_SSH_HARDEN="${ARG_SSH_HARDEN}"
  export EDGE_OPEN_WAN_443="${ARG_OPEN_WAN_443}"

  export EDGE_WAN_IP="${WAN_IP:-}"
  export EDGE_GEO_CC="${GEO_CC:-}"
  export EDGE_GEO_CITY="${GEO_CITY:-}"
  export EDGE_GEO_REGION="${GEO_REGION:-}"
  export EDGE_GEO_PROVIDER="${GEO_PROVIDER:-}"
  export EDGE_GEO_FLAG="${GEO_FLAG:-}"

  # Kernel backup dir (if detected)
  export EDGE_KERNEL_BACKUP_DIR="${KERNEL_BACKUP_DIR:-}"

  # Tailscale facts
  export EDGE_TS_IP="$(tailscale_ip4 || true)"
  export EDGE_TS_NAME="$(tailscale_magicdns || true)"

  # Run summary asset
  hdr "🧾 Summary"
  set +e
  run_asset "print-summary" "$URL_PRINT_SUMMARY" "$LOG_SUMMARY"
  local rc=$?
  set -e
  if [[ $rc -eq 0 ]]; then
    ok "summary printed"
  else
    warn "summary asset exited with code=$rc (see $LOG_SUMMARY)"
  fi
}

on_exit_apply() {
  # Always try to print summary at the end of apply (even on early failure)
  local code=$?
  if [[ "${CMD}" == "apply" ]]; then
    run_summary_best_effort || true
  fi
  exit "$code"
}

# -------------------- Apply flow --------------------
print_start_banner() {
  hdr "🏁 Start"
  local ip gl cc region city org flag
  ip="$(ext_ip)"
  [[ -n "$ip" ]] || ip="?"
  gl="$(geo_lookup "$ip")"
  cc="${gl%%|*}"
  region="$(echo "$gl" | cut -d'|' -f3)"
  city="$(echo "$gl" | cut -d'|' -f4)"
  org="$(echo "$gl" | cut -d'|' -f5)"
  flag="$(country_flag "$cc")"

  echo "  ${flag} ${ip} — ${city:-?}, ${region:-?}, ${cc:-?} — ${org:-?}"

  WAN_IP="$ip"
  GEO_CC="$cc"
  GEO_CITY="$city"
  GEO_REGION="$region"
  GEO_PROVIDER="$org"
  GEO_FLAG="$flag"
}

timezone_apply() {
  hdr "🕒 Timezone"
  if [[ -n "${ARG_TIMEZONE:-}" ]]; then
    ln -sf "/usr/share/zoneinfo/${ARG_TIMEZONE}" /etc/localtime >>"$LOG_ERR" 2>&1 || true
    timedatectl set-timezone "${ARG_TIMEZONE}" >>"$LOG_ERR" 2>&1 || true
    ok "Timezone set to ${ARG_TIMEZONE}"
  fi
}

maybe_reboot() {
  local r="${ARG_REBOOT:-0}"
  case "${r}" in
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

apply_cmd() {
  need_root
  trap on_exit_apply EXIT

  print_start_banner
  timezone_apply

  # Export common env for assets
  export EDGE_TIMEZONE="${ARG_TIMEZONE}"
  export EDGE_USER="${ARG_USER}"

  export EDGE_DNS_PROFILE="${ARG_DNS_PROFILE}"
  export EDGE_DNS_SWITCHER="${ARG_DNS_SWITCHER}"
  export EDGE_TAILSCALE="${ARG_TAILSCALE}"
  export EDGE_REMNANODE="${ARG_REMNANODE}"
  export EDGE_SSH_HARDEN="${ARG_SSH_HARDEN}"
  export EDGE_OPEN_WAN_443="${ARG_OPEN_WAN_443}"

  # 1) apt bootstrap
  hdr "📦 Packages"
  if run_asset "apt-bootstrap" "$URL_APT" "$LOG_APT"; then
    ok "apt-bootstrap finished"
  else
    warn "apt-bootstrap exited with code=$? (see $LOG_APT)"
    # Continue; some assets may still run, and summary will print
  fi

  # 2) DNS (optional)
  if [[ "${ARG_DNS_SWITCHER}" == "1" ]]; then
    hdr "🌐 DNS switcher (early)"
    set +e
    run_asset "dns-bootstrap" "$URL_DNS" "$LOG_DNS"
    local rc=$?
    set -e
    if [[ $rc -eq 0 ]]; then
      ok "dns-bootstrap finished"
      ok "dns-switcher applied (see ${LOG_DNS})"
    else
      warn "dns-bootstrap exited with code=$rc (see ${LOG_DNS})"
      warn "dns-switcher may still be applied; check log."
    fi
  fi

  # 3) Tailscale (optional)
  if [[ "${ARG_TAILSCALE}" == "1" ]]; then
    hdr "🧠 Tailscale (early)"
    set +e
    run_asset "tailscale-bootstrap" "$URL_TS" "$LOG_TS"
    local rc=$?
    set -e
    if [[ $rc -eq 0 ]]; then
      ok "tailscale-bootstrap finished"
    else
      warn "tailscale-bootstrap exited with code=$rc (see ${LOG_TS})"
    fi

    local ip name
    ip="$(tailscale_ip4 || true)"
    name="$(tailscale_magicdns || true)"
    [[ -n "$ip" ]] && ok "tailscale ip: $ip" || warn "tailscale ip not detected"
    [[ -n "$name" ]] && ok "MagicDNS: $name" || warn "MagicDNS not detected"
  fi

  # 4) User setup (optional if user provided)
  if [[ -n "${ARG_USER:-}" ]]; then
    hdr "👤 User setup"
    set +e
    run_asset "user-setup" "$URL_USER" "$LOG_USER"
    local rc=$?
    set -e
    if [[ $rc -eq 0 ]]; then
      ok "user-setup finished"
    else
      warn "user-setup exited with code=$rc (see ${LOG_USER})"
      ok "user-setup done (see ${LOG_USER})"
    fi
  fi

  # 5) Zsh (always ok to run; it should be idempotent)
  hdr "💅 Zsh"
  if run_asset "zsh-bootstrap" "$URL_ZSH" "$LOG_ZSH"; then
    ok "zsh-bootstrap finished"
  else
    warn "zsh-bootstrap exited with code=$? (see ${LOG_ZSH})"
  fi

  # 6) Kernel tuning (treat success by log signature, NOT exit code)
  hdr "🧠 Kernel + system tuning"
  set +e
  run_asset "kernel-bootstrap" "$URL_KERNEL" "$LOG_TUNE"
  local krc=$?
  set -e

  if grep -qE '^OK Applied\. Backup:' "$LOG_TUNE"; then
    # Extract backup dir if present
    KERNEL_BACKUP_DIR="$(grep -Eo '/root/edge-tuning-backup-[0-9]{8}-[0-9]{6,}' "$LOG_TUNE" | head -n1 || true)"
    export EDGE_KERNEL_BACKUP_DIR="${KERNEL_BACKUP_DIR:-}"

    ok "kernel tuning applied"
    [[ -n "${KERNEL_BACKUP_DIR:-}" ]] && warn "Kernel tuning backup: ${KERNEL_BACKUP_DIR}"
    warn "Kernel script returned rc=${krc}, but APPLY succeeded (this is expected sometimes)."
    [[ -n "${KERNEL_BACKUP_DIR:-}" ]] && warn "Rollback (if ever needed): sudo BACKUP_DIR=${KERNEL_BACKUP_DIR} bash rollback"

    echo
    # Print the nice upstream report (trim if you want)
    sed -n '1,260p' "$LOG_TUNE" || true
  else
    warn "kernel-bootstrap exited with code=${krc} and no 'OK Applied' found (see ${LOG_TUNE})"
    # Do NOT hard-exit here; continue, summary will include rollback hint from log.
  fi

  # 7) UFW (optional)
  if [[ "${ARG_OPEN_WAN_443}" == "1" || "${ARG_TAILSCALE}" == "1" ]]; then
    hdr "🧱 UFW"
    set +e
    run_asset "ufw-bootstrap" "$URL_UFW" "$LOG_UFW"
    local rc=$?
    set -e
    if [[ $rc -eq 0 ]]; then
      ok "ufw-bootstrap finished"
    else
      warn "ufw-bootstrap exited with code=$rc (see ${LOG_UFW})"
    fi
  fi

  # 8) remnanode (optional)
  if [[ "${ARG_REMNANODE}" == "1" ]]; then
    hdr "🧩 remnanode"
    set +e
    run_asset "remnanode-bootstrap" "$URL_REMNANODE" "$LOG_REMNA"
    local rc=$?
    set -e
    if [[ $rc -eq 0 ]]; then
      ok "remnanode-bootstrap finished"
    else
      warn "remnanode-bootstrap exited with code=$rc (see ${LOG_REMNA})"
    fi
  fi

  # 9) SSH hardening (optional)
  if [[ "${ARG_SSH_HARDEN}" == "1" ]]; then
    hdr "🔐 SSH hardening + fail2ban"
    set +e
    run_asset "ssh-bootstrap" "$URL_SSH" "$LOG_SSH"
    local rc=$?
    set -e
    if [[ $rc -eq 0 ]]; then
      ok "ssh-bootstrap finished"
    else
      warn "ssh-bootstrap exited with code=$rc (see ${LOG_SSH})"
    fi
  fi

  # Summary is printed by EXIT trap (always)
  maybe_reboot
}

status_cmd() {
  need_root
  hdr "📊 Status"
  echo "Host: $(host_short)"
  echo "Timezone: $(timedatectl show -p Timezone --value 2>/dev/null || true)"
  echo
  echo "Tailscale:"
  if command -v tailscale >/dev/null 2>&1; then
    echo "  IP: $(tailscale_ip4 || true)"
    echo "  DNS: $(tailscale_magicdns || true)"
  else
    echo "  (not installed)"
  fi
  echo
  echo "UFW:"
  if command -v ufw >/dev/null 2>&1; then
    ufw status 2>/dev/null || true
  else
    echo "  (not installed)"
  fi
  echo
  echo "Logs:"
  echo "  - APT:      $LOG_APT"
  echo "  - DNS:      $LOG_DNS"
  echo "  - TS:       $LOG_TS"
  echo "  - USER:     $LOG_USER"
  echo "  - ZSH:      $LOG_ZSH"
  echo "  - TUNE:     $LOG_TUNE"
  echo "  - UFW:      $LOG_UFW"
  echo "  - REMNA:    $LOG_REMNA"
  echo "  - SSH:      $LOG_SSH"
  echo "  - SUMMARY:  $LOG_SUMMARY"
  echo "  - ERROR:    $LOG_ERR"
}

# -------------------- Main --------------------
case "${CMD}" in
  apply)    apply_cmd ;;
  status)   status_cmd ;;
  ""|help|-h|--help) usage; exit 0 ;;
  *)
    usage
    exit 1
    ;;
esac
