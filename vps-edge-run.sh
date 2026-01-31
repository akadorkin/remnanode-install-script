#!/usr/bin/env bash
set -Eeuo pipefail

# vps-edge-run.sh
# Awesome Remnanode installer + VPS edge tuning (idempotent + rollback)
# - DNS switcher (systemd-resolved) early
# - Tailscale early (no auth key, no exit-node; idempotent)
# - Kernel/sysctl/limits/journald/logrotate/tmpfiles tuning (profiled) + rollback
# - Docker install
# - Optional remnanode compose + start (over Tailscale-only linkage)
# - Optional SSH hardening (PasswordAuth no, PermitRootLogin no)
# - Optional UFW: WAN only 443, Tailscale allow all

###############################################################################
# Globals / defaults
###############################################################################
SCRIPT_NAME="$(basename "${BASH_SOURCE[0]:-$0}")"

# CLI defaults (if user runs: ./vps-edge-run.sh apply)
EDGE_CONFIRM="${EDGE_CONFIRM:-0}"               # set 1 to ask confirm before apply (non-interactive CI can keep 0)
LOG_TS="${EDGE_LOG_TS:-1}"

# Feature toggles default to "interactive ask" when not provided
ARG_USER=""
ARG_TAILSCALE=""       # 1/0 or empty -> ask
ARG_DNS_SWITCHER=""    # 1/0 or empty -> ask
ARG_DNS_PROFILE=""     # 1..5 (default 1)
ARG_REMNANODE=""       # 1/0 or empty -> ask
ARG_SSH_HARDEN=""      # 1/0 or empty -> ask
ARG_OPEN_WAN_443=""    # 1/0 or empty -> ask
ARG_IPERF3_SERVER=""   # 1/0 or empty -> ask
ARG_REBOOT="${ARG_REBOOT:-}"  # 5m default if interactive, otherwise as provided

TIMEZONE_DEFAULT="Europe/Moscow"

# Remnanode params
NODE_PORT=""
SECRET_KEY=""

# Logs
APT_LOG="/var/log/vps-edge-apt.log"
DNS_LOG="/var/log/vps-edge-dns-switcher.log"
TS_LOG="/var/log/vps-edge-tailscale.log"
DOCKER_LOG="/var/log/vps-edge-docker.log"
ERR_LOG="/var/log/vps-edge-error.log"

# Backup/rollback
backup_dir=""
moved_dir=""
manifest=""

# Runtime collected
WAN_IP=""
WAN_CITY=""
WAN_REGION=""
WAN_COUNTRY_CODE=""
WAN_COUNTRY_NAME=""
WAN_ASN=""
WAN_ORG=""
WAN_FLAG="🏳️"

TS_IP=""
TS_DNS=""   # MagicDNS name (device DNS name)
HOST_SHORT="$(hostname -s 2>/dev/null || hostname)"

# Planned tuning profile info (shown in Summary)
PROFILE=""
TIER=""
CPU_COUNT=""
MEM_MB=""
DISK_ROOT_MB=""

# User info
CREATED_USER=""     # name
PASS_GEN=""         # only when created new

###############################################################################
# Logging + colors
###############################################################################
ts() { [[ "$LOG_TS" == "1" ]] && date +"%Y-%m-%d %H:%M:%S" || true; }
_is_tty() { [[ -t 1 ]]; }

c_reset=$'\033[0m'
c_dim=$'\033[2m'
c_bold=$'\033[1m'
c_red=$'\033[31m'
c_yel=$'\033[33m'
c_grn=$'\033[32m'
c_cyan=$'\033[36m'

color() { # color <ansi> <text...>
  local code="$1"; shift
  if _is_tty; then printf "%s%s%s" "$code" "$*" "$c_reset"; else printf "%s" "$*"; fi
}

_pfx() { _is_tty && printf "%s%s%s" "${c_dim}" "$(ts) " "${c_reset}" || true; }

ok()   { _pfx; color "$c_grn" "✅ OK";   printf " %s\n" "$*"; }
info() { _pfx; color "$c_cyan" "ℹ️  ";   printf " %s\n" "$*"; }
warn() { _pfx; color "$c_yel" "⚠️  ";   printf " %s\n" "$*"; }
err()  { _pfx; color "$c_red" "🛑 ";     printf " %s\n" "$*"; }
die()  { err "$*"; exit 1; }

hdr() { echo; color "$c_bold$c_cyan" "$*"; echo; }

###############################################################################
# Root / sudo re-exec
###############################################################################
need_root() {
  if [[ "${EUID:-$(id -u)}" -eq 0 ]]; then
    return 0
  fi

  local self="${BASH_SOURCE[0]:-}"
  if [[ -n "$self" && -f "$self" && -r "$self" ]]; then
    if command -v sudo >/dev/null 2>&1; then
      warn "Not root -> re-exec via sudo"
      exec sudo -E bash "$self" "$@"
    fi
    die "Not root and sudo not found."
  fi

  die "Not root. Use: curl ... | sudo bash -s -- <cmd>"
}

###############################################################################
# TTY input helpers
###############################################################################
read_tty() {
  local __var="$1" __prompt="$2" __v=""
  read -rp "$__prompt" __v </dev/tty || true
  printf -v "$__var" '%s' "$__v"
}

read_tty_silent() {
  local __var="$1" __prompt="$2" __v=""
  read -rsp "$__prompt" __v </dev/tty || true
  echo >/dev/tty || true
  printf -v "$__var" '%s' "$__v"
}

ask_yn_default_yes() {
  local prompt="$1"
  local ans=""
  read_tty ans "${prompt} [Y/n]: "
  ans="${ans,,}"
  [[ -z "$ans" || "$ans" == "y" || "$ans" == "yes" ]]
}

ask_yn_default_no() {
  local prompt="$1"
  local ans=""
  read_tty ans "${prompt} [y/N]: "
  ans="${ans,,}"
  [[ "$ans" == "y" || "$ans" == "yes" ]]
}

###############################################################################
# Confirmation (optional)
###############################################################################
confirm() {
  [[ "${EDGE_CONFIRM:-0}" == "1" ]] || return 0
  [[ -t 0 ]] || return 0
  echo
  echo "This will tune sysctl, swap, limits, journald, unattended-upgrades, logrotate, tmpfiles, and optionally install tailscale/docker/remnanode."
  read -r -p "Continue? [y/N] " ans
  [[ "$ans" == "y" || "$ans" == "Y" ]] || die "Cancelled."
}

###############################################################################
# Backup + manifest
###############################################################################
mkbackup() {
  local tsd
  tsd="$(date +%Y%m%d-%H%M%S)"
  backup_dir="/root/edge-tuning-backup-${tsd}"
  moved_dir="${backup_dir}/moved"
  manifest="${backup_dir}/MANIFEST.tsv"
  mkdir -p "$backup_dir" "$moved_dir" "${backup_dir}/files"
  : > "$manifest"
}

backup_file() {
  local src="$1"
  [[ -f "$src" ]] || return 0
  local rel="${src#/}"
  local dst="${backup_dir}/files/${rel}"
  mkdir -p "$(dirname "$dst")"
  cp -a "$src" "$dst"
  printf "COPY\t%s\t%s\n" "$src" "$dst" >> "$manifest"
}

move_aside() {
  local src="$1"
  [[ -f "$src" ]] || return 0
  local rel="${src#/}"
  local dst="${moved_dir}/${rel}"
  mkdir -p "$(dirname "$dst")"
  mv -f "$src" "$dst"
  printf "MOVE\t%s\t%s\n" "$src" "$dst" >> "$manifest"
}

restore_manifest() {
  local bdir="$1"
  local man="${bdir}/MANIFEST.tsv"
  [[ -f "$man" ]] || die "Manifest not found: $man"

  while IFS=$'\t' read -r kind a b; do
    [[ -n "${kind:-}" ]] || continue
    case "$kind" in
      COPY)
        [[ -f "$b" ]] || continue
        mkdir -p "$(dirname "$a")"
        cp -a "$b" "$a"
        ;;
      MOVE)
        [[ -f "$b" ]] || continue
        mkdir -p "$(dirname "$a")"
        mv -f "$b" "$a"
        ;;
    esac
  done < "$man"
}

latest_backup_dir() {
  ls -1dt /root/edge-tuning-backup-* 2>/dev/null | head -n1 || true
}

###############################################################################
# Utilities
###############################################################################
run_logged() { # run_logged <logfile> <cmd...>
  local logfile="$1"; shift
  "$@" >>"$logfile" 2>&1
}

to_int() { [[ "${1:-}" =~ ^[0-9]+$ ]] && echo "$1" || echo 0; }

imax() {
  local a b
  a="$(to_int "${1:-0}")"
  b="$(to_int "${2:-0}")"
  [[ "$a" -ge "$b" ]] && echo "$a" || echo "$b"
}

clamp() {
  local v lo hi
  v="$(to_int "${1:-0}")"
  lo="$(to_int "${2:-0}")"
  hi="$(to_int "${3:-0}")"
  [[ "$v" -lt "$lo" ]] && v="$lo"
  [[ "$v" -gt "$hi" ]] && v="$hi"
  echo "$v"
}

ceil_gib() { local mem_mb="$1"; echo $(( (mem_mb + 1023) / 1024 )); }

ceil_to_tier() {
  local x="$1"
  if   [[ "$x" -le 1  ]]; then echo 1
  elif [[ "$x" -le 2  ]]; then echo 2
  elif [[ "$x" -le 4  ]]; then echo 4
  elif [[ "$x" -le 8  ]]; then echo 8
  elif [[ "$x" -le 16 ]]; then echo 16
  elif [[ "$x" -le 32 ]]; then echo 32
  else echo 64
  fi
}

tier_rank() {
  case "$1" in
    1) echo 1 ;;
    2) echo 2 ;;
    4) echo 3 ;;
    8) echo 4 ;;
    16) echo 5 ;;
    32) echo 6 ;;
    *) echo 7 ;;
  esac
}

tier_max() {
  local a="$1" b="$2"
  local ra rb
  ra="$(tier_rank "$a")"; rb="$(tier_rank "$b")"
  if [[ "$ra" -ge "$rb" ]]; then echo "$a"; else echo "$b"; fi
}

profile_from_tier() {
  local t="$1"
  case "$t" in
    1)  echo "low" ;;
    2)  echo "mid" ;;
    4)  echo "high" ;;
    8)  echo "xhigh" ;;
    16) echo "2xhigh" ;;
    32) echo "dedicated" ;;
    *)  echo "dedicated+" ;;
  esac
}

# Conntrack soft formula:
# ct_soft = RAM_MiB * 64 + CPU * 8192
ct_soft_from_ram_cpu() {
  local mem_mb="$1" cpu="$2"
  local ct=$(( mem_mb * 64 + cpu * 8192 ))
  [[ "$ct" -lt 32768 ]] && ct=32768
  echo "$ct"
}

disk_root_mb() {
  local mb
  mb="$(df -Pm / 2>/dev/null | awk 'NR==2{print $2}' || true)"
  [[ -n "$mb" ]] || mb="0"
  echo "$mb"
}

disk_size_mb_for_logs() {
  local mb
  mb="$(df -Pm /var/log 2>/dev/null | awk 'NR==2{print $2}' || true)"
  [[ -n "$mb" ]] || mb="$(df -Pm / 2>/dev/null | awk 'NR==2{print $2}' || true)"
  [[ -n "$mb" ]] || mb="0"
  echo "$mb"
}

pick_log_caps() {
  local disk_mb="$1"
  J_SYSTEM="100M"; J_RUNTIME="50M"; LR_ROTATE="7"
  if [[ "$disk_mb" -lt 15000 ]]; then
    J_SYSTEM="80M";  J_RUNTIME="40M";  LR_ROTATE="5"
  elif [[ "$disk_mb" -lt 30000 ]]; then
    J_SYSTEM="120M"; J_RUNTIME="60M";  LR_ROTATE="7"
  elif [[ "$disk_mb" -lt 60000 ]]; then
    J_SYSTEM="200M"; J_RUNTIME="100M"; LR_ROTATE="10"
  elif [[ "$disk_mb" -lt 120000 ]]; then
    J_SYSTEM="300M"; J_RUNTIME="150M"; LR_ROTATE="14"
  else
    J_SYSTEM="400M"; J_RUNTIME="200M"; LR_ROTATE="21"
  fi
}

# Country flag from ISO2 (A-Z)
country_flag() {
  local cc="${1:-}"
  cc="${cc^^}"
  if [[ ! "$cc" =~ ^[A-Z]{2}$ ]]; then
    printf "🏳️"
    return 0
  fi
  local o1 o2 cp1 cp2 esc
  o1="$(printf '%d' "'${cc:0:1}")"
  o2="$(printf '%d' "'${cc:1:1}")"
  cp1=$((0x1F1E6 + o1 - 65))
  cp2=$((0x1F1E6 + o2 - 65))
  printf -v esc "\\U%08X\\U%08X" "$cp1" "$cp2"
  printf "%b" "$esc"
}

###############################################################################
# Snapshots (before/after)
###############################################################################
_swap_state() {
  local s
  s="$(/sbin/swapon --noheadings --show=NAME,SIZE 2>/dev/null | awk '{$1=$1; print}' | tr '\n' ';' | sed 's/;$//' || true)"
  [[ -n "$s" ]] && echo "$s" || echo "none"
}

_nofile_systemd() {
  local n
  n="$(systemctl show --property DefaultLimitNOFILE 2>/dev/null | cut -d= -f2 || true)"
  echo "${n:--}"
}

_journald_caps() {
  local f="/etc/systemd/journald.conf.d/90-edge.conf"
  if [[ -f "$f" ]]; then
    local s r
    s="$(awk -F= '/^\s*SystemMaxUse=/{print $2}' "$f" | tr -d ' ' | head -n1)"
    r="$(awk -F= '/^\s*RuntimeMaxUse=/{print $2}' "$f" | tr -d ' ' | head -n1)"
    [[ -n "$s" || -n "$r" ]] && echo "${s:-?}/${r:-?}" && return 0
  fi
  echo "-"
}

_logrotate_mode() {
  local f="/etc/logrotate.conf"
  [[ -f "$f" ]] || { echo "-"; return 0; }
  local freq rot
  freq="$(awk 'tolower($1)=="daily"||tolower($1)=="weekly"||tolower($1)=="monthly"{print tolower($1); exit}' "$f" 2>/dev/null || true)"
  rot="$(awk 'tolower($1)=="rotate"{print $2; exit}' "$f" 2>/dev/null || true)"
  echo "${freq:-?} / rotate ${rot:-?}"
}

_unattended_reboot_setting() {
  local reboot time
  reboot="$(grep -Rhs 'Unattended-Upgrade::Automatic-Reboot' /etc/apt/apt.conf.d/*.conf 2>/dev/null \
    | sed -nE 's/.*Automatic-Reboot\s+"([^"]+)".*/\1/p' | tail -n1 || true)"
  time="$(grep -Rhs 'Unattended-Upgrade::Automatic-Reboot-Time' /etc/apt/apt.conf.d/*.conf 2>/dev/null \
    | sed -nE 's/.*Automatic-Reboot-Time\s+"([^"]+)".*/\1/p' | tail -n1 || true)"
  [[ -z "${reboot:-}" ]] && reboot="-"
  [[ -z "${time:-}" ]] && time="-"
  echo "${reboot} / ${time}"
}
_unattended_state() { echo "${1%% / *}"; }
_unattended_time()  { echo "${1##* / }"; }

snapshot_before() {
  B_TCP_CC="$(sysctl -n net.ipv4.tcp_congestion_control 2>/dev/null || echo '-')"
  B_QDISC="$(sysctl -n net.core.default_qdisc 2>/dev/null || echo '-')"
  B_FWD="$(sysctl -n net.ipv4.ip_forward 2>/dev/null || echo '-')"
  B_CT_MAX="$(sysctl -n net.netfilter.nf_conntrack_max 2>/dev/null || echo '-')"
  B_TW="$(sysctl -n net.ipv4.tcp_max_tw_buckets 2>/dev/null || echo '-')"
  B_SWAPPINESS="$(sysctl -n vm.swappiness 2>/dev/null || echo '-')"
  B_SWAP="$(_swap_state)"
  B_NOFILE="$(_nofile_systemd)"
  B_JOURNAL="$(_journald_caps)"
  B_LOGROT="$(_logrotate_mode)"
  B_UNATT="$(_unattended_reboot_setting)"
}

snapshot_after() {
  A_TCP_CC="$(sysctl -n net.ipv4.tcp_congestion_control 2>/dev/null || echo '-')"
  A_QDISC="$(sysctl -n net.core.default_qdisc 2>/dev/null || echo '-')"
  A_FWD="$(sysctl -n net.ipv4.ip_forward 2>/dev/null || echo '-')"
  A_CT_MAX="$(sysctl -n net.netfilter.nf_conntrack_max 2>/dev/null || echo '-')"
  A_TW="$(sysctl -n net.ipv4.tcp_max_tw_buckets 2>/dev/null || echo '-')"
  A_SWAPPINESS="$(sysctl -n vm.swappiness 2>/dev/null || echo '-')"
  A_SWAP="$(_swap_state)"
  A_NOFILE="$(_nofile_systemd)"
  A_JOURNAL="$(_journald_caps)"
  A_LOGROT="$(_logrotate_mode)"
  A_UNATT="$(_unattended_reboot_setting)"
}

###############################################################################
# Pretty tables
###############################################################################
row_kv() { local k="$1" v="$2"; printf "%-14s | %s\n" "$k" "$v"; }

print_before_after_all() {
  hdr "🧾 Before → After (all)"
  printf "%-14s-+-%-30s-+-%-30s\n" "$(printf '%.0s-' {1..14})" "$(printf '%.0s-' {1..30})" "$(printf '%.0s-' {1..30})"

  row3() {
    local k="$1" b="$2" a="$3"
    printf "%-14s | %-30s | %-30s\n" "$k" "$b" "$a"
  }

  row3 "TCP"        "$B_TCP_CC" "$A_TCP_CC"
  row3 "Qdisc"      "$B_QDISC" "$A_QDISC"
  row3 "Forward"    "$B_FWD" "$A_FWD"
  row3 "Conntrack"  "$B_CT_MAX" "$A_CT_MAX"
  row3 "TW buckets" "$B_TW" "$A_TW"
  row3 "Swappiness" "$B_SWAPPINESS" "$A_SWAPPINESS"
  row3 "Swap"       "$B_SWAP" "$A_SWAP"
  row3 "Nofile"     "$B_NOFILE" "$A_NOFILE"
  row3 "Journald"   "$B_JOURNAL" "$A_JOURNAL"
  row3 "Logrotate"  "$B_LOGROT" "$A_LOGROT"
  row3 "AutoReboot" "$(_unattended_state "$B_UNATT")" "$(_unattended_state "$A_UNATT")"
  row3 "Reboot time" "$(_unattended_time "$B_UNATT")"  "$(_unattended_time "$A_UNATT")"
}

print_manifest_compact() {
  local man="$1"
  [[ -f "$man" ]] || return 0

  local copies moves
  copies="$(awk -F'\t' '$1=="COPY"{c++} END{print c+0}' "$man" 2>/dev/null || echo 0)"
  moves="$(awk -F'\t' '$1=="MOVE"{c++} END{print c+0}' "$man" 2>/dev/null || echo 0)"

  hdr "📦 Files"
  echo "  backed up (COPY): $copies"
  echo "  moved aside:      $moves"
}

print_summary_table() {
  local remna_state="$1"
  local remna_compose="$2"
  local pass_line="$3"

  hdr "🧾 Summary"
  row_kv "Host"        "${HOST_SHORT}"
  row_kv "WAN"         "${WAN_FLAG} ${WAN_IP:-?}"
  row_kv "Geo"         "${WAN_CITY:-?}, ${WAN_REGION:-?}, ${WAN_COUNTRY_CODE:-?}"
  row_kv "Provider"    "${WAN_ASN:-?} ${WAN_ORG:-?}"
  row_kv "Tailscale IP" "${TS_IP:-"-"}"
  row_kv "MagicDNS"    "${TS_DNS:-"-"}"
  row_kv "HW profile"  "profile ${PROFILE:-?}, tier ${TIER:-?} | CPU ${CPU_COUNT:-?} | RAM ${MEM_MB:-?} MiB | / ${DISK_ROOT_MB:-?} MB"
  row_kv "User"        "${CREATED_USER:-"-"}"
  row_kv "Password"    "${pass_line}"
  row_kv "remnanode"   "${remna_state:-"-"}"
  row_kv "compose"     "${remna_compose:-"-"}"
}

print_backup_logs_table() {
  hdr "📚 Backup + logs"
  echo "Backup: ${backup_dir:-"-"}"
  echo "Logs:"
  echo "  - 📦 APT:       ${APT_LOG}"
  echo "  - 🌐 DNS:       ${DNS_LOG}"
  echo "  - 🧠 Tailscale: ${TS_LOG}"
  echo "  - 🐳 Docker:    ${DOCKER_LOG}"
  echo "  - 🛑 Error:     ${ERR_LOG}"
  echo "BACKUP_DIR=${backup_dir:-"-"}"
}

###############################################################################
# Geo/provider (Start/End banner)
###############################################################################
fetch_wan_info() {
  # Uses ipwho.is (no key). Falls back to ipify if needed.
  local json
  json="$(curl -fsSL "https://ipwho.is/" 2>/dev/null || true)"
  if [[ -n "$json" ]] && command -v jq >/dev/null 2>&1; then
    WAN_IP="$(echo "$json" | jq -r '.ip // empty')"
    WAN_CITY="$(echo "$json" | jq -r '.city // empty')"
    WAN_REGION="$(echo "$json" | jq -r '.region // empty')"
    WAN_COUNTRY_CODE="$(echo "$json" | jq -r '.country_code // empty')"
    WAN_COUNTRY_NAME="$(echo "$json" | jq -r '.country // empty')"
    WAN_ASN="$(echo "$json" | jq -r '.connection.asn // empty')"
    WAN_ORG="$(echo "$json" | jq -r '.connection.isp // empty')"
  fi

  [[ -n "${WAN_IP:-}" ]] || WAN_IP="$(curl -fsSL https://api.ipify.org 2>/dev/null || curl -fsSL ifconfig.me 2>/dev/null || true)"
  [[ -n "${WAN_COUNTRY_CODE:-}" ]] || WAN_COUNTRY_CODE=""

  WAN_FLAG="$(country_flag "${WAN_COUNTRY_CODE:-}")"
}

print_start_end_banner() {
  local title="$1"
  hdr "$title"
  fetch_wan_info || true
  echo "  ${WAN_FLAG} ${WAN_IP:-?} — ${WAN_CITY:-?}, ${WAN_REGION:-?}, ${WAN_COUNTRY_CODE:-?} — ${WAN_ASN:-?} ${WAN_ORG:-?}"
}

###############################################################################
# APT helpers
###############################################################################
aptq() {
  local what="$1"; shift
  mkdir -p "$(dirname "$APT_LOG")"
  : >>"$APT_LOG"
  if DEBIAN_FRONTEND=noninteractive apt-get -y -qq -o Dpkg::Use-Pty=0 \
      -o Dpkg::Options::='--force-confdef' \
      -o Dpkg::Options::='--force-confold' \
      "$@" >>"$APT_LOG" 2>&1; then
    ok "$what"
  else
    err "$what (see tail below)"
    tail -n 80 "$APT_LOG" || true
    return 1
  fi
}

ensure_packages() {
  local title="$1"; shift
  aptq "APT update" update
  aptq "$title" install "$@"
}

###############################################################################
# DNS switcher (systemd-resolved) - interactive-like, but auto proceed
###############################################################################
dns_apply() {
  local profile="${1:-1}"

  hdr "🌐 DNS switcher (early)"
  : > "$DNS_LOG"

  # Ensure resolved is present and active
  if ! command -v resolvectl >/dev/null 2>&1; then
    run_logged "$DNS_LOG" apt-get -y -qq update
    run_logged "$DNS_LOG" apt-get -y -qq install systemd-resolved
  fi
  run_logged "$DNS_LOG" systemctl enable --now systemd-resolved || true

  # Profile mapping (same meaning as upstream script)
  local DNS_SERVERS="" FALLBACK_DNS=""
  case "$profile" in
    2) DNS_SERVERS="8.8.8.8 8.8.4.4"; FALLBACK_DNS="9.9.9.9" ;;
    3) DNS_SERVERS="1.1.1.1 1.0.0.1"; FALLBACK_DNS="9.9.9.9" ;;
    4) DNS_SERVERS="9.9.9.9 149.112.112.112"; FALLBACK_DNS="1.1.1.1" ;;
    5)
      # Custom: ask interactively
      read_tty DNS_SERVERS "Enter primary DNS servers (space-separated): "
      read_tty FALLBACK_DNS "Enter fallback DNS server [default: 9.9.9.9]: "
      [[ -n "$DNS_SERVERS" ]] || die "Custom DNS servers cannot be empty."
      [[ -n "$FALLBACK_DNS" ]] || FALLBACK_DNS="9.9.9.9"
      ;;
    *) DNS_SERVERS="8.8.8.8 8.8.4.4 1.1.1.1 1.0.0.1"; FALLBACK_DNS="9.9.9.9" ;;
  esac

  info "Applying DNS profile ${profile} (auto-yes)"

  # Backup resolved.conf into our backup manifest (and also upstream-style backup directory)
  mkdir -p /etc/dns-switcher-backup
  if [[ -f /etc/systemd/resolved.conf ]]; then
    cp /etc/systemd/resolved.conf "/etc/dns-switcher-backup/resolved.conf.backup.$(date +%Y%m%d_%H%M%S)" >>"$DNS_LOG" 2>&1 || true
  fi
  resolvectl status >"/etc/dns-switcher-backup/dns_status.backup.$(date +%Y%m%d_%H%M%S)" 2>>"$DNS_LOG" || true

  # Write resolved.conf (idempotent)
  backup_file /etc/systemd/resolved.conf || true
  cat > /etc/systemd/resolved.conf <<EOF
# This file is managed by vps-edge-run.sh (DNS switcher)
# Based on: github.com/AndreyTimoschuk/dns-switcher
# Backups: /etc/dns-switcher-backup

[Resolve]
DNS=$DNS_SERVERS
FallbackDNS=$FALLBACK_DNS
Domains=~.
DNSSEC=no
DNSOverTLS=no
Cache=yes
EOF

  run_logged "$DNS_LOG" systemctl restart systemd-resolved
  sleep 1

  ok "dns-switcher applied (profile ${profile})"

  # Print a compact “what changed” + tips like upstream
  hdr "🧾 DNS summary"
  echo "Applied:"
  echo "  - DNS:         ${DNS_SERVERS}"
  echo "  - FallbackDNS: ${FALLBACK_DNS}"
  echo
  echo "Now:"
  resolvectl status 2>/dev/null | grep -E "DNS Servers|DNS Domain|Fallback DNS" || true
  echo
  echo "Tips:"
  echo "  - Monitor DNS queries:"
  echo "      sudo tcpdump -i any port 53 -n -Q out"
  echo "  - Verify after reboot:"
  echo "      sudo resolvectl status | grep -E \"DNS Servers|DNS Domain\""
  echo "Backups:"
  echo "  - /etc/dns-switcher-backup"
}

###############################################################################
# Tailscale (early) - idempotent, no auth key, no exit-node
###############################################################################
tailscale_install_if_needed() {
  if command -v tailscale >/dev/null 2>&1; then
    ok "tailscale already installed"
    return 0
  fi

  : > "$TS_LOG"
  info "Installing tailscale…"
  run_logged "$TS_LOG" bash -lc 'curl -fsSL https://tailscale.com/install.sh | sh'
  ok "tailscale installed"
}

tailscale_get_state_json() {
  tailscale status --json 2>/dev/null || true
}

tailscale_is_logged_in() {
  local js
  js="$(tailscale_get_state_json)"
  [[ -n "$js" ]] || return 1
  if command -v jq >/dev/null 2>&1; then
    local st
    st="$(echo "$js" | jq -r '.BackendState // empty' 2>/dev/null || true)"
    [[ "$st" == "Running" ]] && return 0
  fi
  return 1
}

tailscale_collect_ids() {
  TS_IP="$(tailscale ip -4 2>/dev/null | head -n1 || true)"
  if command -v jq >/dev/null 2>&1; then
    TS_DNS="$(tailscale_get_state_json | jq -r '.Self.DNSName // empty' 2>/dev/null || true)"
  fi
  TS_DNS="${TS_DNS%.}"  # remove trailing dot if any
}

tailscale_up_flow() {
  hdr "🧠 Tailscale (early)"
  : > "$TS_LOG"

  # Kernel prereqs (do it once, early; avoid later duplicates)
  backup_file /etc/sysctl.conf || true
  backup_file /etc/sysctl.d/99-edge-tailscale.conf || true
  cat > /etc/sysctl.d/99-edge-tailscale.conf <<'EOF'
# vps-edge-run.sh: tailscale routing friendly defaults
net.ipv4.ip_forward=1
net.ipv6.conf.all.forwarding=1
net.ipv4.conf.all.rp_filter=0
net.ipv4.conf.default.rp_filter=0
EOF
  sysctl --system >/dev/null 2>&1 || true

  # GRO hints (best effort; do not fail)
  local iface
  iface="$(ip route show default 2>/dev/null | awk '/default/ {print $5; exit}' || true)"
  if [[ -n "${iface:-}" ]] && command -v ethtool >/dev/null 2>&1; then
    run_logged "$TS_LOG" ethtool -K "$iface" gro on || true
    run_logged "$TS_LOG" ethtool -K "$iface" rx-udp-gro-forwarding on || true
  fi

  tailscale_install_if_needed

  systemctl enable --now tailscaled >>"$TS_LOG" 2>&1 || true

  if tailscale_is_logged_in; then
    tailscale_collect_ids
    ok "tailscale is up (ip ${TS_IP:-?})"
    [[ -n "${TS_DNS:-}" ]] && ok "MagicDNS: ${TS_DNS}" || warn "MagicDNS name not available (admin may have it disabled)"
    return 0
  fi

  # Not logged in: run plain `tailscale up` (no extra flags to avoid the “non-default flags” trap)
  info "tailscale needs authentication"
  local out url
  out="$(tailscale up 2>&1 | tee -a "$TS_LOG" || true)"
  url="$(echo "$out" | grep -Eo 'https://login\.tailscale\.com/[A-Za-z0-9/_-]+' | head -n1 || true)"

  if [[ -n "$url" ]]; then
    echo
    echo "🔗 Open to authenticate:"
    echo "   $url"
    echo
  else
    warn "Auth URL not found in output. You can run: tailscale up"
  fi

  # Re-check loop (no “hanging”: user drives it with Enter)
  while true; do
    read_tty _ "Press Enter after you approve this device in Tailscale admin… "
    if tailscale_is_logged_in; then
      tailscale_collect_ids
      ok "tailscale is up (ip ${TS_IP:-?})"
      [[ -n "${TS_DNS:-}" ]] && ok "MagicDNS: ${TS_DNS}" || warn "MagicDNS name not available (admin may have it disabled)"
      break
    fi
    warn "Still not authenticated. If you approved it already, check admin panel and try again."
  done
}

###############################################################################
# Docker
###############################################################################
docker_install_if_needed() {
  hdr "🐳 Docker"
  : > "$DOCKER_LOG"

  if command -v docker >/dev/null 2>&1; then
    ok "docker already installed"
    return 0
  fi

  info "Installing Docker CE…"
  run_logged "$DOCKER_LOG" bash -lc 'apt-get -y -qq update'
  run_logged "$DOCKER_LOG" bash -lc 'apt-get -y -qq install ca-certificates curl gnupg lsb-release apt-transport-https'
  run_logged "$DOCKER_LOG" bash -lc 'install -m 0755 -d /etc/apt/keyrings'
  run_logged "$DOCKER_LOG" bash -lc 'curl -fsSL https://download.docker.com/linux/ubuntu/gpg | gpg --batch --yes --dearmor -o /etc/apt/keyrings/docker.gpg'
  run_logged "$DOCKER_LOG" bash -lc 'chmod a+r /etc/apt/keyrings/docker.gpg'
  run_logged "$DOCKER_LOG" bash -lc 'echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/ubuntu $(. /etc/os-release && echo $VERSION_CODENAME) stable" > /etc/apt/sources.list.d/docker.list'
  run_logged "$DOCKER_LOG" bash -lc 'apt-get -y -qq update'
  run_logged "$DOCKER_LOG" bash -lc 'apt-get -y -qq install docker-ce docker-ce-cli containerd.io docker-compose-plugin'
  run_logged "$DOCKER_LOG" systemctl enable --now docker

  ok "docker installed"
}

###############################################################################
# User + Zsh for all /home/* users (+ root)
###############################################################################
ensure_user() {
  hdr "👤 User"
  if [[ -z "${ARG_USER:-}" ]]; then
    read_tty ARG_USER "Enter username to create (or existing): "
  fi
  [[ -n "${ARG_USER:-}" ]] || die "--user is empty"

  CREATED_USER="$ARG_USER"

  if id -u "$CREATED_USER" >/dev/null 2>&1; then
    ok "user exists: ${CREATED_USER}"
    PASS_GEN=""
    return 0
  fi

  PASS_GEN="$(openssl rand -base64 16)"
  useradd -m -s /usr/bin/zsh "$CREATED_USER"
  echo "${CREATED_USER}:${PASS_GEN}" | chpasswd
  usermod -aG sudo "$CREATED_USER" || true
  ok "user created: ${CREATED_USER}"
}

zsh_disable_updates_lines() {
  # prevents OMZ update prompts
  cat <<'EOF'
# vps-edge-run.sh: disable oh-my-zsh auto-update prompts
DISABLE_AUTO_UPDATE="true"
DISABLE_UPDATE_PROMPT="true"
zstyle ':omz:update' mode disabled
EOF
}

ensure_zsh_for_user_home() {
  local u="$1" home="$2"
  [[ -d "$home" ]] || return 0

  # Make sure zsh is a valid shell
  grep -q '^/usr/bin/zsh$' /etc/shells || echo '/usr/bin/zsh' >> /etc/shells

  # Install stack (oh-my-zsh + plugins + p10k + fzf), idempotent
  local zsh_dir="${home}/.oh-my-zsh"
  local custom="${zsh_dir}/custom"

  if [[ ! -d "$zsh_dir" ]]; then
    su - "$u" -c 'RUNZSH=no KEEP_ZSHRC=yes CHSH=no sh -c "$(curl -fsSL https://raw.githubusercontent.com/ohmyzsh/ohmyzsh/master/tools/install.sh)"' >/dev/null 2>&1 || true
  fi

  su - "$u" -c "mkdir -p ${custom}/plugins ${custom}/themes" >/dev/null 2>&1 || true

  [[ -d "${custom}/plugins/zsh-autosuggestions" ]] || su - "$u" -c "git clone --depth=1 https://github.com/zsh-users/zsh-autosuggestions ${custom}/plugins/zsh-autosuggestions" >/dev/null 2>&1 || true
  [[ -d "${custom}/plugins/zsh-completions" ]]     || su - "$u" -c "git clone --depth=1 https://github.com/zsh-users/zsh-completions ${custom}/plugins/zsh-completions" >/dev/null 2>&1 || true
  [[ -d "${custom}/plugins/zsh-syntax-highlighting" ]] || su - "$u" -c "git clone --depth=1 https://github.com/zsh-users/zsh-syntax-highlighting ${custom}/plugins/zsh-syntax-highlighting" >/dev/null 2>&1 || true
  [[ -d "${custom}/themes/powerlevel10k" ]] || su - "$u" -c "git clone --depth=1 https://github.com/romkatv/powerlevel10k.git ${custom}/themes/powerlevel10k" >/dev/null 2>&1 || true

  if [[ ! -d "${home}/.fzf" ]]; then
    su - "$u" -c 'git clone --depth 1 https://github.com/junegunn/fzf.git ~/.fzf' >/dev/null 2>&1 || true
    su - "$u" -c 'yes | ~/.fzf/install --key-bindings --completion --no-bash --no-fish --no-update-rc' >/dev/null 2>&1 || true
  fi

  # zshrc + p10k from this repo (same link where script lives)
  # Put these files in repo root: zshrc, p10k
  local base_raw="${EDGE_RAW_BASE:-https://raw.githubusercontent.com/akadorkin/remnanode-install-script/main}"
  curl -fsSL "${base_raw}/zshrc" -o "${home}/.zshrc" >/dev/null 2>&1 || true
  curl -fsSL "${base_raw}/p10k"  -o "${home}/.p10k.zsh" >/dev/null 2>&1 || true

  # Ensure update prompts are disabled (append if missing)
  if [[ -f "${home}/.zshrc" ]]; then
    if ! grep -q 'vps-edge-run.sh: disable oh-my-zsh auto-update prompts' "${home}/.zshrc" 2>/dev/null; then
      zsh_disable_updates_lines >> "${home}/.zshrc"
    fi
  fi

  # Fix ownership
  chown -R "${u}:${u}" "${home}/.oh-my-zsh" "${home}/.fzf" "${home}/.zshrc" "${home}/.p10k.zsh" 2>/dev/null || true

  # Default shell (best effort)
  chsh -s /usr/bin/zsh "$u" >/dev/null 2>&1 || true
}

zsh_for_all_users() {
  hdr "💅 Zsh for all /home/* users"
  aptq "Install zsh stack packages" install zsh git curl wget jq ca-certificates >/dev/null 2>&1 || true

  local d u
  for d in /home/*; do
    [[ -d "$d" ]] || continue
    u="$(basename "$d")"
    if id -u "$u" >/dev/null 2>&1; then
      ensure_zsh_for_user_home "$u" "$d"
      ok "zsh stack ensured for ${u}"
    fi
  done

  # root too
  ensure_zsh_for_user_home "root" "/root"
  ok "zsh stack ensured for root"
}

###############################################################################
# Kernel + system tuning (profiled) + rollback compatibility
###############################################################################
tuning_apply() {
  hdr "🧠 Kernel + system tuning"

  snapshot_before

  # Discover resources
  local mem_kb mem_mb cpu disk_mb_logs gib ram_tier cpu_tier tier profile disk_mb_root
  mem_kb="$(awk '/MemTotal:/ {print $2}' /proc/meminfo)"
  mem_mb="$((mem_kb / 1024))"
  cpu="$(nproc)"
  disk_mb_logs="$(disk_size_mb_for_logs)"
  disk_mb_root="$(disk_root_mb)"

  gib="$(ceil_gib "$mem_mb")"
  ram_tier="$(ceil_to_tier "$gib")"
  cpu_tier="$(ceil_to_tier "$cpu")"
  tier="$(tier_max "$ram_tier" "$cpu_tier")"
  profile="$(profile_from_tier "$tier")"

  # Save for summary
  PROFILE="$profile"
  TIER="$tier"
  CPU_COUNT="$cpu"
  MEM_MB="$mem_mb"
  DISK_ROOT_MB="$disk_mb_root"

  # Disk-aware log caps
  pick_log_caps "$disk_mb_logs"
  local j_system="$J_SYSTEM" j_runtime="$J_RUNTIME" logrotate_rotate="$LR_ROTATE"

  # Defaults by profile
  local somaxconn netdev_backlog syn_backlog rmem_max wmem_max rmem_def wmem_def tcp_rmem tcp_wmem
  local swappiness nofile_profile tw_profile
  local ct_min ct_cap

  case "$profile" in
    low)
      somaxconn=4096;  netdev_backlog=16384;  syn_backlog=4096
      rmem_max=$((32*1024*1024));  wmem_max=$((32*1024*1024))
      rmem_def=$((8*1024*1024));   wmem_def=$((8*1024*1024))
      tcp_rmem="4096 262144 ${rmem_max}"
      tcp_wmem="4096 262144 ${wmem_max}"
      swappiness=5
      nofile_profile=65536
      tw_profile=50000
      ct_min=32768;   ct_cap=65536
      ;;
    mid)
      somaxconn=16384; netdev_backlog=65536;  syn_backlog=16384
      rmem_max=$((64*1024*1024));  wmem_max=$((64*1024*1024))
      rmem_def=$((16*1024*1024));  wmem_def=$((16*1024*1024))
      tcp_rmem="4096 87380 ${rmem_max}"
      tcp_wmem="4096 65536 ${wmem_max}"
      swappiness=10
      nofile_profile=131072
      tw_profile=90000
      ct_min=65536;   ct_cap=131072
      ;;
    high)
      somaxconn=65535; netdev_backlog=131072; syn_backlog=65535
      rmem_max=$((128*1024*1024)); wmem_max=$((128*1024*1024))
      rmem_def=$((32*1024*1024));  wmem_def=$((32*1024*1024))
      tcp_rmem="4096 87380 ${rmem_max}"
      tcp_wmem="4096 65536 ${wmem_max}"
      swappiness=10
      nofile_profile=262144
      tw_profile=150000
      ct_min=131072;  ct_cap=262144
      ;;
    xhigh)
      somaxconn=65535; netdev_backlog=250000; syn_backlog=65535
      rmem_max=$((256*1024*1024)); wmem_max=$((256*1024*1024))
      rmem_def=$((64*1024*1024));  wmem_def=$((64*1024*1024))
      tcp_rmem="4096 87380 ${rmem_max}"
      tcp_wmem="4096 65536 ${wmem_max}"
      swappiness=10
      nofile_profile=524288
      tw_profile=250000
      ct_min=262144;  ct_cap=524288
      ;;
    2xhigh)
      somaxconn=65535; netdev_backlog=350000; syn_backlog=65535
      rmem_max=$((384*1024*1024)); wmem_max=$((384*1024*1024))
      rmem_def=$((96*1024*1024));  wmem_def=$((96*1024*1024))
      tcp_rmem="4096 87380 ${rmem_max}"
      tcp_wmem="4096 65536 ${wmem_max}"
      swappiness=10
      nofile_profile=1048576
      tw_profile=350000
      ct_min=524288;  ct_cap=1048576
      ;;
    dedicated)
      somaxconn=65535; netdev_backlog=500000; syn_backlog=65535
      rmem_max=$((512*1024*1024)); wmem_max=$((512*1024*1024))
      rmem_def=$((128*1024*1024)); wmem_def=$((128*1024*1024))
      tcp_rmem="4096 87380 ${rmem_max}"
      tcp_wmem="4096 65536 ${wmem_max}"
      swappiness=10
      nofile_profile=2097152
      tw_profile=600000
      ct_min=1048576; ct_cap=2097152
      ;;
    dedicated+)
      somaxconn=65535; netdev_backlog=700000; syn_backlog=65535
      rmem_max=$((768*1024*1024)); wmem_max=$((768*1024*1024))
      rmem_def=$((192*1024*1024)); wmem_def=$((192*1024*1024))
      tcp_rmem="4096 87380 ${rmem_max}"
      tcp_wmem="4096 65536 ${wmem_max}"
      swappiness=10
      nofile_profile=4194304
      tw_profile=900000
      ct_min=2097152; ct_cap=4194304
      ;;
  esac

  # Never decrease: current as floor
  local current_ct current_tw current_nofile
  current_ct="$(to_int "$B_CT_MAX")"
  current_tw="$(to_int "$B_TW")"
  current_nofile="$(to_int "$B_NOFILE")"

  local nofile_final tw_final
  nofile_final="$(imax "$current_nofile" "$nofile_profile")"
  tw_final="$(imax "$current_tw" "$tw_profile")"

  # Conntrack: compute -> clamp -> never-decrease
  local ct_soft ct_clamped ct_final
  ct_soft="$(ct_soft_from_ram_cpu "$mem_mb" "$cpu")"
  ct_clamped="$(clamp "$ct_soft" "$ct_min" "$ct_cap")"
  ct_final="$(imax "$current_ct" "$ct_clamped")"
  local ct_buckets=$((ct_final/4)); [[ "$ct_buckets" -lt 4096 ]] && ct_buckets=4096

  # ---- swap sizing ----
  backup_file /etc/fstab
  local swap_gb=2
  if   [[ "$mem_mb" -lt 2048  ]]; then swap_gb=1
  elif [[ "$mem_mb" -lt 4096  ]]; then swap_gb=2
  elif [[ "$mem_mb" -lt 8192  ]]; then swap_gb=4
  elif [[ "$mem_mb" -lt 16384 ]]; then swap_gb=6
  else swap_gb=8
  fi

  local swap_target_mb=$((swap_gb * 1024))
  local swap_total_mb; swap_total_mb="$(awk '/SwapTotal:/ {print int($2/1024)}' /proc/meminfo)"
  local has_swap_partition="0"
  if /sbin/swapon --show=TYPE 2>/dev/null | grep -q '^partition$'; then
    has_swap_partition="1"
  fi

  if [[ "$has_swap_partition" == "0" ]]; then
    local need_swapfile="0"
    if [[ "$swap_total_mb" -eq 0 ]]; then
      need_swapfile="1"
    else
      # If swap exists but differs too much from target
      local diff=$(( swap_total_mb > swap_target_mb ? swap_total_mb - swap_target_mb : swap_target_mb - swap_total_mb ))
      [[ "$diff" -ge 256 ]] && need_swapfile="1"
    fi

    if [[ "$need_swapfile" == "1" ]]; then
      /sbin/swapoff /swapfile 2>/dev/null || true
      rm -f /swapfile
      if command -v fallocate >/dev/null 2>&1; then
        fallocate -l "${swap_gb}G" /swapfile
      else
        dd if=/dev/zero of=/swapfile bs=1M count="$swap_target_mb" status=none
      fi
      chmod 600 /swapfile
      mkswap /swapfile >/dev/null
      /sbin/swapon /swapfile
      if ! grep -qE '^\s*/swapfile\s+none\s+swap\s' /etc/fstab; then
        echo '/swapfile none swap sw 0 0' >> /etc/fstab
      fi
    fi
  fi

  # ---- sysctl ----
  backup_file /etc/sysctl.conf
  shopt -s nullglob
  for f in /etc/sysctl.d/*.conf; do
    [[ -f "$f" ]] || continue
    case "$f" in
      /etc/sysctl.d/90-edge-network.conf|/etc/sysctl.d/92-edge-safe.conf|/etc/sysctl.d/95-edge-forward.conf|/etc/sysctl.d/96-edge-vm.conf|/etc/sysctl.d/99-edge-conntrack.conf|/etc/sysctl.d/99-edge-tailscale.conf) continue ;;
    esac
    if grep -Eq 'nf_conntrack_|tcp_congestion_control|default_qdisc|ip_forward|somaxconn|netdev_max_backlog|tcp_rmem|tcp_wmem|rmem_max|wmem_max|vm\.swappiness|vfs_cache_pressure|tcp_syncookies|tcp_max_tw_buckets|tcp_keepalive|tcp_mtu_probing|tcp_fin_timeout|tcp_tw_reuse|tcp_slow_start_after_idle|tcp_rfc1337' "$f"; then
      move_aside "$f"
    fi
  done
  shopt -u nullglob

  if [[ -f /etc/sysctl.conf ]]; then
    sed -i -E \
      's/^\s*(net\.netfilter\.nf_conntrack_|net\.ipv4\.tcp_congestion_control|net\.core\.default_qdisc|net\.ipv4\.ip_forward|net\.core\.somaxconn|net\.core\.netdev_max_backlog|net\.ipv4\.tcp_(rmem|wmem)|net\.core\.(rmem|wmem)_(max|default)|vm\.swappiness|vm\.vfs_cache_pressure|net\.ipv4\.tcp_syncookies|net\.ipv4\.tcp_max_tw_buckets|net\.ipv4\.tcp_(keepalive_time|keepalive_intvl|keepalive_probes)|net\.ipv4\.tcp_rfc1337)/# \0/' \
      /etc/sysctl.conf || true
  fi

  modprobe nf_conntrack >/dev/null 2>&1 || true
  mkdir -p /etc/modules-load.d
  backup_file /etc/modules-load.d/edge-conntrack.conf
  echo nf_conntrack > /etc/modules-load.d/edge-conntrack.conf

  cat > /etc/sysctl.d/90-edge-network.conf <<EOM
net.core.default_qdisc = fq
net.ipv4.tcp_congestion_control = bbr
net.core.somaxconn = ${somaxconn}
net.core.netdev_max_backlog = ${netdev_backlog}
net.ipv4.tcp_max_syn_backlog = ${syn_backlog}
net.core.rmem_max = ${rmem_max}
net.core.wmem_max = ${wmem_max}
net.core.rmem_default = ${rmem_def}
net.core.wmem_default = ${wmem_def}
net.ipv4.tcp_rmem = ${tcp_rmem}
net.ipv4.tcp_wmem = ${tcp_wmem}
net.ipv4.tcp_fastopen = 3
net.ipv4.tcp_fin_timeout = 10
net.ipv4.tcp_tw_reuse = 1
net.ipv4.tcp_slow_start_after_idle = 0
net.ipv4.tcp_mtu_probing = 1
net.ipv4.udp_rmem_min = 8192
net.ipv4.udp_wmem_min = 8192
EOM

  echo "net.ipv4.ip_forward = 1" > /etc/sysctl.d/95-edge-forward.conf

  cat > /etc/sysctl.d/96-edge-vm.conf <<EOM
vm.swappiness = ${swappiness}
vm.vfs_cache_pressure = 50
EOM

  cat > /etc/sysctl.d/99-edge-conntrack.conf <<EOM
net.netfilter.nf_conntrack_max = ${ct_final}
net.netfilter.nf_conntrack_buckets = ${ct_buckets}
net.netfilter.nf_conntrack_tcp_timeout_established = 900
net.netfilter.nf_conntrack_tcp_timeout_time_wait = 15
net.netfilter.nf_conntrack_udp_timeout = 30
net.netfilter.nf_conntrack_udp_timeout_stream = 60
EOM

  cat > /etc/sysctl.d/92-edge-safe.conf <<EOM
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_max_tw_buckets = ${tw_final}
net.ipv4.tcp_rfc1337 = 1
net.ipv4.tcp_keepalive_time = 600
net.ipv4.tcp_keepalive_intvl = 30
net.ipv4.tcp_keepalive_probes = 5
EOM

  sysctl --system >/dev/null 2>&1 || true

  # ---- NOFILE ----
  mkdir -p /etc/systemd/system.conf.d
  shopt -s nullglob
  for f in /etc/systemd/system.conf.d/*.conf; do
    [[ "$f" == "/etc/systemd/system.conf.d/90-edge.conf" ]] && continue
    grep -qE '^\s*DefaultLimitNOFILE\s*=' "$f" && move_aside "$f"
  done
  shopt -u nullglob

  cat > /etc/systemd/system.conf.d/90-edge.conf <<EOM
[Manager]
DefaultLimitNOFILE=${nofile_final}
EOM

  mkdir -p /etc/security/limits.d
  shopt -s nullglob
  for f in /etc/security/limits.d/*.conf; do
    [[ "$f" == "/etc/security/limits.d/90-edge.conf" ]] && continue
    grep -qE '^\s*[*a-zA-Z0-9._-]+\s+(soft|hard)\s+nofile\s+' "$f" && move_aside "$f"
  done
  shopt -u nullglob

  cat > /etc/security/limits.d/90-edge.conf <<EOM
* soft nofile ${nofile_final}
* hard nofile ${nofile_final}
root soft nofile ${nofile_final}
root hard nofile ${nofile_final}
EOM

  systemctl daemon-reexec >/dev/null 2>&1 || true

  # ---- journald ----
  mkdir -p /etc/systemd/journald.conf.d
  shopt -s nullglob
  for f in /etc/systemd/journald.conf.d/*.conf; do
    [[ "$f" == "/etc/systemd/journald.conf.d/90-edge.conf" ]] && continue
    move_aside "$f"
  done
  shopt -u nullglob

  cat > /etc/systemd/journald.conf.d/90-edge.conf <<EOM
[Journal]
Compress=yes
SystemMaxUse=${j_system}
RuntimeMaxUse=${j_runtime}
RateLimitIntervalSec=30s
RateLimitBurst=1000
EOM
  systemctl restart systemd-journald >/dev/null 2>&1 || true

  # ---- unattended-upgrades ----
  mkdir -p /etc/apt/apt.conf.d
  backup_file /etc/apt/apt.conf.d/99-edge-unattended.conf
  cat > /etc/apt/apt.conf.d/99-edge-unattended.conf <<'EOM'
Unattended-Upgrade::Automatic-Reboot "false";
Unattended-Upgrade::Automatic-Reboot-Time "04:00";
EOM

  # ---- logrotate ----
  backup_file /etc/logrotate.conf
  cat > /etc/logrotate.conf <<EOM
daily
rotate ${logrotate_rotate}
compress
delaycompress
missingok
notifempty
create
su root adm
include /etc/logrotate.d
EOM

  mkdir -p /etc/logrotate.d
  backup_file /etc/logrotate.d/edge-all-text-logs
  cat > /etc/logrotate.d/edge-all-text-logs <<EOM
/var/log/syslog
/var/log/kern.log
/var/log/auth.log
/var/log/daemon.log
/var/log/user.log
/var/log/messages
/var/log/dpkg.log
/var/log/apt/history.log
/var/log/apt/term.log
/var/log/*.log
/var/log/*/*.log
/var/log/*/*/*.log
/var/log/*.out
/var/log/*/*.out
/var/log/*.err
/var/log/*/*.err
{
  daily
  rotate ${logrotate_rotate}
  compress
  delaycompress
  missingok
  notifempty
  copytruncate
  sharedscripts
  postrotate
    systemctl kill -s HUP rsyslog.service >/dev/null 2>&1 || true
  endscript
}
EOM

  # ---- tmpfiles ----
  mkdir -p /etc/tmpfiles.d
  backup_file /etc/tmpfiles.d/edge-tmp.conf
  cat > /etc/tmpfiles.d/edge-tmp.conf <<'EOM'
D /tmp            1777 root root 7d
D /var/tmp        1777 root root 14d
EOM
  systemd-tmpfiles --create >/dev/null 2>&1 || true

  snapshot_after

  ok "tuning applied (profile ${profile}, tier ${tier})"
}

###############################################################################
# SSH hardening
###############################################################################
ssh_harden_apply() {
  hdr "🔐 SSH hardening"
  local cfg="/etc/ssh/sshd_config"
  [[ -f "$cfg" ]] || { warn "sshd_config not found, skipping"; return 0; }

  backup_file "$cfg"

  sed -i 's/^[[:space:]]*#\?[[:space:]]*PasswordAuthentication[[:space:]].*/PasswordAuthentication no/' "$cfg" || true
  sed -i 's/^[[:space:]]*#\?[[:space:]]*PermitRootLogin[[:space:]].*/PermitRootLogin no/' "$cfg" || true

  grep -qi '^[[:space:]]*PasswordAuthentication[[:space:]]' "$cfg" || echo 'PasswordAuthentication no' >> "$cfg"
  grep -qi '^[[:space:]]*PermitRootLogin[[:space:]]' "$cfg" || echo 'PermitRootLogin no' >> "$cfg"

  systemctl restart ssh 2>/dev/null || systemctl restart sshd 2>/dev/null || true
  ok "SSH hardening applied"
}

###############################################################################
# UFW (WAN only 443, Tailscale allow all)
###############################################################################
ufw_apply() {
  hdr "🧱 Firewall (UFW)"

  if ! command -v ufw >/dev/null 2>&1; then
    aptq "Install UFW" install ufw
  fi

  local wan_iface
  wan_iface="$(ip route get 8.8.8.8 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="dev"){print $(i+1); exit}}' || true)"
  [[ -n "$wan_iface" ]] || wan_iface="$(ip route show default 2>/dev/null | awk '/default/ {print $5; exit}' || true)"

  [[ -n "$wan_iface" ]] || die "Failed to detect WAN interface for UFW"

  # Forward policy
  backup_file /etc/default/ufw || true
  if [[ -f /etc/default/ufw ]]; then
    if grep -q '^DEFAULT_FORWARD_POLICY=' /etc/default/ufw; then
      sed -i 's/^DEFAULT_FORWARD_POLICY=.*/DEFAULT_FORWARD_POLICY="ACCEPT"/' /etc/default/ufw || true
    else
      echo 'DEFAULT_FORWARD_POLICY="ACCEPT"' >> /etc/default/ufw
    fi
  fi

  ufw --force reset >/dev/null 2>&1 || true
  ufw default deny incoming >/dev/null 2>&1 || true
  ufw default allow outgoing >/dev/null 2>&1 || true

  # WAN only 443
  ufw allow in on "$wan_iface" to any port 443 proto tcp >/dev/null 2>&1 || true
  ufw allow in on "$wan_iface" to any port 443 proto udp >/dev/null 2>&1 || true
  ok "WAN (${wan_iface}): allow 443/tcp, 443/udp"

  # Tailscale all
  ufw allow in on tailscale0 >/dev/null 2>&1 || true
  ufw allow out on tailscale0 >/dev/null 2>&1 || true
  ok "Tailscale (tailscale0): allow all (in/out)"

  # Docker bridges (so local container networks don't get weird)
  local ifs
  ifs="$(ip -o link show | awk -F': ' '$2 ~ /^(docker0|br-)/ {print $2}' || true)"
  if [[ -n "$ifs" ]]; then
    local i
    for i in $ifs; do
      ufw allow in on "$i" >/dev/null 2>&1 || true
      ufw allow out on "$i" >/dev/null 2>&1 || true
    done
    ok "Docker bridges: allow all (in/out)"
  fi

  mkdir -p /etc/cron.d
  install -m 0644 /dev/stdin /etc/cron.d/enable-ufw <<'EOF'
@reboot root ufw --force enable && ufw reload
EOF

  ufw --force enable >/dev/null 2>&1 || true
  ok "ufw enabled"
}

###############################################################################
# iperf3 server (optional)
###############################################################################
iperf3_server_apply() {
  hdr "📡 iperf3 server"
  if ! command -v iperf3 >/dev/null 2>&1; then
    aptq "Install iperf3" install iperf3
  fi

  backup_file /etc/systemd/system/iperf3.service || true
  cat > /etc/systemd/system/iperf3.service <<'EOF'
[Unit]
Description=iperf3 server
After=network.target

[Service]
ExecStart=/usr/bin/iperf3 -s
Restart=always
User=root

[Install]
WantedBy=multi-user.target
EOF

  systemctl daemon-reload >/dev/null 2>&1 || true
  systemctl enable --now iperf3 >/dev/null 2>&1 || true
  ok "iperf3 service enabled"
}

###############################################################################
# remnanode (optional) - ask early only if compose missing
###############################################################################
remnanode_early_inputs_if_needed() {
  local compose="/opt/remnanode/docker-compose.yml"
  if [[ -f "$compose" ]]; then
    ok "remnanode compose exists: ${compose} (skip early inputs)"
    return 0
  fi

  hdr "🧩 remnanode inputs (early)"
  read_tty NODE_PORT "NODE_PORT for remnanode (default 2222): "
  [[ -n "${NODE_PORT:-}" ]] || NODE_PORT="2222"

  read_tty_silent SECRET_KEY "Paste SECRET_KEY (input hidden): "
  [[ -n "${SECRET_KEY:-}" ]] || die "SECRET_KEY is empty"

  ok "remnanode params collected"
}

remnanode_apply() {
  hdr "🧩 remnanode"
  docker_install_if_needed

  local dir="/opt/remnanode"
  local compose="${dir}/docker-compose.yml"

  if [[ -f "$compose" ]]; then
    ok "remnanode compose exists: ${compose}"
  else
    [[ -n "${NODE_PORT:-}" ]] || NODE_PORT="2222"
    [[ -n "${SECRET_KEY:-}" ]] || die "remnanode compose missing and SECRET_KEY empty"

    mkdir -p "$dir"
    cat > "$compose" <<EOF
services:
  remnanode:
    container_name: remnanode
    hostname: remnanode
    image: remnawave/node:latest
    network_mode: host
    restart: always
    ulimits:
      nofile:
        soft: 1048576
        hard: 1048576
    environment:
      - NODE_PORT=${NODE_PORT}
      - SECRET_KEY=${SECRET_KEY}
EOF
    ok "remnanode compose created: ${compose}"
  fi

  (cd "$dir" && docker compose up -d) >/dev/null 2>&1 || true
  ok "remnanode started"
}

remnanode_status_line() {
  if command -v docker >/dev/null 2>&1 && docker ps --format '{{.Names}}' | grep -qx remnanode; then
    docker ps --filter name=remnanode --format 'remnanode {{.Status}}' 2>/dev/null || true
  else
    echo "-"
  fi
}

###############################################################################
# Reboot handler
###############################################################################
schedule_reboot() {
  local v="$1"
  case "$v" in
    0|no|none|skip|"")
      warn "Reboot disabled (--reboot=${v:-skip})"
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
      warn "Reboot in ${v}"
      shutdown -r +"${v}" >/dev/null 2>&1 || shutdown -r now
      ;;
  esac
}

###############################################################################
# CLI parsing
###############################################################################
usage() {
  cat <<EOF
Usage:
  sudo ./${SCRIPT_NAME} {apply|rollback|status} [flags]

Flags:
  --user <name>            Create/ensure this user (if omitted in apply -> asks)
  --tailscale=0|1          Enable tailscale flow (default: ask in interactive)
  --dns-switcher=0|1       Apply DNS switcher early (default: ask in interactive)
  --dns-profile=N          DNS profile 1..5 (default: 1)
  --remnanode=0|1          Install/run remnanode (default: ask in interactive)
  --ssh-harden=0|1         Apply SSH hardening (default: ask in interactive)
  --open-wan-443=0|1       Open WAN only 443 in UFW (default: ask in interactive)
  --iperf3-server=0|1      Enable iperf3 systemd server (default: ask in interactive)
  --reboot=<delay|skip>    Example: 5m (default in interactive), or skip/none/0

Examples:
  sudo ./${SCRIPT_NAME} apply
  sudo ./${SCRIPT_NAME} apply --reboot=skip --tailscale=1 --dns-switcher=1 --dns-profile=1 --remnanode=1 --ssh-harden=1 --open-wan-443=1 --user myuser
  sudo BACKUP_DIR=/root/edge-tuning-backup-YYYYmmdd-HHMMSS ./${SCRIPT_NAME} rollback
EOF
}

parse_args_apply() {
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --user) ARG_USER="${2:-}"; shift 2 ;;
      --user=*) ARG_USER="${1#*=}"; shift ;;
      --tailscale=*) ARG_TAILSCALE="${1#*=}"; shift ;;
      --dns-switcher=*) ARG_DNS_SWITCHER="${1#*=}"; shift ;;
      --dns-profile=*) ARG_DNS_PROFILE="${1#*=}"; shift ;;
      --remnanode=*) ARG_REMNANODE="${1#*=}"; shift ;;
      --ssh-harden=*) ARG_SSH_HARDEN="${1#*=}"; shift ;;
      --open-wan-443=*) ARG_OPEN_WAN_443="${1#*=}"; shift ;;
      --iperf3-server=*) ARG_IPERF3_SERVER="${1#*=}"; shift ;;
      --reboot=*) ARG_REBOOT="${1#*=}"; shift ;;
      *)
        die "Unknown arg: $1"
        ;;
    esac
  done
}

###############################################################################
# Apply / rollback / status
###############################################################################
on_apply_fail() {
  local code=$?
  err "Apply failed (exit code=$code)."
  warn "Rollback: sudo BACKUP_DIR=$backup_dir ./${SCRIPT_NAME} rollback"
  exit "$code"
}

apply_cmd() {
  need_root "$@"
  confirm
  trap on_apply_fail ERR

  mkdir -p /var/log
  : >"$ERR_LOG"

  mkbackup
  snapshot_before

  print_start_end_banner "🏁 Start"

  # Minimal base packages (also for geo parsing)
  ensure_packages "Install base packages" \
    curl wget ca-certificates gnupg lsb-release apt-transport-https \
    jq iproute2 ethtool openssl logrotate cron ufw iperf3 git zsh

  systemctl enable --now cron >/dev/null 2>&1 || true

  # Timezone
  hdr "🕒 Timezone"
  local tz="${TIMEZONE:-$TIMEZONE_DEFAULT}"
  backup_file /etc/localtime || true
  ln -sf "/usr/share/zoneinfo/${tz}" /etc/localtime >/dev/null 2>&1 || true
  timedatectl set-timezone "${tz}" >/dev/null 2>&1 || true
  ok "Timezone set to ${tz}"

  # Interactive defaults
  if [[ -z "${ARG_REBOOT:-}" ]]; then
    # in interactive mode, default is 5m (user can change)
    ARG_REBOOT="5m"
  fi

  if [[ -z "${ARG_DNS_PROFILE:-}" ]]; then
    ARG_DNS_PROFILE="1"
  fi

  # Ask missing toggles
  if [[ -z "${ARG_TAILSCALE:-}" ]]; then
    if ask_yn_default_yes "Enable Tailscale?"; then ARG_TAILSCALE="1"; else ARG_TAILSCALE="0"; fi
  fi
  if [[ -z "${ARG_DNS_SWITCHER:-}" ]]; then
    if ask_yn_default_yes "Apply DNS switcher (systemd-resolved) early?"; then ARG_DNS_SWITCHER="1"; else ARG_DNS_SWITCHER="0"; fi
  fi
  if [[ -z "${ARG_REMNANODE:-}" ]]; then
    if ask_yn_default_yes "Install/run remnanode?"; then ARG_REMNANODE="1"; else ARG_REMNANODE="0"; fi
  fi
  if [[ -z "${ARG_SSH_HARDEN:-}" ]]; then
    if ask_yn_default_no "Apply SSH hardening (PasswordAuth no + PermitRootLogin no)?"; then ARG_SSH_HARDEN="1"; else ARG_SSH_HARDEN="0"; fi
  fi
  if [[ -z "${ARG_OPEN_WAN_443:-}" ]]; then
    if ask_yn_default_yes "Enable UFW and open WAN only 443?"; then ARG_OPEN_WAN_443="1"; else ARG_OPEN_WAN_443="0"; fi
  fi
  if [[ -z "${ARG_IPERF3_SERVER:-}" ]]; then
    if ask_yn_default_no "Enable iperf3 server (systemd service)?"; then ARG_IPERF3_SERVER="1"; else ARG_IPERF3_SERVER="0"; fi
  fi

  # remnanode early inputs (only if requested AND compose absent)
  if [[ "${ARG_REMNANODE}" == "1" ]]; then
    remnanode_early_inputs_if_needed
  fi

  # DNS switcher early (auto-yes, no prompt)
  if [[ "${ARG_DNS_SWITCHER}" == "1" ]]; then
    dns_apply "${ARG_DNS_PROFILE}"
  else
    hdr "🌐 DNS switcher (early)"
    warn "dns-switcher disabled (--dns-switcher=0)"
  fi

  # Tailscale early (before anything else that depends on it)
  if [[ "${ARG_TAILSCALE}" == "1" ]]; then
    tailscale_up_flow
  else
    hdr "🧠 Tailscale (early)"
    warn "tailscale disabled (--tailscale=0)"
  fi

  # Docker (often needed for remnanode)
  docker_install_if_needed

  # User + zsh for all /home/*
  ensure_user
  zsh_for_all_users

  # Kernel/system tuning (single place; no duplicate later)
  tuning_apply

  # SSH hardening
  if [[ "${ARG_SSH_HARDEN}" == "1" ]]; then
    ssh_harden_apply
  else
    hdr "🔐 SSH hardening"
    warn "SSH hardening disabled (--ssh-harden=0)"
  fi

  # UFW
  if [[ "${ARG_OPEN_WAN_443}" == "1" ]]; then
    ufw_apply
  else
    hdr "🧱 Firewall (UFW)"
    warn "UFW not changed (--open-wan-443=0)"
  fi

  # iperf3 server
  if [[ "${ARG_IPERF3_SERVER}" == "1" ]]; then
    iperf3_server_apply
  else
    hdr "📡 iperf3 server"
    warn "iperf3 server disabled (--iperf3-server=0)"
  fi

  # remnanode
  if [[ "${ARG_REMNANODE}" == "1" ]]; then
    remnanode_apply
  else
    hdr "🧩 remnanode"
    warn "remnanode disabled (--remnanode=0)"
  fi

  # Autoremove
  hdr "🧹 Autoremove"
  aptq "Autoremove" autoremove --purge || true

  # Final snapshots
  snapshot_after
  print_start_end_banner "🏁 End"

  print_before_after_all
  print_manifest_compact "$manifest"

  # Remnanode status line for summary
  local remna_state remna_compose pass_line
  remna_state="$(remnanode_status_line)"
  remna_compose="/opt/remnanode/docker-compose.yml"
  [[ -f "$remna_compose" ]] || remna_compose="-"

  if [[ -n "${PASS_GEN:-}" ]]; then
    pass_line="${PASS_GEN}"
  else
    pass_line="(unchanged)"
  fi

  # Refresh tailscale ids for summary (in case it came up mid-run)
  if command -v tailscale >/dev/null 2>&1; then
    tailscale_collect_ids || true
  fi

  print_summary_table "$remna_state" "$remna_compose" "$pass_line"
  print_backup_logs_table

  schedule_reboot "${ARG_REBOOT}"
}

rollback_cmd() {
  need_root "$@"

  local backup="${BACKUP_DIR:-}"
  [[ -n "$backup" ]] || backup="$(latest_backup_dir)"
  [[ -n "$backup" && -d "$backup" ]] || die "Backup not found. Set BACKUP_DIR=/root/edge-tuning-backup-... or run apply first."

  snapshot_before

  rm -f /etc/sysctl.d/90-edge-network.conf \
        /etc/sysctl.d/92-edge-safe.conf \
        /etc/sysctl.d/95-edge-forward.conf \
        /etc/sysctl.d/96-edge-vm.conf \
        /etc/sysctl.d/99-edge-conntrack.conf \
        /etc/sysctl.d/99-edge-tailscale.conf \
        /etc/modules-load.d/edge-conntrack.conf \
        /etc/systemd/system.conf.d/90-edge.conf \
        /etc/security/limits.d/90-edge.conf \
        /etc/systemd/journald.conf.d/90-edge.conf \
        /etc/apt/apt.conf.d/99-edge-unattended.conf \
        /etc/logrotate.d/edge-all-text-logs \
        /etc/tmpfiles.d/edge-tmp.conf 2>/dev/null || true

  restore_manifest "$backup"

  # swapfile cleanup if we created/changed it
  if /sbin/swapon --show=NAME 2>/dev/null | grep -qx '/swapfile'; then
    /sbin/swapoff /swapfile 2>/dev/null || true
  fi
  sed -i -E '/^\s*\/swapfile\s+none\s+swap\s+/d' /etc/fstab 2>/dev/null || true
  rm -f /swapfile 2>/dev/null || true

  sysctl --system >/dev/null 2>&1 || true
  systemctl daemon-reexec >/dev/null 2>&1 || true
  systemctl restart systemd-journald >/dev/null 2>&1 || true

  snapshot_after

  ok "Rolled back. Backup used: $backup"
  hdr "Run"
  row_kv "Host"   "$(hostname -s 2>/dev/null || hostname)"
  row_kv "Mode"   "rollback"
  row_kv "Backup" "$backup"

  print_before_after_all
  print_manifest_compact "${backup}/MANIFEST.tsv"
}

status_cmd() {
  snapshot_before
  fetch_wan_info || true
  if command -v tailscale >/dev/null 2>&1; then tailscale_collect_ids || true; fi

  hdr "📍 Current status"
  row_kv "Host"        "$HOST_SHORT"
  row_kv "WAN"         "${WAN_FLAG} ${WAN_IP:-?}"
  row_kv "Geo"         "${WAN_CITY:-?}, ${WAN_REGION:-?}, ${WAN_COUNTRY_CODE:-?}"
  row_kv "Provider"    "${WAN_ASN:-?} ${WAN_ORG:-?}"
  row_kv "Tailscale IP" "${TS_IP:-"-"}"
  row_kv "MagicDNS"    "${TS_DNS:-"-"}"
  echo
  row_kv "TCP"        "$B_TCP_CC"
  row_kv "Qdisc"      "$B_QDISC"
  row_kv "Forward"    "$B_FWD"
  row_kv "Conntrack"  "$B_CT_MAX"
  row_kv "TW buckets" "$B_TW"
  row_kv "Swappiness" "$B_SWAPPINESS"
  row_kv "Swap"       "$B_SWAP"
  row_kv "Nofile"     "$B_NOFILE"
  row_kv "Journald"   "$B_JOURNAL"
  row_kv "Logrotate"  "$B_LOGROT"
  row_kv "AutoReboot" "$(_unattended_state "$B_UNATT")"
  row_kv "RebootTime" "$(_unattended_time "$B_UNATT")"
  echo
  row_kv "remnanode" "$(remnanode_status_line)"
}

###############################################################################
# Main
###############################################################################
main() {
  case "${1:-}" in
    apply)
      shift
      parse_args_apply "$@"
      apply_cmd
      ;;
    rollback)
      shift
      rollback_cmd "$@"
      ;;
    status)
      shift
      status_cmd "$@"
      ;;
    *)
      usage
      exit 1
      ;;
  esac
}

main "$@"
