#!/usr/bin/env bash
set -Eeuo pipefail

###############################################################################
# VPS Edge Router / Node Bootstrap Script
#
# ABSOLUTELY NO WARRANTY:
# This script modifies system settings (kernel/sysctl, SSH, firewall, logs, etc).
# You run it at your own risk. It may break networking, access (SSH), services,
# or performance depending on your environment. Always test on a fresh VM first.
###############################################################################

###############################################################################
# Goals (apply):
# - DNS switcher (optional, early)
# - Tailscale (optional, early; idempotent; safe waiting for Running+IPv4)
# - Node Exporter install (optional; runs "in background" from script POV)
# - Docker + remnanode (optional)
# - Zsh stack for all /home/* users + root (optional-ish, enabled by default)
# - Kernel/system tuning with backup+rollback
# - UFW: WAN only 443 (optional), Tailscale allow-all, Docker bridges allow-all
# - iperf3 server enabled always
#
# Commands:
#   apply    apply tuning and create a backup
#   rollback undo changes using a backup
#   status   show current tuning state
#
# Works best on:
# - Ubuntu 20.04/22.04/24.04 LTS (tested)
# - Debian 11/12 should mostly work, but unattended-upgrades/pam paths may differ.
###############################################################################

###############################################################################
# Logging + colors
###############################################################################
LOG_TS="${EDGE_LOG_TS:-1}"
ts() { [[ "$LOG_TS" == "1" ]] && date +"%Y-%m-%d %H:%M:%S" || true; }
_is_tty() { [[ -t 1 ]]; }
_has_dev_tty() { [[ -r /dev/tty && -w /dev/tty ]]; }

c_reset=$'\033[0m'
c_dim=$'\033[2m'
c_bold=$'\033[1m'
c_red=$'\033[31m'
c_yel=$'\033[33m'
c_grn=$'\033[32m'
c_cyan=$'\033[36m'

color() { local code="$1"; shift; if _is_tty; then printf "%s%s%s" "$code" "$*" "$c_reset"; else printf "%s" "$*"; fi; }
_pfx() { _is_tty && printf "%s%s%s" "${c_dim}" "$(ts) " "${c_reset}" || true; }
ok()   { _pfx; color "$c_grn" "✅ OK";    printf " %s\n" "$*"; }
info() { _pfx; color "$c_cyan" "ℹ️ ";     printf " %s\n" "$*"; }
warn() { _pfx; color "$c_yel" "⚠️  WARN"; printf " %s\n" "$*"; }
err()  { _pfx; color "$c_red" "🛑 ERROR"; printf " %s\n" "$*"; }
die()  { err "$*"; exit 1; }

hdr() { echo; color "$c_bold$c_cyan" "$*"; echo; }
host_short() { hostname -s 2>/dev/null || hostname; }

###############################################################################
# Root / sudo
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
# TTY input helpers (works even when piped)
###############################################################################
read_tty() {
  local __var="$1" __prompt="$2" __v=""
  if _has_dev_tty; then
    read -rp "$__prompt" __v </dev/tty || true
    printf -v "$__var" '%s' "$__v"
    return 0
  fi
  printf -v "$__var" '%s' ""
  return 0
}

read_tty_silent() {
  local __var="$1" __prompt="$2" __v=""
  if _has_dev_tty; then
    read -rsp "$__prompt" __v </dev/tty || true
    echo >/dev/tty || true
    printf -v "$__var" '%s' "$__v"
    return 0
  fi
  printf -v "$__var" '%s' ""
  return 0
}

###############################################################################
# Backup + manifest (for rollback)
###############################################################################
backup_dir=""
moved_dir=""
manifest=""

mkbackup() {
  local tsd="${BACKUP_TS:-${EDGE_BACKUP_TS:-}}"
  [[ -n "$tsd" ]] || tsd="$(date +%Y%m%d-%H%M%S)"
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

latest_backup_dir() { ls -1dt /root/edge-tuning-backup-* 2>/dev/null | head -n1 || true; }

###############################################################################
# Numeric helpers
###############################################################################
to_int() { local s="${1:-}"; [[ "$s" =~ ^[0-9]+$ ]] && echo "$s" || echo 0; }
clamp() { local v lo hi; v="$(to_int "${1:-0}")"; lo="$(to_int "${2:-0}")"; hi="$(to_int "${3:-0}")"; [[ "$v" -lt "$lo" ]] && v="$lo"; [[ "$v" -gt "$hi" ]] && v="$hi"; echo "$v"; }

###############################################################################
# Geo/ISP helpers (best-effort)
###############################################################################
country_flag() {
  local cc="${1:-}"; cc="${cc^^}"
  if [[ ! "$cc" =~ ^[A-Z]{2}$ ]]; then printf "🏳️"; return 0; fi
  awk -v cc="$cc" 'BEGIN{
    o1 = ord(substr(cc,1,1)); o2 = ord(substr(cc,2,1));
    cp1 = 0x1F1E6 + o1 - 65; cp2 = 0x1F1E6 + o2 - 65;
    printf "%c%c", cp1, cp2
  }
  function ord(c){ return index("ABCDEFGHIJKLMNOPQRSTUVWXYZ", c)-1 + 65 }'
}

ext_ip() {
  curl -fsSL --max-time 3 https://api.ipify.org 2>/dev/null \
    || curl -fsSL --max-time 3 ifconfig.me 2>/dev/null \
    || true
}

geo_lookup() {
  # Outputs: COUNTRY_CODE|COUNTRY|REGION|CITY|ORG
  local ip="${1:-}"
  local out=""

  out="$(curl -fsSL --max-time 3 "https://ipinfo.io/${ip}/json" 2>/dev/null || true)"
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

  out="$(curl -fsSL --max-time 3 "http://ip-api.com/json/${ip}?fields=status,countryCode,country,regionName,city,as,isp,org" 2>/dev/null || true)"
  if [[ -n "$out" ]]; then
    local status cc country region city as isp org provider
    status="$(printf "%s" "$out" | jq -r '.status // empty' 2>/dev/null || true)"
    if [[ "$status" == "success" ]]; then
      cc="$(printf "%s" "$out" | jq -r '.countryCode // empty' 2>/dev/null || true)"
      country="$(printf "%s" "$out" | jq -r '.country // empty' 2>/dev/null || true)"
      region="$(printf "%s" "$out" | jq -r '.regionName // empty' 2>/dev/null || true)"
      city="$(printf "%s" "$out" | jq -r '.city // empty' 2>/dev/null || true)"
      as="$(printf "%s" "$out" | jq -r '.as // empty' 2>/dev/null || true)"
      isp="$(printf "%s" "$out" | jq -r '.isp // empty' 2>/dev/null || true)"
      org="$(printf "%s" "$out" | jq -r '.org // empty' 2>/dev/null || true)"

      # FIX: safe "first non-empty"
      provider="$as"
      [[ -n "$provider" ]] || provider="$org"
      [[ -n "$provider" ]] || provider="$isp"

      printf "%s|%s|%s|%s|%s" "${cc:-}" "${country:-}" "${region:-}" "${city:-}" "${provider:-}"
      return 0
    fi
  fi

  printf "||||"
}

###############################################################################
# Snapshot helpers (before/after)
###############################################################################
_swap_state() {
  local s
  s="$(/sbin/swapon --noheadings --show=NAME,SIZE 2>/dev/null | awk '{$1=$1; print}' | tr '\n' ';' | sed 's/;$//' || true)"
  [[ -n "$s" ]] && echo "$s" || echo "none"
}
_nofile_systemd() { systemctl show --property DefaultLimitNOFILE 2>/dev/null | cut -d= -f2 || echo "-"; }
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
# Tier selection + disk-aware log caps
###############################################################################
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
ct_soft_from_ram_cpu() {
  local mem_mb="$1" cpu="$2"
  local ct=$(( mem_mb * 64 + cpu * 8192 ))
  [[ "$ct" -lt 32768 ]] && ct=32768
  echo "$ct"
}
disk_size_mb_for_logs() {
  local mb=""
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

###############################################################################
# Table helpers
###############################################################################
row_kv() { local k="$1" v="$2"; printf "%-14s | %s\n" "$k" "$v"; }

print_before_after_all() {
  hdr "🧾 Before → After (all)"
  printf "%-14s-+-%-32s-+-%-32s\n" "$(printf '%.0s-' {1..14})" "$(printf '%.0s-' {1..32})" "$(printf '%.0s-' {1..32})"

  row3() {
    local k="$1" b="$2" a="$3"
    if [[ "$b" != "$a" ]]; then
      printf "%-14s | %-32s | %-32s\n" "$k" "$(color "$c_grn" "$b")" "$(color "$c_grn" "$a")"
    else
      printf "%-14s | %-32s | %-32s\n" "$k" "$b" "$a"
    fi
  }

  row3 "TCP"         "$B_TCP_CC" "$A_TCP_CC"
  row3 "Qdisc"       "$B_QDISC" "$A_QDISC"
  row3 "Forward"     "$B_FWD" "$A_FWD"
  row3 "Conntrack"   "$B_CT_MAX" "$A_CT_MAX"
  row3 "TW buckets"  "$B_TW" "$A_TW"
  row3 "Swappiness"  "$B_SWAPPINESS" "$A_SWAPPINESS"
  row3 "Swap"        "$B_SWAP" "$A_SWAP"
  row3 "Nofile"      "$B_NOFILE" "$A_NOFILE"
  row3 "Journald"    "$B_JOURNAL" "$A_JOURNAL"
  row3 "Logrotate"   "$B_LOGROT" "$A_LOGROT"
  row3 "AutoReboot"  "$(_unattended_state "$B_UNATT")" "$(_unattended_state "$A_UNATT")"
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

###############################################################################
# Args + defaults
###############################################################################
CMD="${1:-}"; shift || true

ARG_USER=""
ARG_TIMEZONE="Europe/Moscow"
ARG_REBOOT="5m"

ARG_TAILSCALE=""         # 0/1; interactive if empty
ARG_DNS_SWITCHER=""      # 0/1; interactive if empty
ARG_DNS_PROFILE="1"      # 1..5
ARG_REMNANODE=""         # 0/1; interactive if empty
ARG_SSH_HARDEN=""        # 0/1; interactive if empty
ARG_OPEN_WAN_443=""      # 0/1; interactive if empty
ARG_NODE_EXPORTER=""     # 0/1; interactive if empty
ARG_ZSH_ALL_USERS=""     # 0/1; interactive if empty

NODE_PORT="${NODE_PORT:-}"
SECRET_KEY="${SECRET_KEY:-}"
SKIP_REMNANODE_INPUTS="0"

DNS_SWITCHER_URL="${DNS_SWITCHER_URL:-https://raw.githubusercontent.com/AndreyTimoschuk/dns-switcher/main/dns-switcher.sh}"

ZSHRC_URL="${ZSHRC_URL:-https://raw.githubusercontent.com/akadorkin/remnanode-install-script/refs/heads/main/main/zshrc}"
P10K_URL="${P10K_URL:-https://raw.githubusercontent.com/akadorkin/remnanode-install-script/refs/heads/main/main/p10k}"

NODE_EXPORTER_INSTALL_CMD='bash <(curl -fsSL raw.githubusercontent.com/hteppl/sh/master/node_install.sh)'

APT_LOG="/var/log/vps-edge-apt.log"
DNS_LOG="/var/log/vps-edge-dns-switcher.log"
TS_LOG="/var/log/vps-edge-tailscale.log"
DOCKER_LOG="/var/log/vps-edge-docker.log"
NODE_EXPORTER_LOG="/var/log/vps-edge-node-exporter.log"
ERR_LOG="/var/log/vps-edge-error.log"

touch "$APT_LOG" "$DNS_LOG" "$TS_LOG" "$DOCKER_LOG" "$NODE_EXPORTER_LOG" "$ERR_LOG" 2>/dev/null || true

while [[ $# -gt 0 ]]; do
  case "$1" in
    --user=*)          ARG_USER="${1#*=}"; shift ;;
    --timezone=*)      ARG_TIMEZONE="${1#*=}"; shift ;;
    --reboot=*)        ARG_REBOOT="${1#*=}"; shift ;;
    --tailscale=*)     ARG_TAILSCALE="${1#*=}"; shift ;;
    --dns-switcher=*)  ARG_DNS_SWITCHER="${1#*=}"; shift ;;
    --dns-profile=*)   ARG_DNS_PROFILE="${1#*=}"; shift ;;
    --remnanode=*)     ARG_REMNANODE="${1#*=}"; shift ;;
    --ssh-harden=*)    ARG_SSH_HARDEN="${1#*=}"; shift ;;
    --open-wan-443=*)  ARG_OPEN_WAN_443="${1#*=}"; shift ;;
    --node-exporter=*) ARG_NODE_EXPORTER="${1#*=}"; shift ;;
    --zsh-all-users=*) ARG_ZSH_ALL_USERS="${1#*=}"; shift ;;

    --user)          ARG_USER="${2:-}"; shift 2 ;;
    --timezone)      ARG_TIMEZONE="${2:-}"; shift 2 ;;
    --reboot)        ARG_REBOOT="${2:-}"; shift 2 ;;
    --tailscale)     ARG_TAILSCALE="${2:-}"; shift 2 ;;
    --dns-switcher)  ARG_DNS_SWITCHER="${2:-}"; shift 2 ;;
    --dns-profile)   ARG_DNS_PROFILE="${2:-}"; shift 2 ;;
    --remnanode)     ARG_REMNANODE="${2:-}"; shift 2 ;;
    --ssh-harden)    ARG_SSH_HARDEN="${2:-}"; shift 2 ;;
    --open-wan-443)  ARG_OPEN_WAN_443="${2:-}"; shift 2 ;;
    --node-exporter) ARG_NODE_EXPORTER="${2:-}"; shift 2 ;;
    --zsh-all-users) ARG_ZSH_ALL_USERS="${2:-}"; shift 2 ;;
    *) die "Unknown arg: $1" ;;
  esac
done

usage() {
  cat <<'EOF'
Usage:
  sudo ./vps-edge-run.sh apply [flags]
  sudo ./vps-edge-run.sh rollback [--backup-dir=/root/edge-tuning-backup-...]
  sudo ./vps-edge-run.sh status

Flags (apply):
  --user <name>                Create/ensure user (optional; interactive if omitted)
  --timezone <TZ>              Default: Europe/Moscow
  --reboot <5m|30s|skip|none>  Default: 5m

  --dns-switcher 0|1           Run DNS switcher early
  --dns-profile 1..5           DNS switcher profile (default: 1)

  --tailscale 0|1              Install/up tailscale early (no exit-node; no auth key)
  --node-exporter 0|1          Install Node Exporter using:
                                 bash <(curl -fsSL raw.githubusercontent.com/hteppl/sh/master/node_install.sh)

  --remnanode 0|1              Ensure /opt/remnanode + compose + start container
  --ssh-harden 0|1             PasswordAuthentication no, PermitRootLogin no
  --open-wan-443 0|1           WAN UFW allow only 443 (tcp+udp).
                               If tailscale is enabled but NOT ready, UFW will be skipped.

  --zsh-all-users 0|1          Ensure oh-my-zsh + p10k for all /home/* users + root (default: 1)

Environment (advanced):
  EDGE_ENABLE_GRO=1            Enable ethtool GRO + rx-udp-gro-forwarding tweaks (default: 0)
                               WARNING: can break networking on some VPS/NICs.

Notes:
  - Interactive prompts work even when piped (curl | sudo bash) because we read from /dev/tty.
  - Rollback restores files from MANIFEST and removes our extra drop-ins.
EOF
}

###############################################################################
# APT helper
###############################################################################
export DEBIAN_FRONTEND=noninteractive
export NEEDRESTART_MODE=a

aptq() {
  local what="$1"; shift
  if apt-get -y -qq -o Dpkg::Use-Pty=0 \
      -o Dpkg::Options::='--force-confdef' \
      -o Dpkg::Options::='--force-confold' \
      "$@" >>"$APT_LOG" 2>&1; then
    ok "$what"
  else
    err "$what failed. Tail:"
    tail -n 60 "$APT_LOG" || true
    die "APT error. Full log: $APT_LOG"
  fi
}

ensure_packages() {
  local title="$1"; shift
  hdr "$title"
  aptq "APT update" update
  aptq "Install base packages" install "$@"
}

###############################################################################
# Detect distro
###############################################################################
is_debian_like() { command -v apt-get >/dev/null 2>&1; }

###############################################################################
# Docker install (idempotent)
###############################################################################
docker_install() {
  hdr "🐳 Docker"
  if command -v docker >/dev/null 2>&1; then
    ok "docker already installed"
    return 0
  fi

  : >"$DOCKER_LOG" || true
  if [[ ! -f /etc/apt/keyrings/docker.gpg ]]; then
    mkdir -p /etc/apt/keyrings
    curl -fsSL https://download.docker.com/linux/ubuntu/gpg | gpg --batch --yes --dearmor -o /etc/apt/keyrings/docker.gpg >>"$DOCKER_LOG" 2>&1 || true
    chmod a+r /etc/apt/keyrings/docker.gpg || true
  fi

  local codename=""
  codename="$(. /etc/os-release 2>/dev/null; echo "${VERSION_CODENAME:-}")"
  [[ -n "$codename" ]] || codename="$(lsb_release -cs 2>/dev/null || true)"
  [[ -n "$codename" ]] || die "Cannot detect distro codename"

  echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/ubuntu ${codename} stable" \
    > /etc/apt/sources.list.d/docker.list

  aptq "APT update (docker)" update
  aptq "Install Docker CE" install docker-ce docker-ce-cli containerd.io docker-compose-plugin

  systemctl enable --now docker >>"$DOCKER_LOG" 2>&1 || true
  ok "docker installed"
}

###############################################################################
# Timezone
###############################################################################
timezone_apply() {
  hdr "🕒 Timezone"
  if [[ -n "${ARG_TIMEZONE:-}" ]]; then
    ln -sf "/usr/share/zoneinfo/${ARG_TIMEZONE}" /etc/localtime 2>>"$ERR_LOG" || true
    timedatectl set-timezone "${ARG_TIMEZONE}" >>"$ERR_LOG" 2>&1 || true
    ok "Timezone set to ${ARG_TIMEZONE}"
  fi
}

###############################################################################
# DNS switcher
###############################################################################
dns_apply() {
  hdr "🌐 DNS switcher (early)"
  local profile="${ARG_DNS_PROFILE:-1}"
  [[ "$profile" =~ ^[1-5]$ ]] || profile="1"

  info "Applying DNS profile ${profile} (auto-yes)"
  : >"$DNS_LOG" || true

  backup_file /etc/systemd/resolved.conf

  local tmp="/tmp/dns-switcher.sh"
  if ! curl -fsSL "$DNS_SWITCHER_URL" -o "$tmp" >>"$DNS_LOG" 2>&1; then
    warn "dns-switcher download failed: ${DNS_SWITCHER_URL}"
    return 0
  fi
  chmod +x "$tmp" >>"$DNS_LOG" 2>&1 || true

  if printf "y\n%s\n" "$profile" | bash "$tmp" >>"$DNS_LOG" 2>&1; then
    ok "dns-switcher applied (profile ${profile})"
  else
    warn "dns-switcher failed (see $DNS_LOG). Continuing."
  fi

  local dns_line fb_line
  dns_line="$(awk -F= 'tolower($1)=="dns"{gsub(/^[[:space:]]+|[[:space:]]+$/,"",$2); print $2}' /etc/systemd/resolved.conf 2>/dev/null | head -n1 || true)"
  fb_line="$(awk -F= 'tolower($1)=="fallbackdns"{gsub(/^[[:space:]]+|[[:space:]]+$/,"",$2); print $2}' /etc/systemd/resolved.conf 2>/dev/null | head -n1 || true)"

  hdr "🧾 DNS summary"
  echo "Applied:"
  echo "  - DNS:         ${dns_line:-"(unknown)"}"
  echo "  - FallbackDNS: ${fb_line:-"(unknown)"}"
  echo
  echo "Now:"
  resolvectl status 2>/dev/null | grep -E "DNS Servers|DNS Domain|Fallback DNS" || true
  echo
  echo "Backups:"
  echo "  - /etc/dns-switcher-backup"
}

###############################################################################
# Tailscale (reliable AuthURL + reliable waiting)
###############################################################################
tailscale_install_if_needed() {
  : >"$TS_LOG" 2>/dev/null || true
  if command -v tailscale >/dev/null 2>&1; then
    ok "tailscale already installed"
    return 0
  fi
  if curl -fsSL https://tailscale.com/install.sh | sh >>"$TS_LOG" 2>&1; then
    ok "tailscale installed"
    return 0
  fi
  warn "tailscale install failed (see $TS_LOG)"
  return 1
}

tailscale_restart_daemon() {
  systemctl enable --now tailscaled >>"$TS_LOG" 2>&1 || true
  systemctl restart tailscaled >>"$TS_LOG" 2>&1 || true
}

tailscale_sysctl_tune() {
  install -m 0644 /dev/stdin /etc/sysctl.d/95-edge-tailscale.conf <<'EOF'
net.ipv4.ip_forward=1
net.ipv6.conf.all.forwarding=1
net.ipv4.conf.all.rp_filter=0
net.ipv4.conf.default.rp_filter=0
EOF
  sysctl --system >>"$TS_LOG" 2>&1 || true

  # SAFETY FIX:
  # Some VPS/NICs behave badly with GRO/rx-udp-gro-forwarding.
  # Enable only if EDGE_ENABLE_GRO=1
  if [[ "${EDGE_ENABLE_GRO:-0}" == "1" ]]; then
    local internet_iface=""
    internet_iface="$(ip route show default 2>/dev/null | awk '/default/ {print $5; exit}' || true)"
    if [[ -n "${internet_iface:-}" ]] && command -v ethtool >/dev/null 2>&1; then
      ethtool -K "$internet_iface" gro on >>"$TS_LOG" 2>&1 || true
      ethtool -K "$internet_iface" rx-udp-gro-forwarding on >>"$TS_LOG" 2>&1 || true
      ok "GRO tweaks enabled on ${internet_iface} (EDGE_ENABLE_GRO=1)"
    fi
  else
    info "Skipping GRO tweaks (set EDGE_ENABLE_GRO=1 to enable)"
  fi
}

tailscale_magicdns_name() {
  local name=""
  if tailscale status --json >/dev/null 2>&1; then
    name="$(tailscale status --json 2>/dev/null | jq -r '.Self.DNSName // empty' 2>/dev/null || true)"
  fi
  if [[ -z "$name" ]]; then
    name="$(tailscale status 2>/dev/null | awk 'NR==1{print $2}' | sed 's/^\(.*\)\.$/\1/' || true)"
  fi
  name="${name%.}"
  echo "$name"
}

tailscale_ip4() { tailscale ip -4 2>/dev/null | head -n1 || true; }
tailscale_iface_has_ipv4() { ip -4 addr show dev tailscale0 2>/dev/null | grep -qE '\binet\s' && return 0; return 1; }
tailscale0_present() { ip link show tailscale0 >/dev/null 2>&1; }

tailscale_need_reinstall() {
  if tailscale0_present; then
    if ! tailscale_iface_has_ipv4; then return 0; fi
  fi
  return 1
}

tailscale_reinstall_if_broken() {
  if ! tailscale_need_reinstall; then return 0; fi
  warn "tailscale0 has no IPv4 (looks broken) -> reinstalling tailscale first"
  : >"$TS_LOG" 2>/dev/null || true

  systemctl stop tailscaled >>"$TS_LOG" 2>&1 || true

  if command -v apt-get >/dev/null 2>&1; then
    apt-get -y -qq -o Dpkg::Use-Pty=0 remove --purge tailscale >>"$TS_LOG" 2>&1 || true
    rm -f /etc/apt/sources.list.d/tailscale.list /etc/apt/keyrings/tailscale.gpg >>"$TS_LOG" 2>&1 || true
    apt-get -y -qq -o Dpkg::Use-Pty=0 update >>"$TS_LOG" 2>&1 || true
  fi

  rm -rf /var/lib/tailscale /var/cache/tailscale >>"$TS_LOG" 2>&1 || true

  if curl -fsSL https://tailscale.com/install.sh | sh >>"$TS_LOG" 2>&1; then
    ok "Reinstall tailscale"
  else
    warn "Reinstall tailscale failed (see $TS_LOG)"
  fi

  tailscale_restart_daemon
}

tailscale_backend_state() { tailscale status --json 2>/dev/null | jq -r '.BackendState // "NoState"' 2>/dev/null || echo "NoState"; }
tailscale_auth_url_json() { tailscale status --json 2>/dev/null | jq -r '.AuthURL // empty' 2>/dev/null || true; }

tailscale_login_qr_emit() {
  : >"$TS_LOG" 2>/dev/null || true
  local cmd=("tailscale" "login" "--qr")
  if command -v stdbuf >/dev/null 2>&1; then cmd=("stdbuf" "-oL" "-eL" "tailscale" "login" "--qr"); fi
  "${cmd[@]}" 2>&1 | tee -a "$TS_LOG" || true
}

tailscale_wait_running_and_ipv4() {
  local max="${1:-180}"
  local i st ip
  for ((i=1; i<=max; i++)); do
    st="$(tailscale_backend_state)"
    ip="$(tailscale_ip4)"
    if [[ "$st" == "Running" ]] && [[ -n "${ip:-}" ]] && tailscale_iface_has_ipv4; then
      echo "$ip"; return 0
    fi
    if _is_tty && (( i % 5 == 0 )); then info "Waiting Tailscale… state=${st}, ip4=${ip:-"-"} (${i}/${max})"; fi
    sleep 1
  done
  return 1
}

tailscale_up_ssh_quiet() { tailscale up --ssh >>"$TS_LOG" 2>&1 || true; }

tailscale_apply() {
  hdr "🧠 Tailscale (early)"
  : >"$TS_LOG" 2>/dev/null || true

  tailscale_install_if_needed
  tailscale_restart_daemon
  tailscale_sysctl_tune

  tailscale_reinstall_if_broken

  local st ip url
  st="$(tailscale_backend_state)"
  ip="$(tailscale_ip4)"

  if [[ "$st" == "Running" ]] && [[ -n "${ip:-}" ]] && tailscale_iface_has_ipv4; then
    ok "tailscale is up (ip ${ip})"
    local name; name="$(tailscale_magicdns_name)"
    [[ -n "$name" ]] && ok "MagicDNS: ${name}" || warn "MagicDNS name not available (maybe disabled)."
    TAILSCALE_READY="1"
    return 0
  fi

  if [[ "$st" == "NeedsLogin" ]]; then
    url="$(tailscale_auth_url_json)"
    if [[ -n "${url:-}" ]]; then
      echo; echo "🔗 Authenticate Tailscale in browser:"; echo "   $url"; echo
    else
      warn "Tailscale needs login but AuthURL is empty -> running 'tailscale login --qr'"
      tailscale_login_qr_emit
      url="$(tailscale_auth_url_json)"
      if [[ -n "${url:-}" ]]; then
        echo; echo "🔗 Authenticate Tailscale in browser:"; echo "   $url"; echo
      fi
    fi

    if _has_dev_tty; then
      read_tty _ "Press Enter AFTER you approve the device in Tailscale admin (or press Enter now, I'll keep waiting)… "
    else
      warn "No /dev/tty available. Will wait for approval automatically."
    fi
  else
    warn "Tailscale state=${st} -> trying 'tailscale up --ssh'"
  fi

  tailscale_up_ssh_quiet

  if ip="$(tailscale_wait_running_and_ipv4 240)"; then
    ok "tailscale is up (ip ${ip})"
    local name; name="$(tailscale_magicdns_name)"
    [[ -n "$name" ]] && ok "MagicDNS: ${name}" || warn "MagicDNS name not available (maybe disabled)."
    TAILSCALE_READY="1"
    return 0
  fi

  warn "tailscale did not become Ready (Running+IPv4) in time."
  warn "This is unsafe to proceed with UFW (can lock you out). We'll skip enabling UFW."
  TAILSCALE_READY="0"
  return 0
}

###############################################################################
# Node Exporter (via external installer)
###############################################################################
node_exporter_apply() {
  hdr "📈 Node Exporter"
  : >"$NODE_EXPORTER_LOG" 2>/dev/null || true

  (
    set +e
    echo "[$(date -Is)] start: ${NODE_EXPORTER_INSTALL_CMD}"
    bash -c "${NODE_EXPORTER_INSTALL_CMD}"
    rc=$?
    echo "[$(date -Is)] done: rc=${rc}"
    exit $rc
  ) >>"$NODE_EXPORTER_LOG" 2>&1 &

  disown >/dev/null 2>&1 || true
  ok "Node Exporter install kicked off (log: $NODE_EXPORTER_LOG)"
}

###############################################################################
# User management
###############################################################################
USER_CREATED="0"
USER_PASS=""

create_or_ensure_user() {
  local uname="$1"
  [[ -n "$uname" ]] || return 0

  hdr "👤 User"

  if id -u "$uname" >/dev/null 2>&1; then
    ok "user exists: $uname"
    USER_CREATED="0"
    USER_PASS=""
    return 0
  fi

  local pass=""
  pass="$(openssl rand -base64 16 2>/dev/null || true)"
  [[ -n "$pass" ]] || pass="ChangeMe-$(date +%s)"

  useradd -m -s /usr/bin/zsh "$uname" >>"$ERR_LOG" 2>&1 || die "useradd failed"
  echo "${uname}:${pass}" | chpasswd >>"$ERR_LOG" 2>&1 || die "chpasswd failed"
  usermod -aG sudo,docker "$uname" >>"$ERR_LOG" 2>&1 || true

  install -m 0440 /dev/stdin "/etc/sudoers.d/${uname}" <<EOF
${uname} ALL=(ALL) NOPASSWD:ALL
EOF

  ok "user created: $uname"
  USER_CREATED="1"
  USER_PASS="$pass"
}

###############################################################################
# Zsh stack for users (/home/* + root)
###############################################################################
zsh_disable_update_prompts() {
  local zrc="$1"
  [[ -f "$zrc" ]] || return 0
  grep -q 'DISABLE_AUTO_UPDATE' "$zrc" 2>/dev/null || echo 'DISABLE_AUTO_UPDATE="true"' >> "$zrc"
  grep -q 'DISABLE_UPDATE_PROMPT' "$zrc" 2>/dev/null || echo 'DISABLE_UPDATE_PROMPT=true' >> "$zrc"
  grep -q ":omz:update" "$zrc" 2>/dev/null || echo "zstyle ':omz:update' mode disabled" >> "$zrc"
}

ensure_ohmyzsh_for_user() {
  local uname="$1"
  local home="$2"
  [[ -d "$home" ]] || return 0

  grep -q '^/usr/bin/zsh$' /etc/shells 2>/dev/null || echo '/usr/bin/zsh' >> /etc/shells

  if [[ ! -d "${home}/.oh-my-zsh" ]]; then
    if [[ "$uname" == "root" ]]; then
      RUNZSH=no KEEP_ZSHRC=yes CHSH=no sh -c "$(curl -fsSL https://raw.githubusercontent.com/ohmyzsh/ohmyzsh/master/tools/install.sh)" >>"$ERR_LOG" 2>&1 || true
    else
      su - "$uname" -c 'RUNZSH=no KEEP_ZSHRC=yes CHSH=no sh -c "$(curl -fsSL https://raw.githubusercontent.com/ohmyzsh/ohmyzsh/master/tools/install.sh)"' >>"$ERR_LOG" 2>&1 || true
    fi
  fi

  local zsh_path="${home}/.oh-my-zsh"
  local zsh_custom="${zsh_path}/custom"
  mkdir -p "${zsh_custom}/plugins" "${zsh_custom}/themes" >>"$ERR_LOG" 2>&1 || true

  if [[ ! -d "${zsh_custom}/plugins/zsh-autosuggestions" ]]; then
    if [[ "$uname" == "root" ]]; then
      git clone --depth=1 https://github.com/zsh-users/zsh-autosuggestions "${zsh_custom}/plugins/zsh-autosuggestions" >>"$ERR_LOG" 2>&1 || true
    else
      su - "$uname" -c "git clone --depth=1 https://github.com/zsh-users/zsh-autosuggestions ${zsh_custom}/plugins/zsh-autosuggestions" >>"$ERR_LOG" 2>&1 || true
    fi
  fi

  if [[ ! -d "${zsh_custom}/plugins/zsh-completions" ]]; then
    if [[ "$uname" == "root" ]]; then
      git clone --depth=1 https://github.com/zsh-users/zsh-completions "${zsh_custom}/plugins/zsh-completions" >>"$ERR_LOG" 2>&1 || true
    else
      su - "$uname" -c "git clone --depth=1 https://github.com/zsh-users/zsh-completions ${zsh_custom}/plugins/zsh-completions" >>"$ERR_LOG" 2>&1 || true
    fi
  fi

  if [[ ! -d "${zsh_custom}/plugins/zsh-syntax-highlighting" ]]; then
    if [[ "$uname" == "root" ]]; then
      git clone --depth=1 https://github.com/zsh-users/zsh-syntax-highlighting "${zsh_custom}/plugins/zsh-syntax-highlighting" >>"$ERR_LOG" 2>&1 || true
    else
      su - "$uname" -c "git clone --depth=1 https://github.com/zsh-users/zsh-syntax-highlighting ${zsh_custom}/plugins/zsh-syntax-highlighting" >>"$ERR_LOG" 2>&1 || true
    fi
  fi

  if [[ ! -d "${zsh_custom}/themes/powerlevel10k" ]]; then
    if [[ "$uname" == "root" ]]; then
      git clone --depth=1 https://github.com/romkatv/powerlevel10k.git "${zsh_custom}/themes/powerlevel10k" >>"$ERR_LOG" 2>&1 || true
    else
      su - "$uname" -c "git clone --depth=1 https://github.com/romkatv/powerlevel10k.git ${zsh_custom}/themes/powerlevel10k" >>"$ERR_LOG" 2>&1 || true
    fi
  fi

  if [[ ! -d "${home}/.fzf" ]]; then
    if [[ "$uname" == "root" ]]; then
      git clone --depth 1 https://github.com/junegunn/fzf.git "${home}/.fzf" >>"$ERR_LOG" 2>&1 || true
      bash -lc 'yes | ~/.fzf/install --key-bindings --completion --no-bash --no-fish --no-update-rc' >>"$ERR_LOG" 2>&1 || true
    else
      su - "$uname" -c 'git clone --depth 1 https://github.com/junegunn/fzf.git ~/.fzf' >>"$ERR_LOG" 2>&1 || true
      su - "$uname" -c 'yes | ~/.fzf/install --key-bindings --completion --no-bash --no-fish --no-update-rc' >>"$ERR_LOG" 2>&1 || true
    fi
  fi

  curl -fsSL "$ZSHRC_URL" -o "${home}/.zshrc" >>"$ERR_LOG" 2>&1 || true
  curl -fsSL "$P10K_URL" -o "${home}/.p10k.zsh" >>"$ERR_LOG" 2>&1 || true

  if [[ -f "${home}/.zshrc" ]] && ! grep -q 'FZF_BASE=' "${home}/.zshrc" 2>/dev/null; then
    cat >> "${home}/.zshrc" <<'EOF_FZF'
# Linux fallback for oh-my-zsh fzf plugin
if command -v fzf >/dev/null 2>&1; then
  export FZF_BASE="${FZF_BASE:-$HOME/.fzf}"
fi
EOF_FZF
  fi

  zsh_disable_update_prompts "${home}/.zshrc"

  if [[ "$uname" == "root" ]]; then
    chown root:root "${home}/.zshrc" "${home}/.p10k.zsh" 2>/dev/null || true
    chsh -s /usr/bin/zsh root >/dev/null 2>&1 || true
  else
    chown "$uname:$uname" "${home}/.zshrc" "${home}/.p10k.zsh" 2>/dev/null || true
    chsh -s /usr/bin/zsh "$uname" >/dev/null 2>&1 || true
  fi
}

zsh_apply_all_users() {
  hdr "💅 Zsh for all /home/* users"
  aptq "Install zsh stack packages" install zsh git curl wget ca-certificates jq >/dev/null 2>&1 || true

  local homes=()
  while IFS= read -r -d '' d; do homes+=("$d"); done < <(find /home -mindepth 1 -maxdepth 1 -type d -print0 2>/dev/null || true)

  for h in "${homes[@]:-}"; do
    local u; u="$(basename "$h")"
    ensure_ohmyzsh_for_user "$u" "$h"
    ok "zsh stack ensured for $u"
  done

  ensure_ohmyzsh_for_user "root" "/root"
  ok "zsh stack ensured for root"
}

###############################################################################
# SSH hardening
###############################################################################
ssh_harden_apply() {
  hdr "🔐 SSH hardening"
  local cfg="/etc/ssh/sshd_config"
  [[ -f "$cfg" ]] || { warn "sshd_config not found; skip"; return 0; }

  backup_file "$cfg"

  sed -i 's/^[[:space:]]*#\?[[:space:]]*PasswordAuthentication[[:space:]].*/PasswordAuthentication no/' "$cfg" || true
  sed -i 's/^[[:space:]]*#\?[[:space:]]*PermitRootLogin[[:space:]].*/PermitRootLogin no/' "$cfg" || true

  grep -qi '^[[:space:]]*PasswordAuthentication[[:space:]]' "$cfg" || echo 'PasswordAuthentication no' >> "$cfg"
  grep -qi '^[[:space:]]*PermitRootLogin[[:space:]]' "$cfg" || echo 'PermitRootLogin no' >> "$cfg"

  systemctl restart ssh 2>/dev/null || systemctl restart sshd 2>/dev/null || true
  ok "SSH hardening applied"
}

###############################################################################
# UFW firewall
###############################################################################
ufw_apply() {
  hdr "🧱 Firewall (UFW)"

  if ! command -v ufw >/dev/null 2>&1; then
    aptq "Install UFW" install ufw
  fi

  backup_file /etc/default/ufw

  if [[ -f /etc/default/ufw ]]; then
    if grep -q '^DEFAULT_FORWARD_POLICY=' /etc/default/ufw; then
      sed -i 's/^DEFAULT_FORWARD_POLICY=.*/DEFAULT_FORWARD_POLICY="ACCEPT"/' /etc/default/ufw || true
    else
      echo 'DEFAULT_FORWARD_POLICY="ACCEPT"' >> /etc/default/ufw
    fi
  fi

  if [[ "${ARG_TAILSCALE}" == "1" ]]; then
    if [[ "${TAILSCALE_READY:-0}" != "1" ]]; then
      warn "tailscale enabled but not ready -> skipping UFW enable to avoid lockout."
      return 0
    fi
  fi

  local internet_iface=""
  internet_iface="$(ip route get 8.8.8.8 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="dev") print $(i+1)}' | head -n1 || true)"
  [[ -n "$internet_iface" ]] || internet_iface="$(ip route show default 2>/dev/null | awk '/default/ {print $5; exit}' || true)"
  [[ -n "$internet_iface" ]] || { warn "Cannot detect WAN iface; skipping UFW"; return 0; }

  ufw --force reset >/dev/null 2>&1 || true
  ufw default deny incoming >/dev/null 2>&1 || true
  ufw default allow outgoing >/dev/null 2>&1 || true

  # SAFETY FIX:
  # If tailscale is NOT enabled, do not accidentally lock yourself out from current SSH.
  # (If tailscale is enabled+ready, you explicitly want WAN closed except 443.)
  local ssh_port="${SSH_PORT:-22}"
  if [[ "${ARG_TAILSCALE}" != "1" ]]; then
    ufw allow in on "$internet_iface" to any port "$ssh_port" proto tcp >/dev/null 2>&1 || true
    ok "WAN (${internet_iface}): allow SSH ${ssh_port}/tcp (tailscale=0 safety)"
  fi

  if [[ "${ARG_OPEN_WAN_443}" == "1" ]]; then
    ufw allow in on "$internet_iface" to any port 443 proto tcp >/dev/null 2>&1 || true
    ufw allow in on "$internet_iface" to any port 443 proto udp >/dev/null 2>&1 || true
    ok "WAN (${internet_iface}): allow 443/tcp, 443/udp"
  else
    warn "WAN (${internet_iface}): no inbound ports opened (open-wan-443=0)"
  fi

  if ip link show tailscale0 >/dev/null 2>&1; then
    ufw allow in on tailscale0 >/dev/null 2>&1 || true
    ufw allow out on tailscale0 >/dev/null 2>&1 || true
    ok "Tailscale (tailscale0): allow all (in/out)"
  else
    warn "tailscale0 not found (tailscale disabled or not up yet)."
  fi

  local docker_ifaces=""
  docker_ifaces="$(ip -o link show 2>/dev/null | awk -F': ' '$2 ~ /^(docker0|br-)/ {print $2}' || true)"
  if [[ -n "$docker_ifaces" ]]; then
    for ifc in $docker_ifaces; do
      ufw allow in on "$ifc" >/dev/null 2>&1 || true
      ufw allow out on "$ifc" >/dev/null 2>&1 || true
    done
    ok "Docker bridges: allow all (in/out)"
  fi

  ufw --force enable >/dev/null 2>&1 || true
  ok "ufw enabled"
}

###############################################################################
# iperf3 server (always)
###############################################################################
iperf3_server_apply() {
  hdr "📡 iperf3 server"
  install -m 0644 /dev/stdin /etc/systemd/system/iperf3.service <<'EOF'
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
# remnanode (compose create only if missing)
###############################################################################
remnanode_collect_inputs_early() {
  local compose="/opt/remnanode/docker-compose.yml"
  if [[ -f "$compose" ]]; then
    ok "remnanode compose exists: ${compose} (skip inputs)"
    SKIP_REMNANODE_INPUTS="1"
    return 0
  fi

  hdr "🧩 remnanode inputs (early)"

  if ! _has_dev_tty; then
    die "remnanode=1 but compose is missing and there is no /dev/tty to ask for NODE_PORT/SECRET_KEY."
  fi

  local port="${NODE_PORT:-}"
  read_tty port "NODE_PORT for remnanode (default 2222): "
  [[ -n "$port" ]] || port="2222"
  NODE_PORT="$port"

  local key="${SECRET_KEY:-}"
  read_tty_silent key "Paste SECRET_KEY (input hidden): "
  if [[ -z "$key" ]]; then
    die "SECRET_KEY empty. Refusing to continue with remnanode=1 without inputs."
  fi
  SECRET_KEY="$key"

  ok "remnanode params collected"
  SKIP_REMNANODE_INPUTS="0"
}

remnanode_logrotate_apply() {
  mkdir -p /etc/logrotate.d
  backup_file /etc/logrotate.d/remnanode
  cat > /etc/logrotate.d/remnanode <<'EOF'
/var/log/remnanode/*.log {
  size 50M
  rotate 5
  compress
  missingok
  notifempty
  copytruncate
}
EOF
  if command -v logrotate >/dev/null 2>&1; then
    logrotate -vf /etc/logrotate.d/remnanode >>"$ERR_LOG" 2>&1 || true
  fi
  ok "remnanode logrotate configured: /etc/logrotate.d/remnanode"
}

remnanode_apply() {
  hdr "🧩 remnanode"

  docker_install

  local dir="/opt/remnanode"
  local compose="${dir}/docker-compose.yml"

  mkdir -p "$dir" >/dev/null 2>&1 || true

  if [[ ! -f "$compose" ]]; then
    [[ "${SKIP_REMNANODE_INPUTS:-0}" == "1" ]] && die "remnanode compose missing but inputs were skipped."
    [[ -n "${SECRET_KEY:-}" ]] || die "SECRET_KEY missing for remnanode compose."
    [[ -n "${NODE_PORT:-}" ]] || NODE_PORT="2222"

    backup_file "$compose"

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
  else
    ok "remnanode compose exists: ${compose}"
  fi

  if (cd "$dir" && docker compose up -d) >>"$ERR_LOG" 2>&1; then
    ok "remnanode started"
  else
    warn "remnanode start failed (see $ERR_LOG)"
  fi

  remnanode_logrotate_apply
}

remnanode_status_line() {
  if command -v docker >/dev/null 2>&1; then
    docker ps --format '{{.Names}} {{.Status}}' 2>/dev/null | awk '$1=="remnanode"{ $1=""; sub(/^ /,""); print "remnanode " $0 }' | head -n1 || true
  fi
}

###############################################################################
# Kernel/system tuning (tiered; reversible)
###############################################################################
HW_CPU="?"
HW_RAM_MB="?"
HW_TIER="?"
HW_PROFILE="?"
HW_DISK_MB="?"
J_SYSTEM="100M"
J_RUNTIME="50M"
LR_ROTATE="7"

detect_hw_profile() {
  HW_CPU="$(nproc 2>/dev/null || echo 1)"
  HW_RAM_MB="$(awk '/MemTotal/ {print int($2/1024)}' /proc/meminfo 2>/dev/null || echo 1024)"
  local ram_gib; ram_gib="$(ceil_gib "$HW_RAM_MB")"
  HW_TIER="$(ceil_to_tier "$ram_gib")"
  HW_PROFILE="$(profile_from_tier "$HW_TIER")"
  HW_DISK_MB="$(disk_size_mb_for_logs)"
  pick_log_caps "$HW_DISK_MB"
}

apply_sysctl_file() {
  local f="/etc/sysctl.d/99-edge.conf"
  backup_file "$f"

  local ct_soft; ct_soft="$(ct_soft_from_ram_cpu "$HW_RAM_MB" "$HW_CPU")"
  local ct_max; ct_max="$(clamp "$ct_soft" 65536 1048576)"
  local ct_buckets; ct_buckets="$(clamp $(( ct_max / 4 )) 16384 262144)"

  local tw_buckets
  if [[ "$HW_TIER" -le 2 ]]; then tw_buckets="200000"
  elif [[ "$HW_TIER" -le 8 ]]; then tw_buckets="500000"
  else tw_buckets="1000000"
  fi

  local netdev_backlog somaxconn
  if [[ "$HW_TIER" -le 2 ]]; then netdev_backlog="16384"; somaxconn="8192"
  elif [[ "$HW_TIER" -le 8 ]]; then netdev_backlog="32768"; somaxconn="16384"
  else netdev_backlog="65536"; somaxconn="32768"
  fi

  cat >"$f" <<EOF
# Managed by vps-edge-run.sh
# Profile: ${HW_PROFILE} (tier=${HW_TIER}), CPU=${HW_CPU}, RAM=${HW_RAM_MB}MiB

net.ipv4.ip_forward=1

net.core.default_qdisc=fq
net.ipv4.tcp_congestion_control=bbr

net.netfilter.nf_conntrack_max=${ct_max}
net.netfilter.nf_conntrack_buckets=${ct_buckets}

net.netfilter.nf_conntrack_tcp_timeout_established=7200
net.netfilter.nf_conntrack_tcp_timeout_close_wait=60
net.netfilter.nf_conntrack_tcp_timeout_fin_wait=60
net.netfilter.nf_conntrack_tcp_timeout_time_wait=60

net.ipv4.tcp_syncookies=1
net.ipv4.tcp_rfc1337=1
net.ipv4.tcp_keepalive_time=60
net.ipv4.tcp_keepalive_intvl=10
net.ipv4.tcp_keepalive_probes=6

net.core.somaxconn=${somaxconn}
net.core.netdev_max_backlog=${netdev_backlog}
net.ipv4.tcp_max_syn_backlog=8192
net.ipv4.ip_local_port_range=10240 60999

net.ipv4.tcp_max_tw_buckets=${tw_buckets}

vm.swappiness=10
EOF

  sysctl --system >>"$ERR_LOG" 2>&1 || true
  ok "sysctl tuning applied: $f"
}

ensure_swapfile() {
  hdr "💾 Swap"
  if /sbin/swapon --noheadings --show=NAME 2>/dev/null | grep -q .; then
    ok "swap already enabled: $(_swap_state)"
    return 0
  fi

  local ram_gib swap_gib
  ram_gib="$(ceil_gib "$HW_RAM_MB")"
  if [[ "$ram_gib" -le 2 ]]; then
    swap_gib="$ram_gib"
  elif [[ "$ram_gib" -le 8 ]]; then
    swap_gib="2"
  else
    swap_gib="4"
  fi
  [[ "$swap_gib" -lt 1 ]] && swap_gib="1"

  local sf="/swapfile"
  backup_file /etc/fstab

  if [[ -f "$sf" ]]; then
    warn "/swapfile already exists but swap not enabled; will try to (re)enable it."
  else
    info "Creating swapfile: ${swap_gib}G at ${sf}"
    if command -v fallocate >/dev/null 2>&1; then
      fallocate -l "${swap_gib}G" "$sf" >>"$ERR_LOG" 2>&1 || true
    fi
    if [[ ! -s "$sf" ]]; then
      dd if=/dev/zero of="$sf" bs=1M count=$((swap_gib*1024)) status=none >>"$ERR_LOG" 2>&1 || true
    fi
    chmod 600 "$sf" >>"$ERR_LOG" 2>&1 || true
    mkswap "$sf" >>"$ERR_LOG" 2>&1 || true
  fi

  swapon "$sf" >>"$ERR_LOG" 2>&1 || true

  if ! grep -qE '^[^#].*\s/swapfile\s+swap\s' /etc/fstab 2>/dev/null; then
    echo "/swapfile none swap sw 0 0" >> /etc/fstab
  fi

  if /sbin/swapon --noheadings --show=NAME 2>/dev/null | grep -q /swapfile; then
    ok "swap enabled: $(_swap_state)"
  else
    warn "swap not enabled (see $ERR_LOG)."
  fi
}

apply_nofile_limits() {
  hdr "📂 nofile limits"
  local sysd="/etc/systemd/system.conf.d/90-edge-nofile.conf"
  local lim="/etc/security/limits.d/90-edge.conf"

  mkdir -p /etc/systemd/system.conf.d /etc/security/limits.d

  backup_file "$sysd"
  backup_file "$lim"
  backup_file /etc/pam.d/common-session
  backup_file /etc/pam.d/common-session-noninteractive

  cat >"$sysd" <<'EOF'
# Managed by vps-edge-run.sh
[Manager]
DefaultLimitNOFILE=1048576
EOF

  cat >"$lim" <<'EOF'
# Managed by vps-edge-run.sh
* soft nofile 1048576
* hard nofile 1048576
root soft nofile 1048576
root hard nofile 1048576
EOF

  if [[ -f /etc/pam.d/common-session ]] && ! grep -qE '^\s*session\s+required\s+pam_limits\.so' /etc/pam.d/common-session; then
    echo "session required pam_limits.so" >> /etc/pam.d/common-session
  fi
  if [[ -f /etc/pam.d/common-session-noninteractive ]] && ! grep -qE '^\s*session\s+required\s+pam_limits\.so' /etc/pam.d/common-session-noninteractive; then
    echo "session required pam_limits.so" >> /etc/pam.d/common-session-noninteractive
  fi

  systemctl daemon-reexec >>"$ERR_LOG" 2>&1 || true
  ok "nofile set to 1048576 (systemd + pam)"
}

apply_journald_limits() {
  hdr "🪵 journald limits"
  mkdir -p /etc/systemd/journald.conf.d
  local f="/etc/systemd/journald.conf.d/90-edge.conf"
  backup_file "$f"

  cat >"$f" <<EOF
# Managed by vps-edge-run.sh (disk-aware)
[Journal]
SystemMaxUse=${J_SYSTEM}
RuntimeMaxUse=${J_RUNTIME}
Compress=yes
RateLimitIntervalSec=30s
RateLimitBurst=10000
EOF

  systemctl restart systemd-journald >>"$ERR_LOG" 2>&1 || true
  ok "journald caps applied: SystemMaxUse=${J_SYSTEM}, RuntimeMaxUse=${J_RUNTIME}"
}

apply_unattended_upgrades_policy() {
  hdr "🔁 unattended-upgrades"
  local f="/etc/apt/apt.conf.d/52unattended-upgrades-edge"
  backup_file "$f"
  cat >"$f" <<'EOF'
/* Managed by vps-edge-run.sh */
Unattended-Upgrade::Automatic-Reboot "false";
Unattended-Upgrade::Automatic-Reboot-Time "04:00";
EOF
  ok "Auto-reboot disabled for unattended-upgrades"
}

apply_logrotate_varlog() {
  hdr "🗂️ logrotate (var/log)"
  local f="/etc/logrotate.d/zz-edge-varlog"
  backup_file "$f"
  cat >"$f" <<EOF
# Managed by vps-edge-run.sh
/var/log/*.log /var/log/syslog /var/log/auth.log /var/log/kern.log /var/log/daemon.log /var/log/messages {
  daily
  rotate ${LR_ROTATE}
  missingok
  notifempty
  compress
  delaycompress
  copytruncate
}
EOF
  if command -v logrotate >/dev/null 2>&1; then
    logrotate -vf "$f" >>"$ERR_LOG" 2>&1 || true
  fi
  ok "logrotate rule installed: $f (rotate=${LR_ROTATE})"
}

tuning_apply() {
  hdr "🛠️ System tuning"

  detect_hw_profile
  info "HW profile: profile=${HW_PROFILE}, tier=${HW_TIER} | CPU=${HW_CPU} | RAM=${HW_RAM_MB}MiB | disk(/var/log)=${HW_DISK_MB}MB"

  apply_sysctl_file
  ensure_swapfile
  apply_nofile_limits
  apply_journald_limits
  apply_unattended_upgrades_policy
  apply_logrotate_varlog
}

###############################################################################
# Start/end banner
###############################################################################
print_start_end_banner() {
  local title="$1"
  local ip cc region city org flag
  ip="$(ext_ip)"; [[ -n "$ip" ]] || ip="?"
  local gl; gl="$(geo_lookup "$ip")"
  cc="${gl%%|*}"
  region="$(echo "$gl" | cut -d'|' -f3)"
  city="$(echo "$gl" | cut -d'|' -f4)"
  org="$(echo "$gl" | cut -d'|' -f5)"
  flag="$(country_flag "$cc")"
  hdr "$title"
  echo "  ${flag} ${ip} — ${city:-?}, ${region:-?}, ${cc:-?} — ${org:-?}"
  WAN_IP="$ip"; GEO_CC="$cc"; GEO_CITY="$city"; GEO_REGION="$region"; GEO_PROVIDER="$org"; GEO_FLAG="$flag"
}

###############################################################################
# Reboot scheduling
###############################################################################
maybe_reboot() {
  local r="${ARG_REBOOT:-5m}"
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
# Apply / rollback / status
###############################################################################
on_apply_fail() {
  local code=$?
  err "Apply failed (exit code=$code)."
  warn "Rollback: sudo BACKUP_DIR=$backup_dir $0 rollback"
  exit "$code"
}

apply_cmd() {
  need_root "$@"
  trap on_apply_fail ERR

  is_debian_like || die "This script expects Debian/Ubuntu (apt)."

  mkbackup
  snapshot_before

  if [[ -z "${ARG_USER}" ]]; then
    read_tty ARG_USER "User to create/ensure (leave empty to skip): "
  fi

  if [[ -z "${ARG_DNS_SWITCHER}" ]]; then
    local a="n"
    read_tty a "Run DNS switcher early? [y/N]: "
    [[ "${a,,}" == "y" || "${a,,}" == "yes" ]] && ARG_DNS_SWITCHER="1" || ARG_DNS_SWITCHER="0"
  fi

  if [[ -z "${ARG_TAILSCALE}" ]]; then
    local a="y"
    read_tty a "Enable Tailscale early? [Y/n]: "
    [[ -z "$a" || "${a,,}" == "y" || "${a,,}" == "yes" ]] && ARG_TAILSCALE="1" || ARG_TAILSCALE="0"
  fi

  if [[ -z "${ARG_NODE_EXPORTER}" ]]; then
    local a="y"
    read_tty a "Install Node Exporter? [Y/n]: "
    [[ -z "$a" || "${a,,}" == "y" || "${a,,}" == "yes" ]] && ARG_NODE_EXPORTER="1" || ARG_NODE_EXPORTER="0"
  fi

  if [[ -z "${ARG_REMNANODE}" ]]; then
    local a="n"
    read_tty a "Install/start remnanode? [y/N]: "
    [[ "${a,,}" == "y" || "${a,,}" == "yes" ]] && ARG_REMNANODE="1" || ARG_REMNANODE="0"
  fi

  if [[ -z "${ARG_SSH_HARDEN}" ]]; then
    local a="n"
    read_tty a "Apply SSH hardening? [y/N]: "
    [[ "${a,,}" == "y" || "${a,,}" == "yes" ]] && ARG_SSH_HARDEN="1" || ARG_SSH_HARDEN="0"
  fi

  if [[ -z "${ARG_OPEN_WAN_443}" ]]; then
    local a="y"
    read_tty a "Open WAN only 443 via UFW? [Y/n]: "
    [[ -z "$a" || "${a,,}" == "y" || "${a,,}" == "yes" ]] && ARG_OPEN_WAN_443="1" || ARG_OPEN_WAN_443="0"
  fi

  if [[ -z "${ARG_ZSH_ALL_USERS}" ]]; then
    local a="y"
    read_tty a "Setup zsh stack for all users? [Y/n]: "
    [[ -z "$a" || "${a,,}" == "y" || "${a,,}" == "yes" ]] && ARG_ZSH_ALL_USERS="1" || ARG_ZSH_ALL_USERS="0"
  fi

  if [[ "${ARG_REMNANODE}" == "1" ]]; then
    remnanode_collect_inputs_early
  fi

  print_start_end_banner "🏁 Start"

  ensure_packages "📦 Packages" \
    curl wget ca-certificates gnupg lsb-release apt-transport-https \
    jq iproute2 ethtool openssl logrotate cron ufw iperf3 git zsh mc

  timezone_apply

  if [[ "${ARG_DNS_SWITCHER}" == "1" ]]; then
    dns_apply
  fi

  TAILSCALE_READY="0"
  if [[ "${ARG_TAILSCALE}" == "1" ]]; then
    tailscale_apply
    if [[ "${TAILSCALE_READY:-0}" != "1" ]]; then
      warn "tailscale not ready (no IPv4) -> UFW will be skipped."
    fi
  fi

  if [[ "${ARG_NODE_EXPORTER}" == "1" ]]; then
    node_exporter_apply
  fi

  if [[ "${ARG_REMNANODE}" == "1" ]]; then
    docker_install
  else
    if command -v docker >/dev/null 2>&1; then
      hdr "🐳 Docker"
      ok "docker already installed"
    fi
  fi

  if [[ -n "${ARG_USER}" ]]; then
    create_or_ensure_user "${ARG_USER}"
  else
    USER_CREATED="0"
    USER_PASS=""
  fi

  if [[ "${ARG_ZSH_ALL_USERS}" == "1" ]]; then
    zsh_apply_all_users
  else
    warn "zsh setup skipped (zsh-all-users=0)"
  fi

  tuning_apply

  if [[ "${ARG_SSH_HARDEN}" == "1" ]]; then
    ssh_harden_apply
  fi

  ufw_apply
  iperf3_server_apply

  if [[ "${ARG_REMNANODE}" == "1" ]]; then
    remnanode_apply
  fi

  hdr "🧹 Autoremove"
  aptq "Autoremove" autoremove --purge

  snapshot_after
  print_start_end_banner "🏁 End"

  print_before_after_all
  print_manifest_compact "$manifest"

  local ts_ip ts_name
  ts_ip=""; ts_name=""
  if command -v tailscale >/dev/null 2>&1; then
    ts_ip="$(tailscale_ip4)"
    ts_name="$(tailscale_magicdns_name)"
  fi

  local remna_line=""
  remna_line="$(remnanode_status_line)"

  hdr "🧾 Summary"
  row_kv "Host"        "$(host_short)"
  row_kv "WAN"         "${GEO_FLAG:-🏳️} ${WAN_IP:-?}"
  row_kv "Geo"         "${GEO_CITY:-?}, ${GEO_REGION:-?}, ${GEO_CC:-?}"
  row_kv "Provider"    "${GEO_PROVIDER:-?}"
  if [[ -n "${ts_ip:-}" ]]; then row_kv "Tailscale IP" "${ts_ip}"; else row_kv "Tailscale IP" "-"; fi
  if [[ -n "${ts_name:-}" ]]; then row_kv "MagicDNS" "${ts_name}"; else row_kv "MagicDNS" "-"; fi
  row_kv "HW profile"  "profile ${HW_PROFILE:-?}, tier ${HW_TIER:-?} | CPU ${HW_CPU:-?} | RAM ${HW_RAM_MB:-?} MiB | /var/log ${HW_DISK_MB:-?} MB"
  if [[ -n "${ARG_USER:-}" ]]; then
    if [[ "${USER_CREATED:-0}" == "1" ]]; then
      row_kv "User"      "${ARG_USER}"
      row_kv "Password"  "${USER_PASS}"
    else
      row_kv "User"      "${ARG_USER}"
      row_kv "Password"  "(unchanged)"
    fi
  else
    row_kv "User"      "-"
    row_kv "Password"  "-"
  fi
  if [[ -n "${remna_line:-}" ]]; then
    row_kv "remnanode"  "${remna_line#remnanode }"
    row_kv "compose"    "/opt/remnanode/docker-compose.yml"
  else
    row_kv "remnanode"  "-"
    row_kv "compose"    "-"
  fi
  if [[ "${ARG_NODE_EXPORTER}" == "1" ]]; then
    row_kv "NodeExp log" "$NODE_EXPORTER_LOG"
  fi

  hdr "📚 Backup + logs"
  echo "Backup: ${backup_dir}"
  echo "Logs:"
  echo "  - 📦 APT:          ${APT_LOG}"
  echo "  - 🌐 DNS:          ${DNS_LOG}"
  echo "  - 🧠 Tailscale:    ${TS_LOG}"
  echo "  - 🐳 Docker:       ${DOCKER_LOG}"
  echo "  - 📈 Node Exporter:${NODE_EXPORTER_LOG}"
  echo "  - 🛑 Error:        ${ERR_LOG}"
  echo "BACKUP_DIR=${backup_dir}"

  hdr "✅ How to verify"
  cat <<'EOF'
1) sysctl + BBR
   sysctl net.ipv4.ip_forward net.core.default_qdisc net.ipv4.tcp_congestion_control
   sysctl net.netfilter.nf_conntrack_max net.netfilter.nf_conntrack_buckets

2) swap / nofile
   swapon --show
   systemctl show --property DefaultLimitNOFILE
   ulimit -n

3) journald / logrotate
   cat /etc/systemd/journald.conf.d/90-edge.conf
   sudo journalctl --disk-usage
   sudo logrotate -vf /etc/logrotate.d/zz-edge-varlog

4) tailscale
   tailscale status
   ip -4 addr show tailscale0

5) firewall (if enabled)
   sudo ufw status verbose

6) node exporter (if enabled)
   systemctl status node_exporter || systemctl status prometheus-node-exporter
   ss -lntp | grep -E ':9100\b' || true
EOF

  maybe_reboot
}

rollback_cmd() {
  need_root "$@"

  local backup="${BACKUP_DIR:-}"
  if [[ -z "$backup" ]]; then
    if [[ "${1:-}" =~ ^--backup-dir= ]]; then
      backup="${1#*=}"
    fi
  fi
  [[ -n "$backup" ]] || backup="$(latest_backup_dir)"
  [[ -n "$backup" && -d "$backup" ]] || die "Backup not found. Set BACKUP_DIR=/root/edge-tuning-backup-... or run apply first."

  snapshot_before

  rm -f /etc/sysctl.d/99-edge.conf \
        /etc/sysctl.d/95-edge-tailscale.conf \
        /etc/systemd/system.conf.d/90-edge-nofile.conf \
        /etc/security/limits.d/90-edge.conf \
        /etc/systemd/journald.conf.d/90-edge.conf \
        /etc/apt/apt.conf.d/52unattended-upgrades-edge \
        /etc/logrotate.d/zz-edge-varlog \
        /etc/systemd/system/iperf3.service 2>/dev/null || true

  restore_manifest "$backup"

  sysctl --system >/dev/null 2>&1 || true
  systemctl daemon-reexec >/dev/null 2>&1 || true
  systemctl restart systemd-journald >/dev/null 2>&1 || true
  systemctl daemon-reload >/dev/null 2>&1 || true

  systemctl disable --now iperf3 >/dev/null 2>&1 || true

  snapshot_after

  ok "Rolled back. Backup used: $backup"
  print_before_after_all
  print_manifest_compact "${backup}/MANIFEST.tsv"
}

status_cmd() {
  snapshot_before
  hdr "📊 Current"
  row_kv "Host"       "$(host_short)"
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
}

case "$CMD" in
  apply)    apply_cmd ;;
  rollback) rollback_cmd "$@" ;;
  status)   status_cmd ;;
  ""|help|-h|--help) usage; exit 0 ;;
  *) usage; exit 1 ;;
esac
