#!/usr/bin/env bash
set -Eeuo pipefail

###############################################################################
# vps-edge-run.sh
# - DNS switcher (optional, early)
# - Tailscale (optional, early; idempotent; no exit-node; no auth key)
# - Docker + remnanode (optional; early inputs only if compose missing)
# - User (optional/interactive) + Zsh stack for all /home/* users + root
# - Kernel/system tuning with backup+rollback (tiered)
# - UFW: WAN only 443 (optional), Tailscale allow-only (22 + NODE_PORT), Docker bridges allow-all
# - iperf3 installed always + systemd server enabled always
#
# IMPORTANT SAFETY:
# - If --tailscale=1, this script will REFUSE to enable UFW until Tailscale is
#   actually up (tailscale0 exists + tailscale status ok + tailscale ip present).
#   This prevents lock-out after reboot.
###############################################################################

SCRIPT_NAME="vps-edge-run.sh"

###############################################################################
# Logging + colors
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

color() { # color <ansi> <text>
  local code="$1"; shift
  if _is_tty; then printf "%s%s%s" "$code" "$*" "$c_reset"; else printf "%s" "$*"; fi
}

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
# TTY input helpers
###############################################################################
read_tty() { local __var="$1" __prompt="$2" __v=""; [[ -t 0 ]] || { printf -v "$__var" '%s' ""; return 0; }; read -rp "$__prompt" __v </dev/tty || true; printf -v "$__var" '%s' "$__v"; }
read_tty_silent() { local __var="$1" __prompt="$2" __v=""; [[ -t 0 ]] || { printf -v "$__var" '%s' ""; return 0; }; read -rsp "$__prompt" __v </dev/tty || true; echo >/dev/tty || true; printf -v "$__var" '%s' "$__v"; }

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

latest_backup_dir() {
  ls -1dt /root/edge-tuning-backup-* 2>/dev/null | head -n1 || true
}

###############################################################################
# Numeric helpers
###############################################################################
to_int() { local s="${1:-}"; [[ "$s" =~ ^[0-9]+$ ]] && echo "$s" || echo 0; }
imax() { local a b; a="$(to_int "${1:-0}")"; b="$(to_int "${2:-0}")"; [[ "$a" -ge "$b" ]] && echo "$a" || echo "$b"; }
clamp() {
  local v lo hi
  v="$(to_int "${1:-0}")"
  lo="$(to_int "${2:-0}")"
  hi="$(to_int "${3:-0}")"
  [[ "$v" -lt "$lo" ]] && v="$lo"
  [[ "$v" -gt "$hi" ]] && v="$hi"
  echo "$v"
}

###############################################################################
# Geo/ISP helpers (best-effort)
###############################################################################
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

ext_ip() {
  curl -fsSL --max-time 3 https://api.ipify.org 2>/dev/null \
    || curl -fsSL --max-time 3 ifconfig.me 2>/dev/null \
    || true
}

geo_lookup() {
  # Outputs: COUNTRY_CODE|COUNTRY|REGION|CITY|ORG
  local ip="${1:-}"
  local out=""
  # ipinfo (no key)
  out="$(curl -fsSL --max-time 3 "https://ipinfo.io/${ip}/json" 2>/dev/null || true)"
  if [[ -n "$out" ]]; then
    local cc country region city org
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

  # ip-api fallback
  out="$(curl -fsSL --max-time 3 "http://ip-api.com/json/${ip}?fields=status,countryCode,country,regionName,city,as,isp,org" 2>/dev/null || true)"
  if [[ -n "$out" ]]; then
    local status cc country region city as isp org
    status="$(printf "%s" "$out" | jq -r '.status // empty' 2>/dev/null || true)"
    if [[ "$status" == "success" ]]; then
      cc="$(printf "%s" "$out" | jq -r '.countryCode // empty' 2>/dev/null || true)"
      country="$(printf "%s" "$out" | jq -r '.country // empty' 2>/dev/null || true)"
      region="$(printf "%s" "$out" | jq -r '.regionName // empty' 2>/dev/null || true)"
      city="$(printf "%s" "$out" | jq -r '.city // empty' 2>/dev/null || true)"
      as="$(printf "%s" "$out" | jq -r '.as // empty' 2>/dev/null || true)"
      isp="$(printf "%s" "$out" | jq -r '.isp // empty' 2>/dev/null || true)"
      org="$(printf "%s" "$out" | jq -r '.org // empty' 2>/dev/null || true)"
      printf "%s|%s|%s|%s|%s" "${cc:-}" "${country:-}" "${region:-}" "${city:-}" "${as:-$org:-$isp}"
      return 0
    fi
  fi

  printf "||||"
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
# Tier selection (RAM + CPU) + disk-aware log caps
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

# Conntrack soft formula:
# ct_soft = RAM_MiB * 64 + CPU * 8192
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

disk_root_mb() {
  df -Pm / 2>/dev/null | awk 'NR==2{print $2}' || echo 0
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

# Defaults: interactive unless explicitly provided
ARG_USER=""
ARG_TIMEZONE="Europe/Moscow"
ARG_REBOOT="5m"

ARG_TAILSCALE=""         # 0/1, if empty -> interactive
ARG_DNS_SWITCHER=""      # 0/1, if empty -> interactive
ARG_DNS_PROFILE="1"      # 1..5 (dns-switcher menu)
ARG_REMNANODE=""         # 0/1, if empty -> interactive
ARG_SSH_HARDEN=""        # 0/1, if empty -> interactive
ARG_OPEN_WAN_443=""      # 0/1, if empty -> interactive

# remnanode inputs (asked early if needed)
NODE_PORT=""
SECRET_KEY=""

# URLs
DNS_SWITCHER_URL="${DNS_SWITCHER_URL:-https://raw.githubusercontent.com/AndreyTimoschuk/dns-switcher/main/dns-switcher.sh}"

# Optional: Provide your own hosted zshrc / p10k files (or leave empty to skip downloads)
ZSHRC_URL="${ZSHRC_URL:-}"
P10K_URL="${P10K_URL:-}"

# Logs
APT_LOG="/var/log/vps-edge-apt.log"
DNS_LOG="/var/log/vps-edge-dns-switcher.log"
TS_LOG="/var/log/vps-edge-tailscale.log"
DOCKER_LOG="/var/log/vps-edge-docker.log"
ERR_LOG="/var/log/vps-edge-error.log"

touch "$APT_LOG" "$DNS_LOG" "$TS_LOG" "$DOCKER_LOG" "$ERR_LOG" 2>/dev/null || true

# Parse flags after command
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

    --user)          ARG_USER="${2:-}"; shift 2 ;;
    --timezone)      ARG_TIMEZONE="${2:-}"; shift 2 ;;
    --reboot)        ARG_REBOOT="${2:-}"; shift 2 ;;
    --tailscale)     ARG_TAILSCALE="${2:-}"; shift 2 ;;
    --dns-switcher)  ARG_DNS_SWITCHER="${2:-}"; shift 2 ;;
    --dns-profile)   ARG_DNS_PROFILE="${2:-}"; shift 2 ;;
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
  sudo ./vps-edge-run.sh apply [flags]
  sudo ./vps-edge-run.sh rollback [--backup-dir=/root/edge-tuning-backup-...]
  sudo ./vps-edge-run.sh status

Flags (apply):
  --user <name>                Create/ensure user (optional; interactive if omitted)
  --timezone <TZ>              Default: Europe/Moscow
  --reboot <5m|30s|skip|none>  Default: 5m

  --dns-switcher 0|1           Run DNS switcher early
  --dns-profile 1..5           DNS switcher profile (default: 1)

  --tailscale 0|1              Install/up tailscale early (no exit-node, no auth key)
  --remnanode 0|1              Ensure /opt/remnanode + compose + start container
  --ssh-harden 0|1             PasswordAuthentication no, PermitRootLogin no
  --open-wan-443 0|1           WAN UFW allow only 443 (tcp+udp). WAN SSH is NOT opened.

Safety note:
  If --tailscale=1, script will REFUSE to enable UFW unless Tailscale is actually up
  (tailscale0 exists + tailscale status OK + tailscale ip present). Prevents lock-out.

Examples:
  sudo ./vps-edge-run.sh apply
  sudo ./vps-edge-run.sh apply --reboot=skip --tailscale=1 --dns-switcher=1 --dns-profile=1 --remnanode=1 --ssh-harden=1 --open-wan-443=1 --user <user>
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
# Detect distro (we assume Ubuntu/Debian-family)
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
# DNS switcher (auto-yes + choose profile) with summary/tips
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
  echo "Tips:"
  echo "  - Monitor DNS queries:"
  echo "      sudo tcpdump -i any port 53 -n -Q out"
  echo "  - Verify after reboot:"
  echo "      sudo resolvectl status | grep -E \"DNS Servers|DNS Domain\""
  echo "Backups:"
  echo "  - /etc/dns-switcher-backup"
}

###############################################################################
# Tailscale (idempotent; no exit-node; no auth key; no reset)
###############################################################################
tailscale_install_if_needed() {
  if command -v tailscale >/dev/null 2>&1; then
    ok "tailscale already installed"
    return 0
  fi
  : >"$TS_LOG" || true
  if curl -fsSL https://tailscale.com/install.sh | sh >>"$TS_LOG" 2>&1; then
    ok "tailscale installed"
  else
    warn "tailscale install failed (see $TS_LOG)"
  fi
}

tailscale_sysctl_tune() {
  install -m 0644 /dev/stdin /etc/sysctl.d/95-edge-tailscale.conf <<'EOF'
net.ipv4.ip_forward=1
net.ipv6.conf.all.forwarding=1
net.ipv4.conf.all.rp_filter=0
net.ipv4.conf.default.rp_filter=0
EOF
  sysctl --system >/dev/null 2>&1 || true

  local internet_iface=""
  internet_iface="$(ip route show default 2>/dev/null | awk '/default/ {print $5; exit}' || true)"
  if [[ -n "$internet_iface" ]] && command -v ethtool >/dev/null 2>&1; then
    ethtool -K "$internet_iface" gro on >/dev/null 2>&1 || true
    ethtool -K "$internet_iface" rx-udp-gro-forwarding on >/dev/null 2>&1 || true
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

tailscale_is_up() {
  tailscale status >/dev/null 2>&1
}

tailscale_ip4() {
  tailscale ip -4 2>/dev/null | head -n1 || true
}

tailscale_wait_ready_or_die() {
  hdr "🧠 Tailscale readiness check"

  local ip=""
  local ok_status="0"

  for _i in {1..45}; do
    if ip link show tailscale0 >/dev/null 2>&1; then
      if tailscale status >/dev/null 2>&1; then
        ok_status="1"
        ip="$(tailscale_ip4)"
        [[ -n "$ip" ]] && break
      fi
    fi
    sleep 1
  done

  if [[ "$ok_status" != "1" || -z "$ip" ]]; then
    err "Tailscale is required but not ready (tailscale0/status/ip missing)."
    echo
    echo "Fix on console:"
    echo "  sudo systemctl status tailscaled --no-pager"
    echo "  sudo tailscale up --ssh"
    echo
    echo "Then re-run:"
    echo "  sudo ./${SCRIPT_NAME} apply --tailscale=1 ..."
    echo
    die "Refusing to enable UFW without a working Tailscale session."
  fi

  ok "tailscale ready (ip ${ip})"
}

tailscale_apply() {
  hdr "🧠 Tailscale (early)"
  tailscale_install_if_needed
  tailscale_sysctl_tune

  if tailscale_is_up; then
    local ip name
    ip="$(tailscale_ip4)"
    if [[ -n "$ip" ]]; then
      ok "tailscale is up (ip ${ip})"
    else
      ok "tailscale is up"
    fi
    name="$(tailscale_magicdns_name)"
    if [[ -n "$name" ]]; then
      ok "MagicDNS: ${name}"
    else
      warn "MagicDNS name not available (maybe disabled)."
    fi
    return 0
  fi

  : >"$TS_LOG" || true
  local out="/tmp/vps-edge-tailscale-up.log"
  rm -f "$out" 2>/dev/null || true

  set +e
  tailscale up --ssh 2>&1 | tee "$out" >>"$TS_LOG"
  local rc=${PIPESTATUS[0]}
  set -e

  if [[ "$rc" -ne 0 ]]; then
    warn "tailscale up returned rc=${rc}. See: $TS_LOG"
  fi

  local url=""
  url="$(grep -Eo 'https://login\.tailscale\.com/[a-zA-Z0-9/_-]+' "$out" | head -n1 || true)"
  if [[ -n "$url" ]]; then
    echo
    echo "🔗 Authenticate Tailscale in browser:"
    echo "   $url"
    echo
    read_tty _ "Press Enter after you approve the device in Tailscale admin… "
  fi

  local ip=""
  for _i in {1..30}; do
    ip="$(tailscale_ip4)"
    [[ -n "$ip" ]] && break
    sleep 1
  done

  if [[ -n "$ip" ]]; then
    ok "tailscale is up (ip ${ip})"
  else
    warn "tailscale IP not detected (maybe still pending auth). You can re-run: tailscale up --ssh"
  fi

  local name
  name="$(tailscale_magicdns_name)"
  if [[ -n "$name" ]]; then
    ok "MagicDNS: ${name}"
  else
    warn "MagicDNS name not available (maybe disabled)."
  fi
}

###############################################################################
# User management
###############################################################################
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

  # Optional downloads (if you host your own)
  if [[ -n "${ZSHRC_URL:-}" ]]; then
    curl -fsSL "$ZSHRC_URL" -o "${home}/.zshrc" >>"$ERR_LOG" 2>&1 || true
  fi
  if [[ -n "${P10K_URL:-}" ]]; then
    curl -fsSL "$P10K_URL" -o "${home}/.p10k.zsh" >>"$ERR_LOG" 2>&1 || true
  fi

  # FZF_BASE fallback
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
    local u
    u="$(basename "$h")"
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
# UFW firewall (SAFE with Tailscale)
###############################################################################
ufw_allow_tailscale_ports() {
  local node_port="${1:-2222}"
  # SSH on tailscale only
  ufw allow in on tailscale0 to any port 22 proto tcp >/dev/null 2>&1 || true
  # remnanode port (host network service) on tailscale only
  ufw allow in on tailscale0 to any port "${node_port}" proto tcp >/dev/null 2>&1 || true
  ok "Tailscale (tailscale0): allow 22/tcp + ${node_port}/tcp inbound"
}

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

  local internet_iface=""
  internet_iface="$(ip route get 8.8.8.8 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="dev") print $(i+1)}' | head -n1 || true)"
  [[ -n "$internet_iface" ]] || internet_iface="$(ip route show default 2>/dev/null | awk '/default/ {print $5; exit}' || true)"
  [[ -n "$internet_iface" ]] || { warn "Cannot detect WAN iface; skipping UFW"; return 0; }

  # Hard safety: if tailscale is required but tailscale0 is missing, do NOT enable firewall
  if [[ "${ARG_TAILSCALE}" == "1" ]] && ! ip link show tailscale0 >/dev/null 2>&1; then
    die "tailscale0 missing but tailscale=1. Refusing to enable UFW (prevents lock-out)."
  fi

  ufw --force reset >/dev/null 2>&1 || true
  ufw default deny incoming >/dev/null 2>&1 || true
  ufw default allow outgoing >/dev/null 2>&1 || true

  # WAN: only 443 if enabled (no WAN SSH here by design)
  if [[ "${ARG_OPEN_WAN_443}" == "1" ]]; then
    ufw allow in on "$internet_iface" to any port 443 proto tcp >/dev/null 2>&1 || true
    ufw allow in on "$internet_iface" to any port 443 proto udp >/dev/null 2>&1 || true
    ok "WAN (${internet_iface}): allow 443/tcp, 443/udp"
  else
    warn "WAN (${internet_iface}): no inbound ports opened (open-wan-443=0)"
  fi

  # Tailscale rules: allow ONLY must-have ports
  if [[ "${ARG_TAILSCALE}" == "1" ]]; then
    local np="${NODE_PORT:-2222}"
    ufw_allow_tailscale_ports "$np"
  fi

  # Docker bridges
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
    ok "remnanode compose exists: ${compose} (skip early inputs)"
    SKIP_REMNANODE_INPUTS="1"
    return 0
  fi

  hdr "🧩 remnanode inputs (early)"
  local port=""
  read_tty port "NODE_PORT for remnanode (default 2222): "
  [[ -n "$port" ]] || port="2222"
  NODE_PORT="$port"

  read_tty_silent SECRET_KEY "Paste SECRET_KEY (input hidden): "
  if [[ -z "$SECRET_KEY" ]]; then
    warn "SECRET_KEY empty -> remnanode compose will not be created."
    SKIP_REMNANODE_INPUTS="1"
    return 0
  fi

  ok "remnanode params collected"
  SKIP_REMNANODE_INPUTS="0"
}

remnanode_apply() {
  hdr "🧩 remnanode"

  docker_install

  local dir="/opt/remnanode"
  local compose="${dir}/docker-compose.yml"

  mkdir -p "$dir" >/dev/null 2>&1 || true

  if [[ ! -f "$compose" ]]; then
    [[ "${SKIP_REMNANODE_INPUTS:-0}" == "1" ]] && { warn "remnanode compose missing but inputs skipped; not creating"; return 0; }
    [[ -n "${SECRET_KEY:-}" ]] || { warn "SECRET_KEY missing; not creating remnanode compose"; return 0; }

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
      - NODE_PORT=${NODE_PORT:-2222}
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
}

remnanode_status_line() {
  if command -v docker >/dev/null 2>&1; then
    docker ps --format '{{.Names}} {{.Status}}' 2>/dev/null | awk '$1=="remnanode"{ $1=""; sub(/^ /,""); print "remnanode " $0 }' | head -n1 || true
  fi
}

###############################################################################
# remnanode logrotate (requested)
###############################################################################
remnanode_logrotate_apply() {
  hdr "🧾 logrotate: /var/log/remnanode/*.log"

  if ! command -v logrotate >/dev/null 2>&1; then
    aptq "Install logrotate" install logrotate
  fi

  mkdir -p /etc/logrotate.d /var/log/remnanode >/dev/null 2>&1 || true

  local f="/etc/logrotate.d/remnanode"
  backup_file "$f"

  cat > "$f" <<'EOF'
/var/log/remnanode/*.log {
  size 50M
  rotate 5
  compress
  missingok
  notifempty
  copytruncate
}
EOF

  # best-effort validation run (do not fail hard)
  if logrotate -vf "$f" >>"$ERR_LOG" 2>&1; then
    ok "remnanode logrotate installed + verified"
  else
    warn "remnanode logrotate installed, but verification returned non-zero (see $ERR_LOG)"
  fi
}

###############################################################################
# Kernel + system tuning (tiered; reversible)
###############################################################################
tuning_apply() {
  hdr "🧠 Kernel + system tuning"

  local mem_kb mem_mb cpu
  mem_kb="$(awk '/MemTotal:/ {print $2}' /proc/meminfo)"
  mem_mb="$((mem_kb / 1024))"
  cpu="$(nproc)"

  local disk_mb
  disk_mb="$(disk_size_mb_for_logs)"

  local gib ram_tier cpu_tier tier profile
  gib="$(ceil_gib "$mem_mb")"
  ram_tier="$(ceil_to_tier "$gib")"
  cpu_tier="$(ceil_to_tier "$cpu")"
  tier="$(tier_max "$ram_tier" "$cpu_tier")"
  profile="$(profile_from_tier "$tier")"

  if [[ "${FORCE_PROFILE:-}" =~ ^(low|mid|high|xhigh|2xhigh|dedicated|dedicated\+)$ ]]; then
    profile="${FORCE_PROFILE}"
  fi

  pick_log_caps "$disk_mb"
  local j_system="$J_SYSTEM" j_runtime="$J_RUNTIME" logrotate_rotate="$LR_ROTATE"

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

  local current_ct current_tw current_nofile
  current_ct="$(to_int "$B_CT_MAX")"
  current_tw="$(to_int "$B_TW")"
  current_nofile="$(to_int "$B_NOFILE")"

  local nofile_final tw_final
  nofile_final="$(imax "$current_nofile" "$nofile_profile")"
  tw_final="$(imax "$current_tw" "$tw_profile")"

  local ct_soft ct_clamped ct_final
  ct_soft="$(ct_soft_from_ram_cpu "$mem_mb" "$cpu")"
  ct_clamped="$(clamp "$ct_soft" "$ct_min" "$ct_cap")"
  ct_final="$(imax "$current_ct" "$ct_clamped")"
  local ct_buckets=$((ct_final/4)); [[ "$ct_buckets" -lt 4096 ]] && ct_buckets=4096

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
    local active_swapfile="0"
    if /sbin/swapon --show=NAME 2>/dev/null | grep -qx '/swapfile'; then
      active_swapfile="1"
    fi

    local need_swapfile="0"
    if [[ "$swap_total_mb" -eq 0 ]]; then
      need_swapfile="1"
    elif [[ "$active_swapfile" == "1" ]]; then
      local diff=$(( swap_total_mb > swap_target_mb ? swap_total_mb - swap_target_mb : swap_target_mb - swap_total_mb ))
      [[ "$diff" -ge 256 ]] && need_swapfile="1"
    elif [[ -f /swapfile ]]; then
      need_swapfile="1"
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

  backup_file /etc/sysctl.conf
  shopt -s nullglob
  for f in /etc/sysctl.d/*.conf; do
    [[ -f "$f" ]] || continue
    case "$f" in
      /etc/sysctl.d/90-edge-network.conf|/etc/sysctl.d/92-edge-safe.conf|/etc/sysctl.d/95-edge-forward.conf|/etc/sysctl.d/96-edge-vm.conf|/etc/sysctl.d/99-edge-conntrack.conf|/etc/sysctl.d/95-edge-tailscale.conf) continue ;;
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

  mkdir -p /etc/apt/apt.conf.d
  backup_file /etc/apt/apt.conf.d/99-edge-unattended.conf
  cat > /etc/apt/apt.conf.d/99-edge-unattended.conf <<'EOM'
Unattended-Upgrade::Automatic-Reboot "false";
Unattended-Upgrade::Automatic-Reboot-Time "04:00";
EOM

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

  mkdir -p /etc/tmpfiles.d
  backup_file /etc/tmpfiles.d/edge-tmp.conf
  cat > /etc/tmpfiles.d/edge-tmp.conf <<'EOM'
D /tmp            1777 root root 7d
D /var/tmp        1777 root root 14d
EOM
  systemd-tmpfiles --create >/dev/null 2>&1 || true

  HW_PROFILE="$profile"
  HW_TIER="$tier"
  HW_CPU="$cpu"
  HW_RAM_MB="$mem_mb"
  HW_DISK_MB="$(disk_root_mb)"

  ok "tuning applied (profile ${profile}, tier ${tier})"
}

###############################################################################
# Summary header: provider/geo
###############################################################################
print_start_end_banner() {
  local title="$1"
  local ip cc country region city org flag
  ip="$(ext_ip)"
  [[ -n "$ip" ]] || ip="?"
  local gl
  gl="$(geo_lookup "$ip")"
  cc="${gl%%|*}"
  country="$(echo "$gl" | cut -d'|' -f2)"
  region="$(echo "$gl" | cut -d'|' -f3)"
  city="$(echo "$gl" | cut -d'|' -f4)"
  org="$(echo "$gl" | cut -d'|' -f5)"

  flag="$(country_flag "$cc")"

  hdr "$title"
  echo "  ${flag} ${ip} — ${city:-?}, ${region:-?}, ${cc:-?} — ${org:-?}"
  WAN_IP="$ip"
  GEO_CC="$cc"
  GEO_CITY="$city"
  GEO_REGION="$region"
  GEO_PROVIDER="$org"
  GEO_FLAG="$flag"
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
    if [[ -t 0 ]]; then
      read_tty ARG_USER "User to create/ensure (leave empty to skip): "
    fi
  fi

  if [[ -z "${ARG_DNS_SWITCHER}" ]]; then
    if [[ -t 0 ]]; then
      local a="n"
      read_tty a "Run DNS switcher early? [y/N]: "
      [[ "${a,,}" == "y" || "${a,,}" == "yes" ]] && ARG_DNS_SWITCHER="1" || ARG_DNS_SWITCHER="0"
    else
      ARG_DNS_SWITCHER="0"
    fi
  fi

  if [[ -z "${ARG_TAILSCALE}" ]]; then
    if [[ -t 0 ]]; then
      local a="y"
      read_tty a "Enable Tailscale early? [Y/n]: "
      [[ -z "$a" || "${a,,}" == "y" || "${a,,}" == "yes" ]] && ARG_TAILSCALE="1" || ARG_TAILSCALE="0"
    else
      ARG_TAILSCALE="1"
    fi
  fi

  if [[ -z "${ARG_REMNANODE}" ]]; then
    if [[ -t 0 ]]; then
      local a="n"
      read_tty a "Install/start remnanode? [y/N]: "
      [[ "${a,,}" == "y" || "${a,,}" == "yes" ]] && ARG_REMNANODE="1" || ARG_REMNANODE="0"
    else
      ARG_REMNANODE="0"
    fi
  fi

  if [[ -z "${ARG_SSH_HARDEN}" ]]; then
    if [[ -t 0 ]]; then
      local a="n"
      read_tty a "Apply SSH hardening? [y/N]: "
      [[ "${a,,}" == "y" || "${a,,}" == "yes" ]] && ARG_SSH_HARDEN="1" || ARG_SSH_HARDEN="0"
    else
      ARG_SSH_HARDEN="0"
    fi
  fi

  if [[ -z "${ARG_OPEN_WAN_443}" ]]; then
    if [[ -t 0 ]]; then
      local a="y"
      read_tty a "Open WAN only 443 via UFW? [Y/n]: "
      [[ -z "$a" || "${a,,}" == "y" || "${a,,}" == "yes" ]] && ARG_OPEN_WAN_443="1" || ARG_OPEN_WAN_443="0"
    else
      ARG_OPEN_WAN_443="1"
    fi
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

  if [[ "${ARG_TAILSCALE}" == "1" ]]; then
    tailscale_apply
    # SAFETY GATE: do not proceed to firewall unless TS is truly reachable
    tailscale_wait_ready_or_die
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

  zsh_apply_all_users

  tuning_apply

  if [[ "${ARG_SSH_HARDEN}" == "1" ]]; then
    ssh_harden_apply
  fi

  # Firewall (SAFE)
  ufw_apply

  iperf3_server_apply

  if [[ "${ARG_REMNANODE}" == "1" ]]; then
    remnanode_apply
    remnanode_logrotate_apply
  else
    # Still ok to install logrotate config if logs exist (best-effort)
    if [[ -d /var/log/remnanode ]]; then
      remnanode_logrotate_apply
    fi
  fi

  hdr "🧹 Autoremove"
  aptq "Autoremove" autoremove --purge

  snapshot_after

  print_start_end_banner "🏁 End"

  print_before_after_all
  print_manifest_compact "$manifest"

  local ts_ip ts_name
  ts_ip=""
  ts_name=""
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
  row_kv "HW profile"  "profile ${HW_PROFILE:-?}, tier ${HW_TIER:-?} | CPU ${HW_CPU:-?} | RAM ${HW_RAM_MB:-?} MiB | / ${HW_DISK_MB:-?} MB"
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

  hdr "📚 Backup + logs"
  echo "Backup: ${backup_dir}"
  echo "Logs:"
  echo "  - 📦 APT:       ${APT_LOG}"
  echo "  - 🌐 DNS:       ${DNS_LOG}"
  echo "  - 🧠 Tailscale: ${TS_LOG}"
  echo "  - 🐳 Docker:    ${DOCKER_LOG}"
  echo "  - 🛑 Error:     ${ERR_LOG}"
  echo "BACKUP_DIR=${backup_dir}"

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

  rm -f /etc/sysctl.d/90-edge-network.conf \
        /etc/sysctl.d/92-edge-safe.conf \
        /etc/sysctl.d/95-edge-forward.conf \
        /etc/sysctl.d/96-edge-vm.conf \
        /etc/sysctl.d/99-edge-conntrack.conf \
        /etc/sysctl.d/95-edge-tailscale.conf \
        /etc/modules-load.d/edge-conntrack.conf \
        /etc/systemd/system.conf.d/90-edge.conf \
        /etc/security/limits.d/90-edge.conf \
        /etc/systemd/journald.conf.d/90-edge.conf \
        /etc/apt/apt.conf.d/99-edge-unattended.conf \
        /etc/logrotate.d/edge-all-text-logs \
        /etc/logrotate.d/remnanode \
        /etc/tmpfiles.d/edge-tmp.conf \
        /etc/systemd/system/iperf3.service 2>/dev/null || true

  restore_manifest "$backup"

  if /sbin/swapon --show=NAME 2>/dev/null | grep -qx '/swapfile'; then
    /sbin/swapoff /swapfile 2>/dev/null || true
  fi
  sed -i -E '/^\s*\/swapfile\s+none\s+swap\s+/d' /etc/fstab 2>/dev/null || true
  rm -f /swapfile 2>/dev/null || true

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

###############################################################################
# Main
###############################################################################
case "$CMD" in
  apply)    apply_cmd ;;
  rollback) rollback_cmd "$@" ;;
  status)   status_cmd ;;
  ""|help|-h|--help) usage; exit 0 ;;
  *)
    usage
    exit 1
    ;;
esac
