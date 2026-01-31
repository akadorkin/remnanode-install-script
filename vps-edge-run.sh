#!/usr/bin/env bash
set -Eeuo pipefail

###############################################################################
# VPS Edge Router / Node Bootstrap Script
#
# ABSOLUTELY NO WARRANTY:
# This script modifies system settings (kernel/sysctl, DNS, SSH, firewall, logs).
# You run it at your own risk. It may break networking, access (SSH), services,
# or performance depending on your environment. Always test on a fresh VM first.
###############################################################################

###############################################################################
# Design choices (per your latest notes)
# - Tailscale: "hand-mode"
#   * install -> tailscale up -> print Auth URL -> (optional Enter) -> continue
#   * NO waiting loops for IP or interface; just a single `tailscale ip -4` check.
# - "DNS patches" and "kernel patches" are moved to the END:
#   * sysctl tuning
#   * tailscale sysctl forwarding/rp_filter tweaks
#   * dns-switcher
# - UFW is ABSOLUTELY last, after everything else.
###############################################################################

###############################################################################
# Commands:
#   apply    apply tuning and create a backup
#   rollback undo changes using a backup
#   status   show current tuning state
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
hdr()  { echo; color "$c_bold$c_cyan" "$*"; echo; }

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
# Snapshot helpers
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

print_before_after_all() {
  hdr "🧾 Before → After (all)"
  printf "%-14s | %-32s | %-32s\n" "Setting" "Before" "After"
  printf "%-14s-+-%-32s-+-%-32s\n" "$(printf '%.0s-' {1..14})" "$(printf '%.0s-' {1..32})" "$(printf '%.0s-' {1..32})"

  row3() { printf "%-14s | %-32s | %-32s\n" "$1" "$2" "$3"; }

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

  --dns-switcher 0|1           Run DNS switcher (NOW RUNS AT THE END)
  --dns-profile 1..5           DNS switcher profile (default: 1)

  --tailscale 0|1              Install/up tailscale early (hand-mode)
  --node-exporter 0|1          Install Node Exporter

  --remnanode 0|1              Ensure /opt/remnanode + compose + start container
  --ssh-harden 0|1             PasswordAuthentication no, PermitRootLogin no
  --open-wan-443 0|1           WAN UFW allow only 443 (tcp+udp).
                               If tailscale is enabled but NOT ready, UFW will be skipped.

  --zsh-all-users 0|1          Ensure oh-my-zsh + p10k for all /home/* users + root (default: 1)

ENV:
  EDGE_TAILSCALE_REQUIRE_ENTER=1  Always ask Enter after showing Auth URL
  EDGE_ENABLE_GRO=1               Enable GRO tweaks (default OFF)

Notes:
  - Interactive prompts work even when piped (curl | sudo bash) because we read from /dev/tty.
  - UFW is applied at the very end.
  - DNS/sysctl patches are applied near the end (per request).
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

is_debian_like() { command -v apt-get >/dev/null 2>&1; }

###############################################################################
# Hostname (interactive, early)
###############################################################################
hostname_apply_interactive() {
  hdr "🏷️ Hostname"
  local cur newh
  cur="$(hostname 2>/dev/null || true)"
  echo "Current: ${cur:-"(unknown)"}"
  if _has_dev_tty; then
    read_tty newh "Enter new hostname (press Enter to keep current): "
    if [[ -n "${newh:-}" ]]; then
      backup_file /etc/hostname
      hostnamectl set-hostname "$newh" >>"$ERR_LOG" 2>&1 || true
      ok "Hostname set to ${newh}"
    else
      ok "Hostname unchanged"
    fi
  else
    warn "No /dev/tty available -> hostname prompt skipped"
  fi
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
# DNS switcher (NOW RUNS AT END)
###############################################################################
dns_apply() {
  hdr "🌐 DNS switcher (end)"
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

  hdr "🧾 DNS summary"
  resolvectl status 2>/dev/null | grep -E "DNS Servers|DNS Domain|Fallback DNS" || true
  echo
  echo "Backups:"
  echo "  - /etc/dns-switcher-backup"
}

###############################################################################
# Tailscale (early hand-mode) + sysctl patch (end)
###############################################################################
TAILSCALE_READY="0"
TAILSCALE_IP4=""

tailscale_install_if_needed() {
  : >"$TS_LOG" 2>/dev/null || true
  if command -v tailscale >/dev/null 2>&1; then
    ok "tailscale installed"
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

tailscale_auth_url_json() {
  tailscale status --json 2>/dev/null | jq -r '.AuthURL // empty' 2>/dev/null || true
}

tailscale_ip4() { tailscale ip -4 2>/dev/null | head -n1 || true; }

tailscale_apply_early_handmode() {
  hdr "🧠 Tailscale (early)"
  : >"$TS_LOG" 2>/dev/null || true

  tailscale_install_if_needed
  tailscale_restart_daemon

  # Hand-mode: tailscale up, then show URL and move on.
  local out url
  out="$(tailscale up --ssh 2>&1 | tee -a "$TS_LOG" || true)"
  url="$(tailscale_auth_url_json)"
  if [[ -z "${url:-}" ]]; then
    url="$(printf "%s" "$out" | grep -Eo 'https://login\.tailscale\.com/[[:alnum:]/_-]+' | head -n1 || true)"
  fi

  if [[ -n "${url:-}" ]]; then
    echo
    echo "🔗 Authenticate Tailscale:"
    echo "   $url"
    echo
  else
    warn "Auth URL not found in output. If device still needs login, run manually: tailscale up --ssh"
  fi

  if [[ "${EDGE_TAILSCALE_REQUIRE_ENTER:-0}" == "1" ]] && _has_dev_tty; then
    read_tty _ "✅ Approved the device? Press Enter to continue… "
  fi

  # Single-shot check (no waiting):
  TAILSCALE_IP4="$(tailscale_ip4)"
  if [[ -n "${TAILSCALE_IP4:-}" ]]; then
    ok "tailscale ip -4: ${TAILSCALE_IP4}"
    TAILSCALE_READY="1"
  else
    warn "tailscale ip -4 is empty right now. Continuing anyway."
    TAILSCALE_READY="0"
  fi
}

tailscale_sysctl_patch_end() {
  # Per request: sysctl/DNS/kernel patches at the end.
  hdr "🧠 Tailscale sysctl patch (end)"
  backup_file /etc/sysctl.d/95-edge-tailscale.conf

  install -m 0644 /dev/stdin /etc/sysctl.d/95-edge-tailscale.conf <<'EOF'
# Managed by vps-edge-run.sh
net.ipv4.ip_forward=1
net.ipv6.conf.all.forwarding=1
net.ipv4.conf.all.rp_filter=0
net.ipv4.conf.default.rp_filter=0
EOF

  sysctl --system >>"$TS_LOG" 2>&1 || true
  ok "tailscale sysctl patch applied"

  if [[ "${EDGE_ENABLE_GRO:-0}" != "1" ]]; then
    info "Skipping GRO tweaks (set EDGE_ENABLE_GRO=1 to enable)"
    return 0
  fi

  local internet_iface=""
  internet_iface="$(ip route show default 2>/dev/null | awk '/default/ {print $5; exit}' || true)"
  if [[ -n "${internet_iface:-}" ]] && command -v ethtool >/dev/null 2>&1; then
    ethtool -K "$internet_iface" gro on >>"$TS_LOG" 2>&1 || true
    ethtool -K "$internet_iface" rx-udp-gro-forwarding on >>"$TS_LOG" 2>&1 || true
    ok "GRO tweaks applied on ${internet_iface}"
  fi
}

###############################################################################
# Node Exporter
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
# Docker
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
# Zsh stack
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
# iperf3 server
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
# remnanode
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

###############################################################################
# Kernel/system tuning (NOW RUNS AT END)
###############################################################################
HW_CPU="?"
HW_RAM_MB="?"
HW_TIER="?"
HW_DISK_MB="?"
J_SYSTEM="120M"
J_RUNTIME="60M"
LR_ROTATE="7"

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
  J_SYSTEM="120M"; J_RUNTIME="60M"; LR_ROTATE="7"
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
detect_hw_profile() {
  HW_CPU="$(nproc 2>/dev/null || echo 1)"
  HW_RAM_MB="$(awk '/MemTotal/ {print int($2/1024)}' /proc/meminfo 2>/dev/null || echo 1024)"
  local ram_gib; ram_gib="$(ceil_gib "$HW_RAM_MB")"
  HW_TIER="$(ceil_to_tier "$ram_gib")"
  HW_DISK_MB="$(disk_size_mb_for_logs)"
  pick_log_caps "$HW_DISK_MB"
}

apply_sysctl_file_end() {
  hdr "🛠️ sysctl tuning (end)"
  detect_hw_profile

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
# CPU=${HW_CPU}, RAM=${HW_RAM_MB}MiB, tier=${HW_TIER}

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

ensure_swapfile_end() {
  hdr "💾 Swap (end)"
  if /sbin/swapon --noheadings --show=NAME 2>/dev/null | grep -q .; then
    ok "swap already enabled: $(_swap_state)"
    return 0
  fi

  detect_hw_profile
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

  if [[ ! -f "$sf" ]]; then
    info "Creating swapfile: ${swap_gib}G at ${sf}"
    if command -v fallocate >/dev/null 2>&1; then
      fallocate -l "${swap_gib}G" "$sf" >>"$ERR_LOG" 2>&1 || true
    fi
    if [[ ! -s "$sf" ]]; then
      dd if=/dev/zero of="$sf" bs=1M count=$((swap_gib*1024)) status=none >>"$ERR_LOG" 2>&1 || true
    fi
    chmod 600 "$sf" >>"$ERR_LOG" 2>&1 || true
    mkswap "$sf" >>"$ERR_LOG" 2>&1 || true
  else
    warn "/swapfile exists but swap not enabled; trying to enable."
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

apply_nofile_limits_end() {
  hdr "📂 nofile limits (end)"
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

apply_journald_limits_end() {
  hdr "🪵 journald limits (end)"
  detect_hw_profile
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

apply_unattended_upgrades_policy_end() {
  hdr "🔁 unattended-upgrades (end)"
  local f="/etc/apt/apt.conf.d/52unattended-upgrades-edge"
  backup_file "$f"
  cat >"$f" <<'EOF'
/* Managed by vps-edge-run.sh */
Unattended-Upgrade::Automatic-Reboot "false";
Unattended-Upgrade::Automatic-Reboot-Time "04:00";
EOF
  ok "Auto-reboot disabled for unattended-upgrades"
}

apply_logrotate_varlog_end() {
  hdr "🗂️ logrotate (var/log) (end)"
  detect_hw_profile
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

tuning_apply_end() {
  hdr "🛠️ System tuning (end)"
  apply_sysctl_file_end
  ensure_swapfile_end
  apply_nofile_limits_end
  apply_journald_limits_end
  apply_unattended_upgrades_policy_end
  apply_logrotate_varlog_end
}

###############################################################################
# UFW firewall (ABSOLUTELY LAST)
###############################################################################
ufw_apply_last() {
  hdr "🧱 Firewall (UFW) (last)"

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

  if [[ "${ARG_TAILSCALE}" == "1" && "${TAILSCALE_READY:-0}" != "1" ]]; then
    warn "tailscale enabled but not ready (tailscale ip -4 empty) -> skipping UFW enable to avoid lockout."
    return 0
  fi

  local internet_iface=""
  internet_iface="$(ip route get 8.8.8.8 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="dev") print $(i+1)}' | head -n1 || true)"
  [[ -n "$internet_iface" ]] || internet_iface="$(ip route show default 2>/dev/null | awk '/default/ {print $5; exit}' || true)"
  [[ -n "$internet_iface" ]] || { warn "Cannot detect WAN iface; skipping UFW"; return 0; }

  ufw --force reset >/dev/null 2>&1 || true
  ufw default deny incoming >/dev/null 2>&1 || true
  ufw default allow outgoing >/dev/null 2>&1 || true

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
    warn "tailscale0 not found."
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
  warn "Rollback: sudo $0 rollback"
  exit "$code"
}

apply_cmd() {
  need_root "$@"
  trap on_apply_fail ERR
  is_debian_like || die "This script expects Debian/Ubuntu (apt)."

  mkbackup
  snapshot_before

  # 0) hostname prompt FIRST (your request)
  hostname_apply_interactive

  # interactive flags
  if [[ -z "${ARG_USER}" ]]; then
    read_tty ARG_USER "User to create/ensure (leave empty to skip): "
  fi

  if [[ -z "${ARG_DNS_SWITCHER}" ]]; then
    local a="n"
    read_tty a "Run DNS switcher at the end? [y/N]: "
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
    read_tty a "Open WAN only 443 via UFW at the end? [Y/n]: "
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

  hdr "📦 Packages"
  ensure_packages "📦 Packages" \
    curl wget ca-certificates gnupg lsb-release apt-transport-https \
    jq iproute2 ethtool openssl logrotate cron ufw iperf3 git zsh mc

  timezone_apply

  # EARLY: tailscale hand-mode (no sysctl / dns / kernel patches here)
  if [[ "${ARG_TAILSCALE}" == "1" ]]; then
    tailscale_apply_early_handmode
  fi

  if [[ "${ARG_NODE_EXPORTER}" == "1" ]]; then
    node_exporter_apply
  fi

  # user + zsh
  if [[ -n "${ARG_USER}" ]]; then
    create_or_ensure_user "${ARG_USER}"
  fi

  if [[ "${ARG_ZSH_ALL_USERS}" == "1" ]]; then
    zsh_apply_all_users
  else
    warn "zsh setup skipped (zsh-all-users=0)"
  fi

  # docker/remnanode
  if [[ "${ARG_REMNANODE}" == "1" ]]; then
    docker_install
    remnanode_apply
  fi

  if [[ "${ARG_SSH_HARDEN}" == "1" ]]; then
    ssh_harden_apply
  fi

  # service
  iperf3_server_apply

  # END: kernel/sysctl patches + tailscale sysctl patch + dns patch
  tuning_apply_end
  if [[ "${ARG_TAILSCALE}" == "1" ]]; then
    tailscale_sysctl_patch_end
    # Re-check once (still no loops)
    TAILSCALE_IP4="$(tailscale_ip4)"
    if [[ -n "${TAILSCALE_IP4:-}" ]]; then
      ok "tailscale ip -4 (post-patch): ${TAILSCALE_IP4}"
      TAILSCALE_READY="1"
    else
      warn "tailscale ip -4 still empty (post-patch)."
      TAILSCALE_READY="0"
    fi
  fi
  if [[ "${ARG_DNS_SWITCHER}" == "1" ]]; then
    dns_apply
  fi

  hdr "🧹 Autoremove"
  aptq "Autoremove" autoremove --purge

  # LAST: UFW
  ufw_apply_last

  snapshot_after
  print_before_after_all

  hdr "✅ Summary"
  echo "Backup dir: ${backup_dir}"
  if [[ "${ARG_TAILSCALE}" == "1" ]]; then
    echo "Tailscale ready: ${TAILSCALE_READY}"
    echo "Tailscale ip -4: ${TAILSCALE_IP4:-"(empty)"}"
  fi
  if [[ "${USER_CREATED}" == "1" ]]; then
    echo "User created: ${ARG_USER}"
    echo "Password:     ${USER_PASS}"
  fi

  maybe_reboot
}

rollback_cmd() {
  need_root "$@"
  local bdir="${BACKUP_DIR:-}"
  if [[ -z "$bdir" ]]; then
    bdir="$(latest_backup_dir)"
  fi
  [[ -n "$bdir" ]] || die "No backups found under /root/edge-tuning-backup-*"
  hdr "↩️ Rollback"
  echo "Using backup: $bdir"
  restore_manifest "$bdir"
  sysctl --system >/dev/null 2>&1 || true
  systemctl daemon-reexec >/dev/null 2>&1 || true
  systemctl restart systemd-journald >/dev/null 2>&1 || true
  systemctl restart ssh >/dev/null 2>&1 || systemctl restart sshd >/dev/null 2>&1 || true
  ok "Rollback complete"
}

status_cmd() {
  hdr "📌 Status"
  echo "Hostname:   $(hostname 2>/dev/null || true)"
  echo "Timezone:   $(timedatectl show -p Timezone --value 2>/dev/null || true)"
  echo "TCP CC:     $(sysctl -n net.ipv4.tcp_congestion_control 2>/dev/null || echo '-')"
  echo "Qdisc:      $(sysctl -n net.core.default_qdisc 2>/dev/null || echo '-')"
  echo "Forward:    $(sysctl -n net.ipv4.ip_forward 2>/dev/null || echo '-')"
  echo "Conntrack:  $(sysctl -n net.netfilter.nf_conntrack_max 2>/dev/null || echo '-')"
  echo "Swap:       $(_swap_state)"
  echo "Nofile:     $(_nofile_systemd)"
  echo "Journald:   $(_journald_caps)"
  echo "Logrotate:  $(_logrotate_mode)"
  echo "AutoReboot: $(_unattended_reboot_setting)"
  if command -v tailscale >/dev/null 2>&1; then
    echo "Tailscale:  $(tailscale status 2>/dev/null | head -n1 || true)"
    echo "TS ip -4:   $(tailscale ip -4 2>/dev/null | head -n1 || true)"
  fi
  if command -v ufw >/dev/null 2>&1; then
    echo "UFW:        $(ufw status 2>/dev/null | head -n1 || true)"
  fi
}

###############################################################################
# Main
###############################################################################
case "${CMD:-}" in
  apply)    apply_cmd "$@" ;;
  rollback) rollback_cmd "$@" ;;
  status)   status_cmd "$@" ;;
  -h|--help|"") usage; exit 0 ;;
  *) die "Unknown command: ${CMD}. Use: apply|rollback|status" ;;
esac
