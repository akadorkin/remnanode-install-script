#!/usr/bin/env bash
set -Eeuo pipefail

# -----------------------------------------------------------------------------
# vps-edge-run.sh
#
# Orchestrator that downloads and runs small "assets" scripts.
# NO WARRANTIES. USE AT YOUR OWN RISK.
# -----------------------------------------------------------------------------

###############################################################################
# Basics / logging
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

color() { local code="$1"; shift; if _is_tty; then printf "%s%s%s" "$code" "$*" "$c_reset"; else printf "%s" "$*"; fi; }
_pfx() { _is_tty && printf "%s%s%s" "${c_dim}" "$(ts) " "${c_reset}" || true; }

ok()   { _pfx; color "$c_grn" "✅ OK";    printf " %s\n" "$*"; }
info() { _pfx; color "$c_cyan" "ℹ️ ";     printf " %s\n" "$*"; }
warn() { _pfx; color "$c_yel" "⚠️  WARN"; printf " %s\n" "$*"; }
err()  { _pfx; color "$c_red" "🛑 ERROR"; printf " %s\n" "$*"; }
die()  { err "$*"; exit 1; }
hdr()  { echo; color "$c_bold$c_cyan" "$*"; echo; }

need_root() {
  [[ "${EUID:-$(id -u)}" -eq 0 ]] || die "Run as root (use sudo)."
}

read_tty() {
  local __var="$1" __prompt="$2" __v=""
  [[ -t 0 ]] || { printf -v "$__var" '%s' ""; return 0; }
  read -rp "$__prompt" __v </dev/tty || true
  printf -v "$__var" '%s' "$__v"
}

###############################################################################
# Args
###############################################################################
CMD="${1:-}"; shift || true

ARG_USER=""
ARG_TIMEZONE="Europe/Moscow"
ARG_REBOOT="0"

ARG_TAILSCALE=""         # 0/1, empty => interactive default: 1
ARG_DNS_SWITCHER=""      # 0/1, empty => interactive default: 0
ARG_DNS_PROFILE=""       # 1..5, empty => let dns script be interactive
ARG_REMNANODE=""         # 0/1, empty => interactive default: 0
ARG_SSH_HARDEN=""        # 0/1, empty => interactive default: 0
ARG_OPEN_WAN_443=""      # 0/1, empty => interactive default: 1

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
  sudo ./vps-edge-run.sh apply [flags]

Flags:
  --user <name>              Ensure user, sudo NOPASSWD, docker group, ssh key copy, /opt rights
  --timezone <TZ>            Default: Europe/Moscow
  --reboot 0|skip|5m|30s     Default: 0 (disabled)

  --dns-switcher 0|1         Run DNS switcher (dns-bootstrap.sh)
  --dns-profile 1..5         If set => auto feed "y" + profile. If empty => interactive.

  --tailscale 0|1            Run tailscale-bootstrap.sh (interactive auth URL flow)
  --remnanode 0|1            Run remnanode-bootstrap.sh (may ask for SECRET_KEY if compose missing)
  --ssh-harden 0|1           Run ssh-bootstrap.sh (fail2ban+recidive+sshd hardening)
  --open-wan-443 0|1         UFW: allow inbound 443 tcp/udp on WAN only; allow all on tailscale0. Outbound WAN allowed.

Example:
  curl -fsSL .../vps-edge-run.sh | sudo bash -s -- apply --user akadorkin --tailscale=1 --dns-switcher=1 --dns-profile=1 --remnanode=1 --ssh-harden=1 --open-wan-443=1 --reboot=0
EOF
}

###############################################################################
# Defaults if not provided (interactive, but sane)
###############################################################################
auto_yesno() {
  local __var="$1" prompt="$2" dflt="$3" in=""
  if [[ -n "${!__var:-}" ]]; then return 0; fi
  if [[ -t 0 ]]; then
    read_tty in "$prompt"
    in="${in:-$dflt}"
    in="${in,,}"
    [[ "$in" == "y" || "$in" == "yes" || "$in" == "1" ]] && printf -v "$__var" '%s' "1" || printf -v "$__var" '%s' "0"
  else
    # non-tty: pick defaults
    printf -v "$__var" '%s' "$dflt"
  fi
}

###############################################################################
# Asset URLs (given by you)
###############################################################################
ASSET_APT_URL="https://raw.githubusercontent.com/akadorkin/remnanode-install-script/refs/heads/main/assests/apt-bootstrap.sh"
ASSET_DNS_URL="https://raw.githubusercontent.com/akadorkin/remnanode-install-script/refs/heads/main/assests/dns-bootstrap.sh"
ASSET_KERNEL_URL="https://raw.githubusercontent.com/akadorkin/remnanode-install-script/refs/heads/main/assests/kernel-bootstrap.sh"
ASSET_PRINT_URL="https://raw.githubusercontent.com/akadorkin/remnanode-install-script/refs/heads/main/assests/print-summary.sh"
ASSET_REMNA_URL="https://raw.githubusercontent.com/akadorkin/remnanode-install-script/refs/heads/main/assests/remnanode-bootstrap.sh"
ASSET_SSH_URL="https://raw.githubusercontent.com/akadorkin/remnanode-install-script/refs/heads/main/assests/ssh-bootstrap.sh"
ASSET_TS_URL="https://raw.githubusercontent.com/akadorkin/remnanode-install-script/refs/heads/main/assests/tailscale-bootstrap.sh"
ASSET_UFW_URL="https://raw.githubusercontent.com/akadorkin/remnanode-install-script/refs/heads/main/assests/ufw-bootstrap.sh"
ASSET_USER_URL="https://raw.githubusercontent.com/akadorkin/remnanode-install-script/refs/heads/main/assests/user-setup.sh"
ASSET_ZSH_URL="https://raw.githubusercontent.com/akadorkin/remnanode-install-script/refs/heads/main/assests/zsh-bootstrap.sh"

###############################################################################
# Paths / logs / backup
###############################################################################
ASSETS_DIR="/opt/remnanode-install-script/assets-cache"
mkdir -p "$ASSETS_DIR"

BACKUP_DIR="/root/edge-tuning-backup-$(date +%Y%m%d-%H%M%S)"
MANIFEST_PATH="${BACKUP_DIR}/MANIFEST.tsv"
mkdir -p "$BACKUP_DIR"
: >"$MANIFEST_PATH" || true

APT_LOG="/var/log/vps-edge-apt.log"
DNS_LOG="/var/log/vps-edge-dns-switcher.log"
TS_LOG="/var/log/vps-edge-tailscale.log"
DOCKER_LOG="/var/log/vps-edge-docker.log"
TUNE_LOG="/var/log/vps-edge-tuning.log"
ERR_LOG="/var/log/vps-edge-error.log"

touch "$APT_LOG" "$DNS_LOG" "$TS_LOG" "$DOCKER_LOG" "$TUNE_LOG" "$ERR_LOG" 2>/dev/null || true

###############################################################################
# Helpers: geo + tailscale status
###############################################################################
host_short() { hostname -s 2>/dev/null || hostname; }

ext_ip() {
  curl -fsSL --max-time 3 https://api.ipify.org 2>/dev/null \
    || curl -fsSL --max-time 3 ifconfig.me 2>/dev/null \
    || true
}

country_flag() {
  local cc="${1:-}"
  cc="${cc^^}"
  if [[ ! "$cc" =~ ^[A-Z]{2}$ ]]; then printf "🏳️"; return 0; fi
  awk -v cc="$cc" 'BEGIN{
    o1 = ord(substr(cc,1,1)); o2 = ord(substr(cc,2,1));
    cp1 = 0x1F1E6 + o1 - 65; cp2 = 0x1F1E6 + o2 - 65;
    printf "%c%c", cp1, cp2
  }
  function ord(c){ return index("ABCDEFGHIJKLMNOPQRSTUVWXYZ", c)+64 }'
}

geo_lookup() {
  # Outputs: CC|COUNTRY|REGION|CITY|ORG
  command -v jq >/dev/null 2>&1 || { printf "||||"; return 0; }
  local ip="${1:-}" out=""
  out="$(curl -fsSL --max-time 3 "https://ipinfo.io/${ip}/json" 2>/dev/null || true)"
  if [[ -n "$out" ]]; then
    local cc region city org
    cc="$(printf "%s" "$out" | jq -r '.country // empty' 2>/dev/null || true)"
    region="$(printf "%s" "$out" | jq -r '.region // empty' 2>/dev/null || true)"
    city="$(printf "%s" "$out" | jq -r '.city // empty' 2>/dev/null || true)"
    org="$(printf "%s" "$out" | jq -r '.org // empty' 2>/dev/null || true)"
    if [[ -n "$cc" || -n "$city" || -n "$org" ]]; then
      printf "%s|%s|%s|%s|%s" "${cc:-}" "${cc:-}" "${region:-}" "${city:-}" "${org:-}"
      return 0
    fi
  fi

  out="$(curl -fsSL --max-time 3 "http://ip-api.com/json/${ip}?fields=status,countryCode,country,regionName,city,as,isp,org" 2>/dev/null || true)"
  if [[ -n "$out" ]]; then
    local status cc country region city as isp org prov
    status="$(printf "%s" "$out" | jq -r '.status // empty' 2>/dev/null || true)"
    if [[ "$status" == "success" ]]; then
      cc="$(printf "%s" "$out" | jq -r '.countryCode // empty' 2>/dev/null || true)"
      country="$(printf "%s" "$out" | jq -r '.country // empty' 2>/dev/null || true)"
      region="$(printf "%s" "$out" | jq -r '.regionName // empty' 2>/dev/null || true)"
      city="$(printf "%s" "$out" | jq -r '.city // empty' 2>/dev/null || true)"
      as="$(printf "%s" "$out" | jq -r '.as // empty' 2>/dev/null || true)"
      isp="$(printf "%s" "$out" | jq -r '.isp // empty' 2>/dev/null || true)"
      org="$(printf "%s" "$out" | jq -r '.org // empty' 2>/dev/null || true)"
      prov="$as"; [[ -z "$prov" ]] && prov="$org"; [[ -z "$prov" ]] && prov="$isp"
      printf "%s|%s|%s|%s|%s" "${cc:-}" "${country:-}" "${region:-}" "${city:-}" "${prov:-}"
      return 0
    fi
  fi

  printf "||||"
}

tailscale_ip4() {
  command -v tailscale >/dev/null 2>&1 || return 0
  tailscale ip -4 2>/dev/null | head -n1 || true
}
tailscale_magicdns_name() {
  command -v tailscale >/dev/null 2>&1 || return 0
  local name=""
  if tailscale status --json >/dev/null 2>&1 && command -v jq >/dev/null 2>&1; then
    name="$(tailscale status --json 2>/dev/null | jq -r '.Self.DNSName // empty' 2>/dev/null || true)"
  fi
  name="${name%.}"
  echo "$name"
}

###############################################################################
# Snapshot (Before/After) collection (so summary is never empty)
###############################################################################
_sysctl_get() { sysctl -n "$1" 2>/dev/null || true; }

_get_qdisc() { _sysctl_get net.core.default_qdisc; }
_get_tcp_cc() { _sysctl_get net.ipv4.tcp_congestion_control; }
_get_forward() { _sysctl_get net.ipv4.ip_forward; }
_get_conntrack() { _sysctl_get net.netfilter.nf_conntrack_max; }
_get_tw() { _sysctl_get net.ipv4.tcp_max_tw_buckets; }
_get_swappiness() { _sysctl_get vm.swappiness; }

_get_swap() {
  local s
  s="$(/sbin/swapon --noheadings --show=NAME,SIZE 2>/dev/null | awk '{$1=$1; print}' | tr '\n' ';' | sed 's/;$//' || true)"
  [[ -n "$s" ]] && echo "$s" || echo "none"
}

_get_nofile_systemd() {
  local n=""
  n="$(systemctl show --property DefaultLimitNOFILE 2>/dev/null | cut -d= -f2 || true)"
  [[ -n "$n" ]] && echo "$n" || echo "-"
}

_get_journald_limits() {
  # best-effort: show SystemMaxUse/RuntimeMaxUse if present
  local f="/etc/systemd/journald.conf"
  [[ -f "$f" ]] || { echo "-"; return 0; }
  local a b
  a="$(grep -E '^\s*SystemMaxUse=' "$f" 2>/dev/null | tail -n1 | cut -d= -f2 | tr -d ' ' || true)"
  b="$(grep -E '^\s*RuntimeMaxUse=' "$f" 2>/dev/null | tail -n1 | cut -d= -f2 | tr -d ' ' || true)"
  [[ -z "$a" && -z "$b" ]] && echo "-" || echo "${a:-?}/${b:-?}"
}

_get_logrotate_hint() {
  # best-effort: just show if daily/rotate in /etc/logrotate.conf
  local f="/etc/logrotate.conf"
  [[ -f "$f" ]] || { echo "-"; return 0; }
  local rot freq
  rot="$(grep -E '^\s*rotate\s+[0-9]+' "$f" 2>/dev/null | tail -n1 | awk '{print $2}' || true)"
  if grep -qE '^\s*daily\s*$' "$f" 2>/dev/null; then freq="daily"
  elif grep -qE '^\s*weekly\s*$' "$f" 2>/dev/null; then freq="weekly"
  elif grep -qE '^\s*monthly\s*$' "$f" 2>/dev/null; then freq="monthly"
  else freq="-"
  fi
  [[ -n "$rot" ]] && echo "${freq} / rotate ${rot}" || echo "${freq}"
}

_get_unattended() {
  local reboot time
  reboot="$(grep -Rhs 'Unattended-Upgrade::Automatic-Reboot' /etc/apt/apt.conf.d/*.conf 2>/dev/null \
    | sed -nE 's/.*Automatic-Reboot\s+"([^"]+)".*/\1/p' | tail -n1 || true)"
  time="$(grep -Rhs 'Unattended-Upgrade::Automatic-Reboot-Time' /etc/apt/apt.conf.d/*.conf 2>/dev/null \
    | sed -nE 's/.*Automatic-Reboot-Time\s+"([^"]+)".*/\1/p' | tail -n1 || true)"
  [[ -z "${reboot:-}" ]] && reboot="-"
  [[ -z "${time:-}" ]] && time="-"
  echo "${reboot}|${time}"
}

snapshot_before() {
  B_TCP="$(_get_tcp_cc)"
  B_QDISC="$(_get_qdisc)"
  B_FORWARD="$(_get_forward)"
  B_CONNTRACK="$(_get_conntrack)"
  B_TW="$(_get_tw)"
  B_SWAPPINESS="$(_get_swappiness)"
  B_SWAP="$(_get_swap)"
  B_NOFILE="$(_get_nofile_systemd)"
  B_JOURNALD="$(_get_journald_limits)"
  B_LOGROTATE="$(_get_logrotate_hint)"
  local ua; ua="$(_get_unattended)"
  B_AUTOREBOOT="${ua%%|*}"
  B_REBOOT_TIME="${ua##*|}"
}

snapshot_after() {
  A_TCP="$(_get_tcp_cc)"
  A_QDISC="$(_get_qdisc)"
  A_FORWARD="$(_get_forward)"
  A_CONNTRACK="$(_get_conntrack)"
  A_TW="$(_get_tw)"
  A_SWAPPINESS="$(_get_swappiness)"
  A_SWAP="$(_get_swap)"
  A_NOFILE="$(_get_nofile_systemd)"
  A_JOURNALD="$(_get_journald_limits)"
  A_LOGROTATE="$(_get_logrotate_hint)"
  local ua; ua="$(_get_unattended)"
  A_AUTOREBOOT="${ua%%|*}"
  A_REBOOT_TIME="${ua##*|}"
}

###############################################################################
# Download + run assets
###############################################################################
fetch_asset() {
  local name="$1" url="$2"
  local dst="${ASSETS_DIR}/${name}"
  if [[ -s "$dst" ]]; then
    return 0
  fi
  info "Downloading asset: $name"
  if ! curl -fsSL "$url" -o "$dst" >>"$ERR_LOG" 2>&1; then
    die "Failed to download: $url"
  fi
  chmod +x "$dst" || true
}

run_asset() {
  local name="$1"; shift
  local logf="$1"; shift
  local file="${ASSETS_DIR}/${name}"

  [[ -x "$file" ]] || die "Asset not found/executable: $file"
  info "Running: ${name} $*"
  if bash "$file" "$@" >>"$logf" 2>&1; then
    ok "${name} done"
  else
    err "${name} failed (tail follows)"
    tail -n 120 "$logf" || true
    die "${name} failed. Full log: $logf"
  fi
}

###############################################################################
# Reboot scheduling
###############################################################################
maybe_reboot() {
  local r="${ARG_REBOOT:-0}"
  case "$r" in
    0|no|none|skip|"")
      REBOOT_LINE="$(ts) WARN Reboot disabled (--reboot=${r:-0})"
      warn "Reboot disabled (--reboot=${r:-0})"
      ;;
    30s|30sec|30)
      REBOOT_LINE="$(ts) WARN Reboot scheduled in 30 seconds"
      warn "Reboot in 30 seconds"
      shutdown -r +0.5 >/dev/null 2>&1 || shutdown -r now
      ;;
    5m|5min|300)
      REBOOT_LINE="$(ts) WARN Reboot scheduled in 5 minutes"
      warn "Reboot in 5 minutes"
      shutdown -r +5 >/dev/null 2>&1 || shutdown -r now
      ;;
    *)
      REBOOT_LINE="$(ts) WARN Reboot scheduled in ${r}"
      warn "Reboot in ${r}"
      shutdown -r +"${r}" >/dev/null 2>&1 || shutdown -r now
      ;;
  esac
}

###############################################################################
# Main apply
###############################################################################
apply_cmd() {
  need_root

  # interactive defaults
  auto_yesno ARG_DNS_SWITCHER "Run DNS switcher? [y/N]: " "0"
  auto_yesno ARG_TAILSCALE    "Enable Tailscale? [Y/n]: " "1"
  auto_yesno ARG_REMNANODE    "Install/start remnanode? [y/N]: " "0"
  auto_yesno ARG_SSH_HARDEN   "Apply SSH hardening + fail2ban? [y/N]: " "0"
  auto_yesno ARG_OPEN_WAN_443 "Open WAN inbound 443 only (tcp/udp) via UFW? [Y/n]: " "1"

  # If user not passed, ask once (optional)
  if [[ -z "${ARG_USER:-}" && -t 0 ]]; then
    read_tty ARG_USER "User to create/ensure (leave empty to skip): "
  fi

  # Fetch assets
  fetch_asset "apt-bootstrap.sh"       "$ASSET_APT_URL"
  fetch_asset "dns-bootstrap.sh"       "$ASSET_DNS_URL"
  fetch_asset "tailscale-bootstrap.sh" "$ASSET_TS_URL"
  fetch_asset "remnanode-bootstrap.sh" "$ASSET_REMNA_URL"
  fetch_asset "user-setup.sh"          "$ASSET_USER_URL"
  fetch_asset "zsh-bootstrap.sh"       "$ASSET_ZSH_URL"
  fetch_asset "kernel-bootstrap.sh"    "$ASSET_KERNEL_URL"
  fetch_asset "ufw-bootstrap.sh"       "$ASSET_UFW_URL"
  fetch_asset "ssh-bootstrap.sh"       "$ASSET_SSH_URL"
  fetch_asset "print-summary.sh"       "$ASSET_PRINT_URL"

  # Load print summary (so we can call print_end_report at the end)
  # shellcheck disable=SC1090
  source "${ASSETS_DIR}/print-summary.sh"

  snapshot_before

  # APT bootstrap (always)
  hdr "📦 APT bootstrap"
  : >"$APT_LOG" || true
  run_asset "apt-bootstrap.sh" "$APT_LOG" apply

  # Timezone (simple, local)
  hdr "🕒 Timezone"
  if [[ -n "${ARG_TIMEZONE:-}" ]]; then
    ln -sf "/usr/share/zoneinfo/${ARG_TIMEZONE}" /etc/localtime >>"$ERR_LOG" 2>&1 || true
    timedatectl set-timezone "${ARG_TIMEZONE}" >>"$ERR_LOG" 2>&1 || true
    ok "Timezone set to ${ARG_TIMEZONE}"
  fi

  # DNS (optional)
  if [[ "${ARG_DNS_SWITCHER}" == "1" ]]; then
    hdr "🌐 DNS bootstrap"
    : >"$DNS_LOG" || true
    if [[ -n "${ARG_DNS_PROFILE:-}" ]]; then
      # pass profile to asset if it supports it; also export for convenience
      export DNS_PROFILE="${ARG_DNS_PROFILE}"
      run_asset "dns-bootstrap.sh" "$DNS_LOG" apply --dns-profile="${ARG_DNS_PROFILE}"
    else
      # interactive selection inside the dns script
      run_asset "dns-bootstrap.sh" "$DNS_LOG" apply
    fi
  else
    warn "DNS bootstrap skipped (--dns-switcher=0)"
  fi

  # Tailscale (optional)
  if [[ "${ARG_TAILSCALE}" == "1" ]]; then
    hdr "🧠 Tailscale bootstrap"
    : >"$TS_LOG" || true
    run_asset "tailscale-bootstrap.sh" "$TS_LOG" apply
  else
    warn "Tailscale skipped (--tailscale=0)"
  fi

  # User setup (optional)
  if [[ -n "${ARG_USER:-}" ]]; then
    hdr "👤 User setup"
    # user-setup should:
    # - create user if missing, generate password, sudo NOPASSWD
    # - add to docker group
    # - copy authorized_keys from root/ubuntu if exists
    # - chmod/chown /opt for write access
    run_asset "user-setup.sh" "$ERR_LOG" apply --user="${ARG_USER}"
    # Try to load info from a conventional env file if your asset writes it
    # (optional, best-effort)
    if [[ -f /tmp/vps-edge-user.env ]]; then
      # shellcheck disable=SC1091
      source /tmp/vps-edge-user.env || true
    fi
  else
    warn "User setup skipped (no --user)"
  fi

  # Zsh (optional-but-usually yes; keep it always here as per your plan)
  hdr "💅 Zsh bootstrap"
  run_asset "zsh-bootstrap.sh" "$ERR_LOG" apply

  # Kernel tuning (always)
  hdr "🧠 Kernel bootstrap"
  : >"$TUNE_LOG" || true
  run_asset "kernel-bootstrap.sh" "$TUNE_LOG" apply

  # UFW (always)
  hdr "🧱 UFW bootstrap"
  : >"$ERR_LOG" || true
  run_asset "ufw-bootstrap.sh" "$ERR_LOG" apply --open-wan-443="${ARG_OPEN_WAN_443}" --tailscale="${ARG_TAILSCALE}"

  # SSH hardening + fail2ban (optional)
  if [[ "${ARG_SSH_HARDEN}" == "1" ]]; then
    hdr "🔐 SSH + fail2ban bootstrap"
    run_asset "ssh-bootstrap.sh" "$ERR_LOG" apply
  else
    warn "SSH hardening skipped (--ssh-harden=0)"
  fi

  # remnanode (optional)
  if [[ "${ARG_REMNANODE}" == "1" ]]; then
    hdr "🧩 Remnanode bootstrap"
    run_asset "remnanode-bootstrap.sh" "$DOCKER_LOG" apply
  else
    warn "remnanode skipped (--remnanode=0)"
  fi

  snapshot_after

  # Fill vars for print-summary.sh
  HOST_SHORT="$(host_short)"

  WAN_IP="$(ext_ip)"
  [[ -n "$WAN_IP" ]] || WAN_IP="?"
  gl="$(geo_lookup "$WAN_IP")"
  GEO_CC="${gl%%|*}"
  GEO_CITY="$(echo "$gl" | cut -d'|' -f4)"
  GEO_REGION="$(echo "$gl" | cut -d'|' -f3)"
  GEO_PROVIDER="$(echo "$gl" | cut -d'|' -f5)"
  GEO_FLAG="$(country_flag "$GEO_CC")"

  TS_IP="$(tailscale_ip4 || true)"
  TS_NAME="$(tailscale_magicdns_name || true)"

  REMNA_COMPOSE_PATH="/opt/remnanode/docker-compose.yml"
  REMNA_STATUS_LINE=""
  if command -v docker >/dev/null 2>&1; then
    # nice short line
    s="$(docker ps --format '{{.Names}} {{.Status}}' 2>/dev/null | awk '$1=="remnanode"{ $1=""; sub(/^ /,""); print "remnanode " $0 }' | head -n1 || true)"
    [[ -n "$s" ]] && REMNA_STATUS_LINE="$s"
  fi

  # user-setup asset can export these (best-effort):
  # USER_CREATED=1/0, USER_PASS=...
  : "${USER_CREATED:=0}"
  : "${USER_PASS:=}"
  : "${ARG_USER:=$ARG_USER}"

  maybe_reboot

  # Finally print end report (this is the part you want on screenshot)
  print_end_report
}

###############################################################################
# Main
###############################################################################
case "$CMD" in
  apply) apply_cmd ;;
  ""|help|-h|--help) usage; exit 0 ;;
  *)
    usage
    exit 1
    ;;
esac
