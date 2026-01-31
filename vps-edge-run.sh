#!/usr/bin/env bash
set -Eeuo pipefail

###############################################################################
# vps-edge-run.sh
#
# ABSOLUTELY NO WARRANTIES. USE AT YOUR OWN RISK.
###############################################################################

# -------------------------- Pretty logging --------------------------
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

hdr() { echo; color "$c_bold$c_cyan" "$*"; echo; }
die() { err "$*"; exit 1; }

# -------------------------- Root / TTY helpers --------------------------
need_root() {
  [[ "${EUID:-$(id -u)}" -eq 0 ]] || die "Not root. Use: curl ... | sudo bash -s -- apply ..."
}

read_tty() {
  local __var="$1" __prompt="$2" __v=""
  [[ -t 0 && -e /dev/tty ]] || { printf -v "$__var" '%s' ""; return 0; }
  read -rp "$__prompt" __v </dev/tty || true
  printf -v "$__var" '%s' "$__v"
}

# -------------------------- Args --------------------------
CMD="${1:-}"; shift || true

ARG_USER=""
ARG_TIMEZONE="Europe/Moscow"
ARG_REBOOT="0"

ARG_TAILSCALE="0"
ARG_DNS_SWITCHER="0"
ARG_DNS_PROFILE=""        # 1..5 => non-interactive; empty => interactive
ARG_REMNANODE="0"
ARG_SSH_HARDEN="0"
ARG_OPEN_WAN_443="0"

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
    *) die "Unknown arg: $1" ;;
  esac
done

# -------------------------- URLs (assets) --------------------------
ASSET_APT="https://raw.githubusercontent.com/akadorkin/remnanode-install-script/refs/heads/main/assests/apt-bootstrap.sh"
ASSET_HOSTNAME="https://raw.githubusercontent.com/akadorkin/remnanode-install-script/refs/heads/main/assests/hostname-bootstrap.sh"
ASSET_DNS="https://raw.githubusercontent.com/akadorkin/remnanode-install-script/refs/heads/main/assests/dns-bootstrap.sh"
ASSET_KERNEL="https://raw.githubusercontent.com/akadorkin/remnanode-install-script/refs/heads/main/assests/kernel-bootstrap.sh"
ASSET_TAILSCALE="https://raw.githubusercontent.com/akadorkin/remnanode-install-script/refs/heads/main/assests/tailscale-bootstrap.sh"
ASSET_USER="https://raw.githubusercontent.com/akadorkin/remnanode-install-script/refs/heads/main/assests/user-setup.sh"
ASSET_ZSH="https://raw.githubusercontent.com/akadorkin/remnanode-install-script/refs/heads/main/assests/zsh-bootstrap.sh"
ASSET_UFW="https://raw.githubusercontent.com/akadorkin/remnanode-install-script/refs/heads/main/assests/ufw-bootstrap.sh"
ASSET_SSH="https://raw.githubusercontent.com/akadorkin/remnanode-install-script/refs/heads/main/assests/ssh-bootstrap.sh"
ASSET_REMNANODE="https://raw.githubusercontent.com/akadorkin/remnanode-install-script/refs/heads/main/assests/remnanode-bootstrap.sh"

# -------------------------- Logs --------------------------
LOG_DIR="/var/log"
L_APT="${LOG_DIR}/vps-edge-apt.log"
L_HOSTNAME="${LOG_DIR}/vps-edge-hostname.log"
L_DNS="${LOG_DIR}/vps-edge-dns-switcher.log"
L_TS="${LOG_DIR}/vps-edge-tailscale.log"
L_USER="${LOG_DIR}/vps-edge-user.log"
L_ZSH="${LOG_DIR}/vps-edge-zsh.log"
L_UFW="${LOG_DIR}/vps-edge-ufw.log"
L_SSH="${LOG_DIR}/vps-edge-ssh.log"
L_REMNA="${LOG_DIR}/vps-edge-remnanode.log"
L_KERNEL="${LOG_DIR}/vps-edge-tuning.log"
touch "$L_APT" "$L_HOSTNAME" "$L_DNS" "$L_TS" "$L_USER" "$L_ZSH" "$L_UFW" "$L_SSH" "$L_REMNA" "$L_KERNEL" 2>/dev/null || true

ASSETS_TMP="/tmp/vps-edge-assets"
mkdir -p "$ASSETS_TMP"

# statuses for summary
S_APT=99 S_HOSTNAME=99 S_DNS=99 S_TS=99 S_USER=99 S_ZSH=99 S_UFW=99 S_SSH=99 S_REMNA=99 S_KERNEL=99
USER_CREATED="0"
USER_PASS=""

# -------------------------- Small utils for summary --------------------------
host_short() { hostname -s 2>/dev/null || hostname; }

ext_ip() {
  curl -fsSL --max-time 3 https://api.ipify.org 2>/dev/null \
    || curl -fsSL --max-time 3 ifconfig.me 2>/dev/null \
    || true
}

tailscale_ip4() { command -v tailscale >/dev/null 2>&1 && tailscale ip -4 2>/dev/null | head -n1 || true; }

tailscale_dnsname() {
  command -v tailscale >/dev/null 2>&1 || return 0
  if command -v jq >/dev/null 2>&1 && tailscale status --json >/dev/null 2>&1; then
    tailscale status --json 2>/dev/null | jq -r '.Self.DNSName // empty' 2>/dev/null | sed 's/\.$//' || true
    return 0
  fi
  tailscale status 2>/dev/null | awk 'NR==1{print $2}' | sed 's/\.$//' || true
}

ram_gib_rounded() {
  local kb
  kb="$(awk '/MemTotal:/ {print $2}' /proc/meminfo 2>/dev/null || echo 0)"
  awk -v kb="$kb" 'BEGIN{
    gib = kb/1024/1024;
    if (gib < 0.5) { printf "0"; exit }
    printf "%.0f", gib+0.5
  }'
}
cpu_cores() { nproc 2>/dev/null || echo 1; }
root_size_gib() {
  local b
  b="$(df -B1 / 2>/dev/null | awk 'NR==2{print $2}' || echo 0)"
  awk -v b="$b" 'BEGIN{ printf "%.0f", b/1024/1024/1024 }'
}
swap_mib() {
  local b
  b="$(/sbin/swapon --bytes --noheadings 2>/dev/null | awk '{s+=$3} END{print s+0}' || echo 0)"
  awk -v b="$b" 'BEGIN{ printf "%.0f", b/1024/1024 }'
}

dns_profile_from_resolved() {
  local dns
  dns="$(awk -F= 'tolower($1)=="dns"{gsub(/^[[:space:]]+|[[:space:]]+$/,"",$2); print $2}' /etc/systemd/resolved.conf 2>/dev/null | head -n1 || true)"
  [[ -n "$dns" ]] || { echo "-"; return 0; }
  case "$dns" in
    *"8.8.8.8"*1.1.1.1* ) echo "1) Google + Cloudflare" ;;
    *"8.8.8.8"*8.8.4.4* ) echo "2) Google only" ;;
    *"1.1.1.1"*1.0.0.1* ) echo "3) Cloudflare only" ;;
    *"9.9.9.9"*149.112.112.112* ) echo "4) Quad9" ;;
    * ) echo "custom (${dns})" ;;
  esac
}

conntrack_max() { cat /proc/sys/net/netfilter/nf_conntrack_max 2>/dev/null || echo "-"; }

nofile_limit() {
  local v
  v="$(systemctl show --property DefaultLimitNOFILE 2>/dev/null | cut -d= -f2 || true)"
  [[ -n "$v" ]] && { echo "$v"; return 0; }
  ulimit -n 2>/dev/null || echo "-"
}

kernel_profile_from_log() {
  grep -E '^[[:space:]]*Profile[[:space:]]+\|' "$L_KERNEL" 2>/dev/null | tail -n1 | awk -F'|' '{gsub(/^[[:space:]]+|[[:space:]]+$/,"",$2); print $2}' || true
}
kernel_backup_from_log() {
  grep -Eo '/root/edge-tuning-backup-[0-9]{8}-[0-9]{6}' "$L_KERNEL" 2>/dev/null | tail -n1 || true
}
kernel_planned_from_log() {
  awk '
    $0 ~ /^Planned \(computed targets\)/ {in=1; next}
    in && $0 ~ /^[A-Za-z]/ && $0 ~ /\|/ { print $0 }
    in && $0 ~ /^$/ { exit }
  ' "$L_KERNEL" 2>/dev/null || true
}

remnanode_status_line() {
  command -v docker >/dev/null 2>&1 || return 0
  docker ps --filter "name=remnanode" --format '{{.Names}}|{{.Status}}' 2>/dev/null | head -n1 || true
}
remnanode_uptime() {
  # best-effort: from docker status string "Up X ..."
  local line
  line="$(remnanode_status_line || true)"
  [[ -n "$line" ]] || { echo "-"; return 0; }
  echo "$line" | cut -d'|' -f2 | sed -nE 's/^Up[[:space:]]+([^()]*)$/\1/p' | head -n1 || true
}
remnanode_log_health() {
  [[ -d /var/log/remnanode ]] || { echo "ℹ️ no /var/log/remnanode"; return 0; }
  local last
  last="$(tail -n 200 /var/log/remnanode/*.log 2>/dev/null | tr '[:upper:]' '[:lower:]' | grep -E 'error|panic|fatal' | tail -n 1 || true)"
  [[ -n "$last" ]] && echo "⚠️ errors found (check /var/log/remnanode/*.log)" || echo "✅ no obvious errors (last 200 lines)"
}
remnanode_logrotate_policy() {
  if [[ -f /etc/logrotate.d/remnanode ]]; then
    awk 'NF{print}' /etc/logrotate.d/remnanode 2>/dev/null | sed 's/^/  /'
  else
    echo "  - (not configured)"
  fi
}

# -------------------------- Asset runner (LIVE output + logs) --------------------------
# Important:
# - Always show full output to console
# - Always write full output to log
# - If we have a TTY, connect stdin to /dev/tty so assets with `read -p` work
run_asset() {
  local name="$1" url="$2" log_file="$3"
  local tmp="${ASSETS_TMP}/${name}.sh"

  info "Running asset: ${name}"
  : >"$log_file" || true

  if ! curl -fsSL "$url" -o "$tmp" 2>&1 | tee -a "$log_file"; then
    warn "${name} download failed: ${url}"
    return 2
  fi
  chmod +x "$tmp" 2>&1 | tee -a "$log_file" >/dev/null || true

  set +e
  if [[ -e /dev/tty && -t 0 ]]; then
    bash "$tmp" </dev/tty 2>&1 | tee -a "$log_file"
  else
    bash "$tmp" 2>&1 | tee -a "$log_file"
  fi
  local rc=${PIPESTATUS[0]:-0}
  set -e

  [[ $rc -eq 0 ]] && ok "${name} finished" || warn "${name} exited with code=${rc} (see ${log_file})"
  return "$rc"
}

run_asset_with_stdin() {
  local name="$1" url="$2" log_file="$3" stdin_payload="$4"
  local tmp="${ASSETS_TMP}/${name}.sh"

  info "Running asset: ${name}"
  : >"$log_file" || true

  if ! curl -fsSL "$url" -o "$tmp" 2>&1 | tee -a "$log_file"; then
    warn "${name} download failed: ${url}"
    return 2
  fi
  chmod +x "$tmp" 2>&1 | tee -a "$log_file" >/dev/null || true

  set +e
  # feed stdin payload; still mirror everything to console + log
  printf "%b" "$stdin_payload" | bash "$tmp" 2>&1 | tee -a "$log_file"
  local rc=${PIPESTATUS[1]:-0}
  set -e

  [[ $rc -eq 0 ]] && ok "${name} finished" || warn "${name} exited with code=${rc} (see ${log_file})"
  return "$rc"
}

# -------------------------- Timezone --------------------------
timezone_apply() {
  hdr "🕒 Timezone"
  if [[ -n "${ARG_TIMEZONE:-}" ]]; then
    ln -sf "/usr/share/zoneinfo/${ARG_TIMEZONE}" /etc/localtime 2>/dev/null || true
    timedatectl set-timezone "${ARG_TIMEZONE}" >/dev/null 2>&1 || true
    ok "Timezone set to ${ARG_TIMEZONE}"
  fi
}

# -------------------------- Reboot scheduling --------------------------
maybe_reboot() {
  local r="${ARG_REBOOT:-0}"
  case "$r" in
    0|no|none|skip|"") info "Reboot disabled (--reboot=${r})" ;;
    30s|30sec|30) warn "Reboot in 30 seconds"; shutdown -r +0.5 >/dev/null 2>&1 || shutdown -r now ;;
    5m|5min|300)  warn "Reboot in 5 minutes";  shutdown -r +5   >/dev/null 2>&1 || shutdown -r now ;;
    *)            warn "Reboot in ${r}";        shutdown -r +"${r}" >/dev/null 2>&1 || shutdown -r now ;;
  esac
}

# -------------------------- Summary (final) --------------------------
step_status() {
  local rc="${1:-99}"
  if [[ "$rc" -eq 0 ]]; then echo "✅ OK"; else echo "⚠️ WARN (rc=$rc)"; fi
}

print_summary() {
  hdr "🧾 Summary"

  local wan host ram cpu rootg swapm tsip tsname
  host="$(host_short)"
  wan="$(ext_ip)"; [[ -n "$wan" ]] || wan="?"
  ram="$(ram_gib_rounded)"
  cpu="$(cpu_cores)"
  rootg="$(root_size_gib)"
  swapm="$(swap_mib)"
  tsip="$(tailscale_ip4)"
  tsname="$(tailscale_dnsname)"

  echo "🖥️  Host      : ${host}"
  echo "🌍 WAN IP    : ${wan}"
  echo "🧠 CPU/RAM   : ${cpu} cores / ~${ram} GiB"
  echo "💾 Disk /    : ~${rootg} GiB"
  echo "🧊 Swap      : ~${swapm} MiB"
  echo

  echo "🧠 Tailscale : ${tsip:-"-"}"
  echo "🔗 MagicDNS  : ${tsname:-"-"}"
  echo

  echo "🌐 DNS       : $(dns_profile_from_resolved)"
  echo "🔗 Repo DNS  : https://github.com/AndreyTimoschuk/dns-switcher"
  echo

  local kprof kbkp
  kprof="$(kernel_profile_from_log)"; [[ -n "$kprof" ]] || kprof="-"
  kbkp="$(kernel_backup_from_log)"; [[ -n "$kbkp" ]] || kbkp="-"

  echo "🧩 Kernel tuning profile : ${kprof}"
  echo "🧳 Kernel backup dir     : ${kbkp}"
  echo "🔗 Repo tuning           : https://github.com/akadorkin/vps-network-tuning-script"
  echo

  echo "🧱 Limits"
  echo "  🧷 Conntrack max : $(conntrack_max)"
  echo "  📎 Nofile        : $(nofile_limit)"
  echo

  echo "🧾 Planned tuning (from log, if available)"
  local planned
  planned="$(kernel_planned_from_log || true)"
  if [[ -n "$planned" ]]; then
    echo "$planned" | sed 's/^/  /'
  else
    echo "  - (not detected in log)"
  fi
  echo

  echo "👤 User"
  if [[ -n "${ARG_USER:-}" ]]; then
    echo "  🧑 Name     : ${ARG_USER}"
    if [[ "${USER_CREATED:-0}" == "1" ]]; then
      echo "  🔑 Password : ${USER_PASS}"
      echo "  🛡️  Sudo     : NOPASSWD ✅"
      echo "  🐳 Docker   : added to docker group ✅"
      echo "  📁 /opt     : write access granted ✅"
      echo "  🔐 SSH keys : copied (root/ubuntu → ${ARG_USER}) ✅"
    else
      echo "  🔑 Password : (unchanged)"
    fi
  else
    echo "  - (skipped)"
  fi
  echo

  echo "🧩 remnanode"
  if command -v docker >/dev/null 2>&1; then
    local line
    line="$(remnanode_status_line || true)"
    if [[ -n "$line" ]]; then
      echo "  🐳 Container : $(echo "$line" | cut -d'|' -f2)"
      echo "  ⏱️  Uptime    : $(remnanode_uptime)"
      echo "  📄 Logs      : $(remnanode_log_health)"
      echo "  📁 Compose   : /opt/remnanode/docker-compose.yml"
      echo
      echo "  🗂️  Logrotate policy (/etc/logrotate.d/remnanode):"
      remnanode_logrotate_policy
    else
      echo "  - container not running (docker ps name=remnanode is empty)"
    fi
  else
    echo "  - docker not installed"
  fi
  echo

  echo "✅ Steps"
  echo "  🖥️  Hostname   : $(step_status "$S_HOSTNAME")"
  echo "  🕒 Timezone    : ✅ OK"
  echo "  📦 Packages    : $(step_status "$S_APT")"
  echo "  🌐 DNS         : $(step_status "$S_DNS")"
  echo "  🧠 Tailscale   : $(step_status "$S_TS")"
  echo "  👤 User setup  : $(step_status "$S_USER")"
  echo "  💅 Zsh         : $(step_status "$S_ZSH")"
  echo "  🧠 Kernel tune : $(step_status "$S_KERNEL")"
  echo "  🧱 UFW         : $(step_status "$S_UFW")"
  echo "  🔐 SSH/Fail2ban: $(step_status "$S_SSH")"
  echo "  🧩 remnanode   : $(step_status "$S_REMNA")"
  echo

  echo "📄 Logs"
  echo "  🖥️  $L_HOSTNAME"
  echo "  📦 $L_APT"
  echo "  🌐 $L_DNS"
  echo "  🧠 $L_TS"
  echo "  👤 $L_USER"
  echo "  💅 $L_ZSH"
  echo "  🧠 $L_KERNEL"
  echo "  🧱 $L_UFW"
  echo "  🔐 $L_SSH"
  echo "  🧩 $L_REMNA"
}

usage() {
  cat <<'EOF'
Usage:
  sudo ./vps-edge-run.sh apply [flags]

Flags:
  --user <name>
  --timezone <TZ>              Default: Europe/Moscow
  --reboot <0|skip|5m|30s|1m|...> Default: 0 (no reboot)

  --dns-switcher 0|1
  --dns-profile 1..5           If set and dns-switcher=1 => non-interactive auto apply
  --tailscale 0|1
  --remnanode 0|1
  --ssh-harden 0|1
  --open-wan-443 0|1
EOF
}

# -------------------------- Apply flow --------------------------
apply_cmd() {
  need_root "$@"

  # Hostname (interactive asset, early)
  hdr "🖥️  Hostname"
  if [[ -t 0 && -e /dev/tty ]]; then
    if run_asset "hostname-bootstrap" "$ASSET_HOSTNAME" "$L_HOSTNAME"; then S_HOSTNAME=0; else S_HOSTNAME=$?; fi
  else
    warn "No TTY — hostname step skipped"
    S_HOSTNAME=2
  fi

  timezone_apply

  hdr "🏁 Start"
  echo "  🌍 WAN: $(ext_ip || true)"
  echo

  # APT
  hdr "📦 Packages"
  if run_asset "apt-bootstrap" "$ASSET_APT" "$L_APT"; then S_APT=0; else S_APT=$?; fi

  # DNS (non-interactive if profile provided)
  if [[ "${ARG_DNS_SWITCHER}" == "1" ]]; then
    hdr "🌐 DNS switcher"
    if [[ -n "${ARG_DNS_PROFILE:-}" && "${ARG_DNS_PROFILE}" =~ ^[1-5]$ ]]; then
      if run_asset_with_stdin "dns-bootstrap" "$ASSET_DNS" "$L_DNS" $'y\n'"${ARG_DNS_PROFILE}"$'\n'; then
        S_DNS=0
      else
        S_DNS=$?
      fi
      ok "dns-switcher auto-applied (profile ${ARG_DNS_PROFILE})"
    else
      if run_asset "dns-bootstrap" "$ASSET_DNS" "$L_DNS"; then S_DNS=0; else S_DNS=$?; fi
    fi
  else
    S_DNS=0
  fi

  # Tailscale (DO NOT TOUCH ASSET; just run it and show everything)
  if [[ "${ARG_TAILSCALE}" == "1" ]]; then
    hdr "🧠 Tailscale"
    if run_asset "tailscale-bootstrap" "$ASSET_TAILSCALE" "$L_TS"; then S_TS=0; else S_TS=$?; fi
  else
    S_TS=0
  fi

  # User setup
  if [[ -n "${ARG_USER:-}" ]]; then
    hdr "👤 User setup"
    export USER_NAME="${ARG_USER}"
    if run_asset "user-setup" "$ASSET_USER" "$L_USER"; then
      S_USER=0
    else
      S_USER=$?
    fi
    USER_CREATED="$(grep -E '^USER_CREATED=' "$L_USER" 2>/dev/null | tail -n1 | cut -d= -f2 | tr -d '\r' || echo 0)"
    USER_PASS="$(grep -E '^USER_PASS=' "$L_USER" 2>/dev/null | tail -n1 | cut -d= -f2- | tr -d '\r' || true)"
    [[ -z "${USER_CREATED:-}" ]] && USER_CREATED="0"
  else
    S_USER=0
  fi

  # Zsh
  hdr "💅 Zsh"
  if run_asset "zsh-bootstrap" "$ASSET_ZSH" "$L_ZSH"; then S_ZSH=0; else S_ZSH=$?; fi

  # Kernel tuning
  hdr "🧠 Kernel + system tuning"
  if run_asset "kernel-bootstrap" "$ASSET_KERNEL" "$L_KERNEL"; then
    S_KERNEL=0
  else
    S_KERNEL=$?
    warn "kernel tuning returned rc=$S_KERNEL — continuing"
  fi

  # UFW
  if [[ "${ARG_OPEN_WAN_443}" == "1" || "${ARG_TAILSCALE}" == "1" ]]; then
    hdr "🧱 UFW"
    export OPEN_WAN_443="${ARG_OPEN_WAN_443}"
    if run_asset "ufw-bootstrap" "$ASSET_UFW" "$L_UFW"; then S_UFW=0; else S_UFW=$?; fi
  else
    S_UFW=0
  fi

  # SSH hardening + fail2ban
  if [[ "${ARG_SSH_HARDEN}" == "1" ]]; then
    hdr "🔐 SSH hardening + fail2ban"
    if run_asset "ssh-bootstrap" "$ASSET_SSH" "$L_SSH"; then S_SSH=0; else S_SSH=$?; fi
  else
    S_SSH=0
  fi

  # remnanode
  if [[ "${ARG_REMNANODE}" == "1" ]]; then
    hdr "🧩 remnanode"
    if run_asset "remnanode-bootstrap" "$ASSET_REMNANODE" "$L_REMNA"; then S_REMNA=0; else S_REMNA=$?; fi
  else
    S_REMNA=0
  fi

  print_summary
  maybe_reboot
}

# -------------------------- Main --------------------------
case "$CMD" in
  apply) apply_cmd ;;
  ""|help|-h|--help) usage; exit 0 ;;
  *) usage; exit 1 ;;
esac