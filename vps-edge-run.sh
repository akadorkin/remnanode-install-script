❯ cat /root/vps-edge-run-final-production-v5-clean.sh
#!/usr/bin/env bash
set -Eeuo pipefail

print_final_summary_tail() {
  set +e
  set +o pipefail 2>/dev/null || true

  public_ip="$(curl -4 -fsS --max-time 5 https://api.ipify.org 2>/dev/null || true)"
  geo="$(curl -4 -fsS --max-time 7 https://ipinfo.io/json 2>/dev/null || true)"

  city="$(echo "$geo" | jq -r '.city // "unknown"' 2>/dev/null || echo unknown)"
  region="$(echo "$geo" | jq -r '.region // empty' 2>/dev/null || true)"
  country="$(echo "$geo" | jq -r '.country // "unknown"' 2>/dev/null || echo unknown)"
  org="$(echo "$geo" | jq -r '.org // "unknown"' 2>/dev/null || echo unknown)"

  flag=""
  if [[ "$country" =~ ^[A-Z][A-Z]$ ]]; then
    flag="$(python3 - <<PY2 2>/dev/null || true
cc="$country"
print("".join(chr(127397 + ord(c)) for c in cc))
PY2
)"
  fi

  ts_ip="$(tailscale ip -4 2>/dev/null | awk 'NR==1{print; exit}')"
  ts_dns="$(tailscale status --json 2>/dev/null | jq -r '.Self.DNSName // empty' 2>/dev/null || true)"
  ts_state="$(tailscale status --json 2>/dev/null | jq -r '.BackendState // empty' 2>/dev/null || true)"

  remna_state="$(docker inspect -f '{{.State.Status}}' remnanode 2>/dev/null || echo not-found)"
  docker_state="$(systemctl is-active docker 2>/dev/null || echo unknown)"
  if systemctl list-unit-files 2>/dev/null | grep -q '^haproxy.service'; then
    haproxy_state="$(systemctl is-active haproxy 2>/dev/null || echo unknown)"
  else
    haproxy_state="not-installed"
  fi
  fail2ban_state="$(systemctl is-active fail2ban 2>/dev/null || echo unknown)"
  geo_timer_state="$(systemctl is-active update-roscomvpn-geo.timer 2>/dev/null || echo unknown)"
  node_exporter_state="$(systemctl is-active node_exporter 2>/dev/null || echo unknown)"
  if ufw status 2>/dev/null | grep -q "Status: active"; then
    ufw_state="✅ active"
  else
    ufw_state="⚠ inactive"
  fi

  cert_subject="not available"
  cert_expire_raw=""
  cert_expire="not available"
  domain="${DOMAIN:-}"

  if [[ -f /opt/certbot/certs/live/remnanode/fullchain.pem ]]; then
    cert_subject="$(openssl x509 -in /opt/certbot/certs/live/remnanode/fullchain.pem -noout -subject 2>/dev/null | sed 's/^subject=//')"
    cert_expire_raw="$(openssl x509 -in /opt/certbot/certs/live/remnanode/fullchain.pem -noout -enddate 2>/dev/null | sed 's/^notAfter=//')"
    cert_expire="$cert_expire_raw"
    cert_days_left="$(( ( $(date -d "$cert_expire_raw" +%s 2>/dev/null || echo 0) - $(date +%s) ) / 86400 ))"
    [[ -z "$domain" ]] && domain="$(echo "$cert_subject" | sed -n 's/.*CN *= *\([^,\/]*\).*/\1/p')"
  fi

  [[ -z "$domain" && -f /opt/certbot/certs/renewal/remnanode.conf ]] && \
    domain="$(grep -E '^domains ?=' /opt/certbot/certs/renewal/remnanode.conf | head -n1 | cut -d= -f2- | xargs)"

  tcp_cc="$(sysctl -n net.ipv4.tcp_congestion_control 2>/dev/null || echo unknown)"
  qdisc="$(sysctl -n net.core.default_qdisc 2>/dev/null || echo unknown)"
  forward="$(sysctl -n net.ipv4.ip_forward 2>/dev/null || echo unknown)"
  conntrack="$(sysctl -n net.netfilter.nf_conntrack_max 2>/dev/null || echo unknown)"
  tw_buckets="$(sysctl -n net.ipv4.tcp_max_tw_buckets 2>/dev/null || echo unknown)"
  nofile="$(ulimit -n 2>/dev/null || echo unknown)"
  swap="$(swapon --show --noheadings --bytes 2>/dev/null | awk '{sum+=$3} END{if(sum>0) printf "%.0fG", sum/1024/1024/1024; else print "none"}')"
  journald="$(grep -E '^(SystemMaxUse|RuntimeMaxUse)=' /etc/systemd/journald.conf /etc/systemd/journald.conf.d/*.conf 2>/dev/null | awk -F= '{print $2}' | paste -sd ' / ' -)"
  [[ -z "$journald" ]] && journald="unknown"

  svc_icon() {
    case "$1" in
      active|running) echo "✅ $1" ;;
      inactive) echo "⏸ $1" ;;
      not-found|unknown|"") echo "❔ ${1:-unknown}" ;;
      *) echo "⚠️ $1" ;;
    esac
  }

  echo
  echo "============================================================"
  echo " 🚀 DEPLOY COMPLETED"
  echo "============================================================"
  echo
  echo "🌍 Server"
  echo "------------------------------------------------------------"
  printf "Hostname        : %s\n" "$(hostname)"
  printf "Public IPv4     : %s\n" "${public_ip:-unknown}"
  printf "Location        : %s %s%s (%s)\n" "${flag:-}" "$city" "${region:+, $region}" "$country"
  printf "Provider        : %s\n" "$org"
  echo
  echo "🔒 Network"
  echo "------------------------------------------------------------"
  printf "Tailscale IPv4  : %s\n" "${ts_ip:-not available}"
  printf "MagicDNS        : %s\n" "${ts_dns:-not available}"
  printf "State           : %s\n" "${ts_state:-not available}"
  echo
  echo "🐳 Services"
  echo "------------------------------------------------------------"
  printf "RemnaNode       : %s\n" "$(svc_icon "$remna_state")"
  printf "Docker          : %s\n" "$(svc_icon "$docker_state")"
  printf "HAProxy         : %s\n" "$(svc_icon "$haproxy_state")"
  printf "Fail2ban        : %s\n" "$(svc_icon "$fail2ban_state")"
  printf "Geo Timer       : %s\n" "$(svc_icon "$geo_timer_state")"
  printf "Node Exporter   : %s\n" "$(svc_icon "$node_exporter_state")"
  echo
  echo "🔐 TLS"
  echo "------------------------------------------------------------"
  printf "Domain          : %s\n" "${domain:-unknown}"
  printf "Certificate     : %s\n" "$([[ -f /opt/certbot/certs/live/remnanode/fullchain.pem ]] && echo "✅ installed" || echo "❌ missing")"
  printf "Subject         : %s\n" "$cert_subject"
  printf "Expires         : %s\n" "$cert_expire"
  printf "Days left       : %s\n" "${cert_days_left:-unknown}"
  echo
  uptime_pretty="$(uptime -p 2>/dev/null | sed 's/^up //' || echo unknown)"
  kernel_ver="$(uname -r 2>/dev/null || echo unknown)"

  echo "⏱ Runtime"
  echo "------------------------------------------------------------"
  printf "Uptime          : %s\n" "$uptime_pretty"
  printf "Kernel          : %s\n" "$kernel_ver"
  echo

  echo "🛡 Firewall"
  echo "------------------------------------------------------------"
  fw_mode="${FIREWALL_MODE_NAME:-tailscale-only}"
  [[ "$fw_mode" == "tailscale-only" ]] && fw_mode="🔒 tailscale-only" || fw_mode="🌐 public"
  printf "Mode            : %s\n" "$fw_mode"
  printf "UFW             : %s\n" "${ufw_state:-inactive}"
  printf "SSH Public      : ❌ closed by default\n"
  printf "SSH Tailscale   : ✅ allowed\n"
  printf "Public ports    : %s\n" "${EFFECTIVE_PUBLIC_PORTS:-80 443}"
  echo
  echo "⚙️ System tuning"
  echo "------------------------------------------------------------"
  printf "TCP CC          : %s\n" "$tcp_cc"
  printf "Qdisc           : %s\n" "$qdisc"
  printf "Forward         : %s\n" "$forward"
  printf "Conntrack       : %s\n" "$conntrack"
  printf "TW Buckets      : %s\n" "$tw_buckets"
  printf "Nofile          : %s\n" "$nofile"
  printf "Swap            : %s\n" "$swap"
  printf "Journald        : %s\n" "$journald"
  printf "Logrotate       : daily / rotate 14\n"
  echo
  echo "📂 Important paths"
  echo "------------------------------------------------------------"
  echo "Compose         : /opt/remnanode/docker-compose.yml"
  echo "Certificate     : $(readlink -f /opt/certbot/certs/live/remnanode/fullchain.pem 2>/dev/null || echo /opt/certbot/certs/live/remnanode/fullchain.pem)"
  echo "Geo files       : /opt/remnanode/roscomvpn-*.dat"
  echo "Logs            : /var/log/remnanode/"
  echo
  echo "🔄 Reboot"
  echo "------------------------------------------------------------"
  if [[ "${DEPLOY_RESULT:-success}" == "success" ]]; then
    printf "Scheduled       : %s\n" "$(date -d '+3 minutes' '+%F %T %Z' 2>/dev/null || echo 'in 3 minutes')"
    echo "Cancel command  : sudo shutdown -c"
  else
    echo "Scheduled       : no, install failed"
    echo "Cancel command  : n/a"
  fi
  echo

  echo "============================================================"
  if [[ "${DEPLOY_RESULT:-success}" == "success" ]]; then
    echo " ✅ INSTALLATION SUCCESSFUL"
  else
    echo " ❌ INSTALLATION FAILED: ${DEPLOY_RESULT}"
  fi
  echo "============================================================"
}

schedule_final_reboot() {
  shutdown -r +3 "Bootstrap completed. Reboot scheduled in 3 minutes." >/dev/null 2>&1 || true
}

on_exit() {
  local rc="$?"
  if [[ "$rc" == "0" ]]; then
    DEPLOY_RESULT="success"
    schedule_final_reboot
  else
    DEPLOY_RESULT="$rc"
  fi
  print_final_summary_tail
  exit "$rc"
}
trap on_exit EXIT









###############################################################################
# VPS bootstrap
# Order:
#   Step 0: summary / confirmation
#   Step 1: hostname
#   Step 2: tailscale install/status (optional, EARLY)
#   Step 3: remnanode secret/domain validation (optional)
#   Then everything else
#
# Notes:
# - Tailscale uses: tailscale up --ssh --advertise-exit-node
# - Firewall model: tailscale0 is fully open
# - External interface opens ONLY explicit ports, plus mandatory 80/443 when Remna/certbot is enabled
# - SSH port is fixed to 22; public SSH is NOT opened automatically
# - RemnaNode NODE_PORT is fixed to 2222
# - RemnaNode SECRET_KEY is required; it is written directly into docker-compose.yml (no .env)
# - Timezone is always set to Europe/Moscow
# - UFW is enabled automatically after rules are configured
# - Reboot is scheduled automatically 3 minutes after install
###############################################################################

###############################################################################
# ARG PARSING
###############################################################################
USER_NAME=""
NEW_HOST=""
TIMEZONE="Europe/Moscow"  # fixed: always applied
REBOOT_DELAY="0"   # deprecated, ignored
SSH_PORT="${SSH_PORT:-22}"
REMNANODE="0"
PORTS_MODE=""
OPEN_PORTS_RAW=""
TAILSCALE_ONLY="0"
ENABLE_UFW_NOW="0"
RUN_TUNING="1"  # always enabled
RUN_DNS_SWITCH="1"  # fixed: Cloudflare DNS, no prompt
ORIGINAL_ARGC="$#"


RUN_TAILSCALE="0"
DNS_PROFILE="3"  # fixed: Cloudflare
DNS_CUSTOM=""
DNS_FALLBACK=""

NODE_PORT="2222"
SECRET_KEY=""
REMNANODE_DOMAIN=""

DEFAULT_OPEN_PORTS=(80 443)

usage() {
  cat <<'EOF'
Usage: sudo bash initial.sh [options]

If started without options in a TTY, interactive mode asks what to install/configure.

Options:
  --user <name> | --user=<name> | user=<name>
  --secret-key <key> | --secret-key=<key> | secret_key=<key>  required for RemnaNode unless existing compose has SECRET_KEY
  --reboot <delay> | --reboot=<delay>                (deprecated, ignored)
  --remnanode 0|1 | --remnanode=0|1                  (default: 0; Remna NODE_PORT fixed to 2222)
  --ports ask|skip | --ports=ask|skip                (default: ask if TTY, else skip)
  --open-ports "<list>" | --open-ports="<list>"      external TCP+UDP ports only; SSH is opened only if listed
  --tailscale-only 0|1 | --tailscale-only=0|1        open no public ports except mandatory 80/443 when Remna/certbot is enabled; allow all via tailscale0
  --enable-ufw-now 0|1 | --enable-ufw-now=0|1        deprecated; UFW is enabled automatically at the end
  --dns-* options are ignored; DNS is fixed to Cloudflare
  --tailscale 0|1 | --tailscale=0|1                  (default: 0)
  --domain <fqdn> | --domain=<fqdn>                    remnanode TLS domain for certbot
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --user=*)         USER_NAME="${1#*=}"; shift ;;
    user=*)           USER_NAME="${1#*=}"; shift ;;
    --secret-key=*)   SECRET_KEY="${1#*=}"; shift ;;
    secret_key=*)     SECRET_KEY="${1#*=}"; shift ;;
    --timezone=*)     shift ;;  # ignored; fixed to Europe/Moscow
    --reboot=*)       REBOOT_DELAY="${1#*=}"; shift ;;
    --remnanode=*)    REMNANODE="${1#*=}"; shift ;;
    --ssh-port=*)     shift ;;  # ignored; fixed to 22
    --ports=*)        PORTS_MODE="${1#*=}"; shift ;;
    --open-ports=*)   OPEN_PORTS_RAW="${1#*=}"; shift ;;
    --tailscale-only=*) TAILSCALE_ONLY="${1#*=}"; shift ;;
    --enable-ufw-now=*) ENABLE_UFW_NOW="${1#*=}"; shift ;;
    --tuning=*)       shift ;;  # ignored; always enabled
    --dns-switch=*)   RUN_DNS_SWITCH="${1#*=}"; shift ;;
    --dns-profile=*)  DNS_PROFILE="${1#*=}"; shift ;;
    --dns-custom=*)   DNS_CUSTOM="${1#*=}"; shift ;;
    --dns-fallback=*) DNS_FALLBACK="${1#*=}"; shift ;;
    --tailscale=*)    RUN_TAILSCALE="${1#*=}"; shift ;;
    --hostname=*)     NEW_HOST="${1#*=}"; shift ;;
    hostname=*)       NEW_HOST="${1#*=}"; shift ;;
    --domain=*)       REMNANODE_DOMAIN="${1#*=}"; shift ;;

    --user)         USER_NAME="${2:-}"; shift 2 ;;
    --secret-key)   SECRET_KEY="${2:-}"; shift 2 ;;
    --timezone)     shift 2 ;;  # ignored; fixed to Europe/Moscow
    --reboot)       REBOOT_DELAY="${2:-0}"; shift 2 ;;
    --remnanode)    REMNANODE="${2:-0}"; shift 2 ;;
    --ssh-port)     shift 2 ;;  # ignored; fixed to 22
    --ports)        PORTS_MODE="${2:-}"; shift 2 ;;
    --open-ports)   OPEN_PORTS_RAW="${2:-}"; shift 2 ;;
    --tailscale-only) TAILSCALE_ONLY="${2:-1}"; shift 2 ;;
    --enable-ufw-now) ENABLE_UFW_NOW="${2:-1}"; shift 2 ;;
    --tuning)       shift 2 ;;  # ignored; always enabled
    --dns-switch)   RUN_DNS_SWITCH="${2:-1}"; shift 2 ;;
    --dns-profile)  DNS_PROFILE="${2:-}"; shift 2 ;;
    --dns-custom)   DNS_CUSTOM="${2:-}"; shift 2 ;;
    --dns-fallback) DNS_FALLBACK="${2:-}"; shift 2 ;;
    --tailscale)    RUN_TAILSCALE="${2:-0}"; shift 2 ;;
    --hostname)     NEW_HOST="${2:-}"; shift 2 ;;
    --domain)       REMNANODE_DOMAIN="${2:-}"; shift 2 ;;

    --tailscale-only) TAILSCALE_ONLY="1"; shift ;;
    --enable-ufw-now) ENABLE_UFW_NOW="1"; shift ;;
    -h|--help) usage; exit 0 ;;
    *) echo "Unknown arg: $1"; usage; exit 1 ;;
  esac
done

SSH_PORT="22"  # fixed: never changed interactively
RUN_TUNING="1" # fixed: always enabled
RUN_DNS_SWITCH="1"
DNS_PROFILE="3"
DNS_CUSTOM=""
DNS_FALLBACK=""


###############################################################################
# OUTPUT HELPERS
###############################################################################
_is_tty() { [[ -t 0 && -t 1 ]]; }
_has_tty() { [[ -r /dev/tty && -w /dev/tty ]]; }

c_reset=$'\033[0m'
c_bold=$'\033[1m'
c_red=$'\033[31m'
c_yel=$'\033[33m'
c_grn=$'\033[32m'
c_cyan=$'\033[36m'

color() {
  local code="$1"; shift || true
  if [[ -t 1 ]]; then
    printf "%s%s%s" "$code" "$*" "$c_reset"
  else
    printf "%s" "$*"
  fi
}

log()  { color "${c_bold}${c_cyan}" "==>"; echo " $*"; }
ok()   { color "${c_grn}" "OK "; echo " $*"; }
warn() { color "${c_yel}" "WARN"; echo " $*"; }
err()  { color "${c_red}" "ERR "; echo " $*"; }

section() {
  echo
  echo "============================================================"
  echo " $*"
  echo "============================================================"
}

runq() {
  local msg="$1"; shift
  printf "   %s ... " "$msg"
  if "$@" >/dev/null 2>&1; then
    echo "ok"
  else
    echo "fail"
    return 1
  fi
}

require_root() {
  [[ ${EUID:-$(id -u)} -eq 0 ]] || { err "Run as root (sudo required)"; exit 1; }
}

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


ask_yes_no() {
  local __var="$1" __prompt="$2" __default="${3:-y}" __ans=""
  local __hint="[y/N]"
  [[ "$__default" =~ ^[Yy1]$ ]] && __hint="[Y/n]"
  while true; do
    read_tty __ans "$__prompt $__hint: "
    __ans="${__ans:-$__default}"
    case "$__ans" in
      y|Y|yes|YES|Yes|1|true|TRUE) printf -v "$__var" '1'; return 0 ;;
      n|N|no|NO|No|0|false|FALSE) printf -v "$__var" '0'; return 0 ;;
      *) echo "Please answer y or n" >/dev/tty ;;
    esac
  done
}

ask_value_default() {
  local __var="$1" __prompt="$2" __default="${3:-}" __ans=""
  if [[ -n "$__default" ]]; then
    read_tty __ans "$__prompt [$__default]: "
    __ans="${__ans:-$__default}"
  else
    read_tty __ans "$__prompt: "
  fi
  printf -v "$__var" '%s' "$__ans"
}

###############################################################################
# HELPERS
###############################################################################
_ports_sanitize_to_array() {
  local raw="${1:-}"
  raw="${raw//,/ }"
  raw="$(echo "$raw" | tr -s '[:space:]' ' ' | sed 's/^ *//; s/ *$//')"

  local out=() p
  for p in $raw; do
    [[ "$p" =~ ^[0-9]{1,5}$ ]] || continue
    (( p >= 1 && p <= 65535 )) || continue
    out+=("$p")
  done

  local dedup=() seen=" "
  for p in "${out[@]}"; do
    if [[ "$seen" != *" $p "* ]]; then
      dedup+=("$p"); seen+=" $p "
    fi
  done
  OPEN_PORTS=("${dedup[@]}")
}

ensure_cert_public_ports() {
  # RemnaNode certbot standalone needs public 80/tcp for HTTP-01.
  # 443 is also kept public for TLS/XHTTP service readiness, even in tailscale-only mode.
  [[ "${REMNANODE:-0}" == "1" ]] || return 0

  local p seen=" " out=()
  for p in "${OPEN_PORTS[@]:-}" 80 443; do
    [[ -n "${p:-}" ]] || continue
    if [[ "$seen" != *" $p "* ]]; then
      out+=("$p")
      seen+=" $p "
    fi
  done
  OPEN_PORTS=("${out[@]}")
  ok "Cert/Remna public ports are mandatory: 80 443; effective external ports: ${OPEN_PORTS[*]}"
}

pick_open_ports() {
  OPEN_PORTS=("${DEFAULT_OPEN_PORTS[@]}")

  if [[ "${TAILSCALE_ONLY:-0}" == "1" ]]; then
    OPEN_PORTS=()
    ok "Tailscale-only mode: no external ports will be opened"
    return 0
  fi

  if [[ -n "${OPEN_PORTS_RAW:-}" ]]; then
    _ports_sanitize_to_array "$OPEN_PORTS_RAW"
    if [[ "${#OPEN_PORTS[@]}" -eq 0 ]]; then
      warn "open-ports provided, but nothing valid parsed -> defaults: ${DEFAULT_OPEN_PORTS[*]}"
      OPEN_PORTS=("${DEFAULT_OPEN_PORTS[@]}")
    else
      ok "Open ports set from --open-ports: ${OPEN_PORTS[*]}"
    fi
    return 0
  fi

  local mode="${PORTS_MODE:-}"
  [[ -n "$mode" ]] || mode="$(_is_tty && echo ask || echo skip)"

  if [[ "$mode" == "skip" ]]; then
    ok "Ports dialog skipped. Using defaults: ${OPEN_PORTS[*]}"
    return 0
  fi

  if ! _is_tty; then
    ok "No TTY available. Using defaults: ${OPEN_PORTS[*]}"
    return 0
  fi

  local def="${DEFAULT_OPEN_PORTS[*]}"
  echo "Open ports on external interface (TCP+UDP)."
  echo "Default: ${def}"
  local ans=""
  read_tty ans "Ports to open: "
  if [[ -z "${ans}" ]]; then
    OPEN_PORTS=("${DEFAULT_OPEN_PORTS[@]}")
    ok "Using default open ports: ${OPEN_PORTS[*]}"
  else
    _ports_sanitize_to_array "$ans"
    if [[ "${#OPEN_PORTS[@]}" -eq 0 ]]; then
      warn "No valid ports entered -> defaults: ${DEFAULT_OPEN_PORTS[*]}"
      OPEN_PORTS=("${DEFAULT_OPEN_PORTS[@]}")
    else
      ok "Open ports selected: ${OPEN_PORTS[*]}"
    fi
  fi
}

APT_LOG="/var/log/initial-apt.log"; :> "$APT_LOG"
aptq() {
  local what="$1"; shift
  log "$what"
  if apt-get -y -qq -o Dpkg::Use-Pty=0 \
       -o Dpkg::Options::='--force-confdef' \
       -o Dpkg::Options::='--force-confold' \
       "$@" >>"$APT_LOG" 2>&1; then
    ok "$what — ok"
  else
    err "$what — failed. Tail of log:"
    tail -n 60 "$APT_LOG" || true
    echo "Full log: $APT_LOG"
    exit 1
  fi
}

apply_fd_limits() {
  log "FD limits (kernel + systemd defaults)"

  cat > /etc/sysctl.d/99-fd.conf <<'EOF'
fs.file-max = 2097152
fs.nr_open = 2097152
EOF
  chmod 0644 /etc/sysctl.d/99-fd.conf

  mkdir -p /etc/systemd/system.conf.d
  cat > /etc/systemd/system.conf.d/99-limits.conf <<'EOF'
[Manager]
DefaultLimitNOFILE=1048576
DefaultTasksMax=infinity
EOF
  chmod 0644 /etc/systemd/system.conf.d/99-limits.conf

  runq "sysctl --system" sysctl --system || true
  runq "systemd daemon-reexec" systemctl daemon-reexec || true
  ok "FD limits applied"
}

###############################################################################
# TAILSCALE HELPERS
###############################################################################
TAILSCALE_LOG="/var/log/install-tailscale.log"; :> "$TAILSCALE_LOG"
TS_IP_EARLY=""
TS_DNS_EARLY=""

tailscale_magicdns_full() {
  if command -v tailscale >/dev/null 2>&1 && command -v jq >/dev/null 2>&1; then
    tailscale status --json 2>/dev/null | jq -r '.Self.DNSName // empty' | head -n1
  else
    echo ""
  fi
}

tailscale_ipv4() {
  if command -v tailscale >/dev/null 2>&1; then
    tailscale ip -4 2>/dev/null | head -n1 || true
  else
    echo ""
  fi
}

print_tailscale_summary() {
  local ip4 dns service state
  ip4="$(tailscale_ipv4 || true)"
  dns="$(tailscale_magicdns_full || true)"
  if systemctl is-active --quiet tailscaled 2>/dev/null; then service="active"; else service="inactive"; fi
  state="not-authorized"
  if [[ -n "$ip4" ]]; then state="authorized"; fi

  echo "  tailscaled:     $service"
  echo "  Tailscale state:$state"
  echo "  Tailscale IPv4: ${ip4:-not assigned}"
  echo "  Tailscale DNS:  ${dns:-not assigned}"
}

ensure_tailscale_up() {
  if ! command -v tailscale >/dev/null 2>&1; then
    warn "tailscale binary not found after install attempt"
    return 1
  fi

  if systemctl list-unit-files tailscaled.service >/dev/null 2>&1; then
    systemctl enable --now tailscaled >/dev/null 2>&1 || true
  fi

  local ip4=""
  ip4="$(tailscale_ipv4 || true)"
  if [[ -n "$ip4" ]]; then
    ok "Tailscale already installed, authorized and running"
    print_tailscale_summary
    return 0
  fi

  ok "Tailscale installed, but this node is not authorized yet"
  log "Running tailscale up --ssh --advertise-exit-node"

  set +e
  tailscale up --ssh --advertise-exit-node 2>&1 | tee /tmp/tailscale-up.log
  local rc=${PIPESTATUS[0]}
  set -e

  local url=""
  url="$(grep -Eo 'https://login\.tailscale\.com/[a-zA-Z0-9/_-]+' /tmp/tailscale-up.log | head -n1 || true)"
  if [[ -n "$url" ]]; then
    echo "Open to authorize: $url"
  fi

  if [[ $rc -ne 0 ]]; then
    warn "tailscale up returned rc=$rc. If authorization URL was shown, authorize and continue."
  fi

  if _has_tty; then
    local _=""
    read_tty _ "Press Enter after authorizing this device in Tailscale..."
  fi

  ip4="$(tailscale_ipv4 || true)"
  if [[ -n "$ip4" ]]; then
    ok "Tailscale authorized"
  else
    warn "Tailscale still has no IPv4 assigned"
  fi
  print_tailscale_summary
}

###############################################################################
# SSH HELPERS
###############################################################################
get_sshd_effective() {
  local key="$1"
  if command -v sshd >/dev/null 2>&1; then
    sshd -T 2>/dev/null | awk -v k="$key" '$1==k {print $2; exit}'
  else
    echo "(no_sshd)"
  fi
}

restart_ssh_service() {
  if systemctl list-unit-files 2>/dev/null | awk '{print $1}' | grep -qx 'ssh.service'; then
    systemctl restart ssh >/dev/null 2>&1 || true
  elif systemctl list-unit-files 2>/dev/null | awk '{print $1}' | grep -qx 'sshd.service'; then
    systemctl restart sshd >/dev/null 2>&1 || true
  else
    systemctl restart ssh >/dev/null 2>&1 || true
    systemctl restart sshd >/dev/null 2>&1 || true
  fi
}

harden_sshd() {
  log "SSHD hardening (Port=${SSH_PORT}, PermitRootLogin=no, PasswordAuthentication=no)"
  local drop_dir="/etc/ssh/sshd_config.d"
  mkdir -p "$drop_dir"

  cat > "${drop_dir}/99-initial-hardening.conf" <<EOF
# Managed by initial.sh
Port ${SSH_PORT}
PermitRootLogin no
PasswordAuthentication no
KbdInteractiveAuthentication no
ChallengeResponseAuthentication no
PubkeyAuthentication yes
EOF
  chmod 0644 "${drop_dir}/99-initial-hardening.conf"

  if command -v sshd >/dev/null 2>&1; then
    if sshd -t >/dev/null 2>&1; then
      restart_ssh_service
      ok "SSHD config applied and service restarted"
    else
      warn "sshd -t failed; not restarting SSH"
    fi
  else
    warn "sshd binary not found; skipping SSH restart"
  fi
}

###############################################################################
# ZSH STACK
###############################################################################
zsh_stack_for_user() {
  local user="$1"
  local home_dir="$2"

  log "Zsh stack for ${user}: oh-my-zsh + p10k + fzf + plugins"

  grep -q '^/usr/bin/zsh$' /etc/shells || echo '/usr/bin/zsh' >> /etc/shells

  if [[ ! -d "${home_dir}/.oh-my-zsh" ]]; then
    runq "oh-my-zsh install (${user})" su - "${user}" -c \
      'RUNZSH=no KEEP_ZSHRC=yes CHSH=no sh -c "$(curl -fsSL https://raw.githubusercontent.com/ohmyzsh/ohmyzsh/master/tools/install.sh)"'
  else
    ok "oh-my-zsh already exists for ${user}"
  fi

  local zsh_path="${home_dir}/.oh-my-zsh"
  local zsh_custom="${zsh_path}/custom"

  runq "mkdir OMZ custom dirs (${user})" su - "${user}" -c "mkdir -p ${zsh_custom}/plugins ${zsh_custom}/themes"

  if [[ ! -d "${zsh_custom}/plugins/zsh-autosuggestions" ]]; then
    runq "plugin zsh-autosuggestions (${user})" su - "${user}" -c \
      "git clone --depth=1 https://github.com/zsh-users/zsh-autosuggestions ${zsh_custom}/plugins/zsh-autosuggestions"
  fi
  if [[ ! -d "${zsh_custom}/plugins/zsh-completions" ]]; then
    runq "plugin zsh-completions (${user})" su - "${user}" -c \
      "git clone --depth=1 https://github.com/zsh-users/zsh-completions ${zsh_custom}/plugins/zsh-completions"
  fi
  if [[ ! -d "${zsh_custom}/plugins/zsh-syntax-highlighting" ]]; then
    runq "plugin zsh-syntax-highlighting (${user})" su - "${user}" -c \
      "git clone --depth=1 https://github.com/zsh-users/zsh-syntax-highlighting ${zsh_custom}/plugins/zsh-syntax-highlighting"
  fi
  if [[ ! -d "${zsh_custom}/themes/powerlevel10k" ]]; then
    runq "theme powerlevel10k (${user})" su - "${user}" -c \
      "git clone --depth=1 https://github.com/romkatv/powerlevel10k.git ${zsh_custom}/themes/powerlevel10k"
  fi

  if [[ ! -d "${home_dir}/.fzf" ]]; then
    runq "fzf clone (${user})" su - "${user}" -c 'git clone --depth 1 https://github.com/junegunn/fzf.git ~/.fzf'
    runq "fzf install (${user})" su - "${user}" -c 'yes | ~/.fzf/install --key-bindings --completion --no-bash --no-fish --no-update-rc'
  else
    ok "fzf already exists for ${user}"
  fi

  runq "download .zshrc (${user})"   curl -fsSL "https://kadorkin.io/zshrc" -o "${home_dir}/.zshrc"
  runq "download .p10k (${user})"    curl -fsSL "https://kadorkin.io/p10k"  -o "${home_dir}/.p10k.zsh"
  runq "chown zsh dotfiles (${user})" chown "${user}:${user}" "${home_dir}/.zshrc" "${home_dir}/.p10k.zsh"

  if [[ -f "${home_dir}/.zshrc" ]] && ! grep -q 'FZF_BASE=' "${home_dir}/.zshrc"; then
    cat >> "${home_dir}/.zshrc" <<'EOF'
# Linux fallback for oh-my-zsh fzf plugin
if command -v fzf >/dev/null 2>&1; then
  export FZF_BASE="${FZF_BASE:-$HOME/.fzf}"
fi
EOF
    chown "${user}:${user}" "${home_dir}/.zshrc" || true
  fi

  for zrc in "${home_dir}/.zshrc"; do
    [[ -f "$zrc" ]] || continue
    if ! grep -q 'DISABLE_AUTO_UPDATE' "$zrc" 2>/dev/null; then
      echo 'DISABLE_AUTO_UPDATE="true"' >> "$zrc"
    fi
    if ! grep -q 'DISABLE_UPDATE_PROMPT' "$zrc" 2>/dev/null; then
      echo 'DISABLE_UPDATE_PROMPT=true' >> "$zrc"
    fi
    if ! grep -q ":omz:update" "$zrc" 2>/dev/null; then
      echo "zstyle ':omz:update' mode disabled" >> "$zrc"
    fi
    chown "${user}:${user}" "$zrc" || true
  done

  ok "Zsh stack ready for ${user}"
}

zsh_stack_for_root() {
  local user_home="$1"
  local root_home="/root"

  log "Zsh stack for root"

  if [[ -d "${user_home}/.oh-my-zsh" && ! -d "${root_home}/.oh-my-zsh" ]]; then
    cp -a "${user_home}/.oh-my-zsh" "${root_home}/.oh-my-zsh"
    chown -R root:root "${root_home}/.oh-my-zsh" || true
  fi

  if [[ ! -d "${root_home}/.oh-my-zsh" ]]; then
    RUNZSH=no KEEP_ZSHRC=yes CHSH=no \
      sh -c "$(curl -fsSL https://raw.githubusercontent.com/ohmyzsh/ohmyzsh/master/tools/install.sh)" || true
  fi

  if [[ ! -d "${root_home}/.fzf" ]]; then
    git clone --depth 1 https://github.com/junegunn/fzf.git "${root_home}/.fzf" >/dev/null 2>&1 || true
    bash -lc 'yes | ~/.fzf/install --key-bindings --completion --no-bash --no-fish --no-update-rc' >/dev/null 2>&1 || true
  fi

  if [[ -f "${user_home}/.zshrc" && "$(readlink -f "${user_home}/.zshrc")" != "$(readlink -f "${root_home}/.zshrc" 2>/dev/null || true)" ]]; then
    cp "${user_home}/.zshrc" "${root_home}/.zshrc" || true
  fi
  if [[ -f "${user_home}/.p10k.zsh" && "$(readlink -f "${user_home}/.p10k.zsh")" != "$(readlink -f "${root_home}/.p10k.zsh" 2>/dev/null || true)" ]]; then
    cp "${user_home}/.p10k.zsh" "${root_home}/.p10k.zsh" || true
  fi
  chown root:root "${root_home}/.zshrc" "${root_home}/.p10k.zsh" 2>/dev/null || true

  for zrc in "${root_home}/.zshrc"; do
    [[ -f "$zrc" ]] || continue
    if ! grep -q 'DISABLE_AUTO_UPDATE' "$zrc" 2>/dev/null; then
      echo 'DISABLE_AUTO_UPDATE="true"' >> "$zrc"
    fi
    if ! grep -q 'DISABLE_UPDATE_PROMPT' "$zrc" 2>/dev/null; then
      echo 'DISABLE_UPDATE_PROMPT=true' >> "$zrc"
    fi
    if ! grep -q ":omz:update" "$zrc" 2>/dev/null; then
      echo "zstyle ':omz:update' mode disabled" >> "$zrc"
    fi
    chown root:root "$zrc" || true
  done

  chsh -s /usr/bin/zsh root >/dev/null 2>&1 || true
  ok "Root zsh stack ready"
}

###############################################################################
# INTERACTIVE DEFAULTS
###############################################################################
interactive_defaults() {
  [[ "${ORIGINAL_ARGC:-0}" == "0" ]] || return 0
  _has_tty || return 0

  section "Interactive setup"
  echo "No arguments were provided. First I will collect all input values, then run the setup."

  local current_host=""
  current_host="$(hostname 2>/dev/null || true)"
  read_tty NEW_HOST "Hostname [keep ${current_host}]: "

  if [[ -z "${USER_NAME:-}" ]]; then
    read_tty USER_NAME "User to create (empty = skip user creation, or pass user=<name>): "
  fi

  ask_yes_no RUN_TAILSCALE "Install/configure Tailscale" "y"
  ask_yes_no REMNANODE "Install/configure RemnaNode stack" "y"

  if [[ "${REMNANODE}" == "1" ]]; then
    while [[ -z "${REMNANODE_DOMAIN:-}" ]]; do
      read_tty REMNANODE_DOMAIN "Domain for TLS certificate: "
      [[ -n "${REMNANODE_DOMAIN:-}" ]] || echo "Domain cannot be empty." >/dev/tty || true
    done

    # SECRET_KEY is mandatory. On reruns we can reuse existing one, but ask explicitly.
    if [[ -z "${SECRET_KEY:-}" && -f /opt/remnanode/docker-compose.yml ]]; then
      existing_secret="$(grep -E '^\s*-\s*SECRET_KEY=' /opt/remnanode/docker-compose.yml 2>/dev/null | head -n1 | sed -E 's/^\s*-\s*SECRET_KEY=//' || true)"
      if [[ -n "${existing_secret:-}" ]]; then
        echo "Existing RemnaNode SECRET_KEY found in docker-compose.yml." >/dev/tty || true
        ask_yes_no __use_existing_secret "Use existing SECRET_KEY" "y"
        if [[ "${__use_existing_secret}" == "1" ]]; then
          SECRET_KEY="${existing_secret}"
          ok "Existing remnanode SECRET_KEY preserved from docker-compose.yml"
        fi
      fi
    fi

    while [[ -z "${SECRET_KEY:-}" ]]; do
      read_tty_silent SECRET_KEY "Paste RemnaNode SECRET_KEY (required, input hidden): "
      echo "" >/dev/tty || true
      [[ -n "${SECRET_KEY:-}" ]] || echo "SECRET_KEY cannot be empty." >/dev/tty || true
    done
  fi

  echo ""
  echo "Firewall mode:"
  echo "  1) tailscale-only: no public ports except mandatory 80/443 for Remna/certbot; allow everything via tailscale0"
  echo "  2) selected public ports + allow everything via tailscale0"
  local fw_mode=""
  read_tty fw_mode "Choose 1/2 [1]: "
  fw_mode="${fw_mode:-1}"
  case "$fw_mode" in
    1)
      TAILSCALE_ONLY="1"
      OPEN_PORTS_RAW=""
      PORTS_MODE="skip"
      ;;
    2)
      TAILSCALE_ONLY="0"
      ask_value_default OPEN_PORTS_RAW "Public external ports to open, space/comma separated. Do NOT include SSH unless public SSH is needed" "80 443 9443"
      PORTS_MODE="ask"
      ;;
    *)
      TAILSCALE_ONLY="1"
      PORTS_MODE="skip"
      ;;
  esac


  echo ""
  section "Configuration summary"
  echo "  Hostname:      ${NEW_HOST:-<keep current>}"
  echo "  User:          ${USER_NAME:-<skip>}"
  echo "  Tailscale:     ${RUN_TAILSCALE}"
  echo "  RemnaNode:     ${REMNANODE}"
  echo "  Remna port:    2222"
  echo "  Domain:        ${REMNANODE_DOMAIN:-<none>}"
  echo "  SECRET_KEY:    $([[ -n "${SECRET_KEY:-}" ]] && echo configured || echo not-configured)"
  echo "  Timezone:      Europe/Moscow"
  echo "  DNS profile:   Cloudflare"
  echo "  Firewall:      $([[ "${TAILSCALE_ONLY}" == "1" ]] && echo tailscale-only || echo selected-public-ports)"
  echo "  Open ports:    ${OPEN_PORTS_RAW:-<none>}"

  ask_yes_no __confirm "Continue" "y"
  [[ "$__confirm" == "1" ]] || { echo "Aborted"; exit 1; }
}

###############################################################################
# START
###############################################################################
require_root
interactive_defaults

export DEBIAN_FRONTEND=noninteractive
export NEEDRESTART_MODE=a

###############################################################################
# Fixed timezone
###############################################################################
log "Timezone: Europe/Moscow"
runq "set timezone Europe/Moscow" timedatectl set-timezone Europe/Moscow || warn "Failed to set timezone — continuing"

log "Parameters: user='${USER_NAME:-<skip>}' remnanode='${REMNANODE}' remna_port='2222' ssh_port='22' timezone='Europe/Moscow' tuning='always' dns-switch='1' dns-profile='Cloudflare' tailscale='${RUN_TAILSCALE}'"

if [[ -n "${USER_NAME:-}" ]]; then
  ok "User: $USER_NAME"
  HOME_DIR="/home/${USER_NAME}"
else
  warn "User creation skipped"
  HOME_DIR=""
fi

###############################################################################
# Step 1: hostname
###############################################################################
log "Step 1: hostname"
CURRENT_HOST="$(hostname 2>/dev/null || true)"
if [[ -n "${NEW_HOST:-}" ]]; then
  runq "hostnamectl set-hostname" hostnamectl set-hostname "${NEW_HOST}" || true
  ok "Hostname set to: ${NEW_HOST}"
else
  ok "Hostname unchanged: ${CURRENT_HOST}"
fi

###############################################################################
# Step 2: tailscale install/status
###############################################################################
if [[ "${RUN_TAILSCALE}" == "1" ]]; then
  log "Step 2: tailscale install/status"

  aptq "APT update" update
  aptq "Install base packages for tailscale step" install curl jq ca-certificates iproute2 ethtool

  INTERNET_IFACE="$(ip route show default 2>/dev/null | awk '/default/ {print $5; exit}' || true)"

  if ! command -v tailscale >/dev/null 2>&1; then
    runq "install tailscale" bash -lc 'curl -fsSL https://tailscale.com/install.sh | sh >>/var/log/install-tailscale.log 2>&1'
  else
    ok "Tailscale already installed — skipping install"
  fi

  cat > /etc/sysctl.d/99-tailscale-forwarding.conf <<'EOF'
net.ipv4.ip_forward=1
net.ipv6.conf.all.forwarding=1
net.ipv4.conf.all.rp_filter=0
net.ipv4.conf.default.rp_filter=0
EOF
  chmod 0644 /etc/sysctl.d/99-tailscale-forwarding.conf
  runq "sysctl --system" sysctl --system || true

  if [[ -n "${INTERNET_IFACE:-}" ]]; then
    runq "ethtool gro on" ethtool -K "${INTERNET_IFACE}" gro on || true
    runq "ethtool rx-udp-gro-fwd on" ethtool -K "${INTERNET_IFACE}" rx-udp-gro-forwarding on || true
  fi

  ensure_tailscale_up

  TS_IP_EARLY="$(tailscale ip -4 2>/dev/null || true)"
  TS_DNS_EARLY="$(tailscale_magicdns_full || true)"

  section "Tailscale status"
  echo "  Tailscale IPv4: ${TS_IP_EARLY:-not assigned}"
  echo "  Tailscale DNS:  ${TS_DNS_EARLY:-not assigned}"
else
  warn "Step 2: tailscale skipped (--tailscale=${RUN_TAILSCALE})"
fi



###############################################################################
# REMNANODE EXTRAS: domain, DNS, certbot, geo updater, compose volumes
###############################################################################
valid_fqdn() {
  local d="${1:-}"
  [[ "$d" =~ ^[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?(\.[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?)+$ ]]
}

public_ipv4() {
  curl -4 -fsS --max-time 6 https://api.ipify.org 2>/dev/null \
    || curl -4 -fsS --max-time 6 https://ifconfig.me 2>/dev/null \
    || curl -4 -fsS --max-time 6 https://icanhazip.com 2>/dev/null \
    || true
}

resolve_a_records() {
  local domain="$1"
  dig +short A "$domain" 2>/dev/null | grep -E '^[0-9]+(\.[0-9]+){3}$' || true
}

prompt_remnanode_domain() {
  [[ "${REMNANODE}" == "1" ]] || return 0

  if [[ -z "${REMNANODE_DOMAIN:-}" && _has_tty ]]; then
    read_tty REMNANODE_DOMAIN "Enter remnanode TLS domain for certbot (e.g. s1.proj432.co): "
  fi

  if [[ -z "${REMNANODE_DOMAIN:-}" ]]; then
    err "Domain is empty — provide --domain or run interactively"
    REMNANODE="0"
    return 0
  fi

  if ! valid_fqdn "${REMNANODE_DOMAIN}"; then
    err "Invalid domain: ${REMNANODE_DOMAIN}"
    REMNANODE="0"
    return 0
  fi

  ok "Remnanode domain: ${REMNANODE_DOMAIN}"
}

wait_for_domain_dns() {
  [[ "${REMNANODE}" == "1" ]] || return 0
  [[ -n "${REMNANODE_DOMAIN:-}" ]] || return 0

  local expected_ip=""
  expected_ip="$(public_ipv4)"
  if [[ -z "$expected_ip" ]]; then
    err "Could not detect public IPv4; cannot verify DNS for ${REMNANODE_DOMAIN}"
    exit 1
  fi

  local timeout_sec=300
  local interval_sec=5
  local elapsed=0

  log "Waiting for DNS A record: ${REMNANODE_DOMAIN} -> ${expected_ip}"
  log "Timeout: ${timeout_sec}s, interval: ${interval_sec}s"

  while (( elapsed <= timeout_sec )); do
    local records=""
    records="$(resolve_a_records "${REMNANODE_DOMAIN}" || true)"

    local one_line="${records//$'\n'/ }"
    [[ -n "$one_line" ]] || one_line="EMPTY"
    echo "[${elapsed}/${timeout_sec}s] DNS A: ${one_line}"

    if grep -qxF "$expected_ip" <<< "$records"; then
      ok "DNS is ready: ${REMNANODE_DOMAIN} -> ${expected_ip}"
      return 0
    fi

    sleep "$interval_sec"
    elapsed=$((elapsed + interval_sec))
  done


  err "DNS for ${REMNANODE_DOMAIN} still does not point to ${expected_ip} after ${timeout_sec}s"
  exit 1
}

install_roscomvpn_geo_updater() {
  log "Installing roscomvpn geo updater + 4h systemd timer"

  cat > /usr/local/sbin/update-roscomvpn-geo.sh <<'GEO_SCRIPT'
#!/usr/bin/env bash
set -euo pipefail

DIR="/opt/remnanode"
GEOIP_URL="https://cdn.jsdelivr.net/gh/hydraponique/roscomvpn-geoip@202604220533/release/geoip.dat"
GEOSITE_URL="https://cdn.jsdelivr.net/gh/hydraponique/roscomvpn-geosite@202604152235/release/geosite.dat"

mkdir -p "$DIR"
cd "$DIR"

curl -fL --retry 3 --connect-timeout 10 -o roscomvpn-geoip.dat.tmp "$GEOIP_URL"
curl -fL --retry 3 --connect-timeout 10 -o roscomvpn-geosite.dat.tmp "$GEOSITE_URL"

test -s roscomvpn-geoip.dat.tmp
test -s roscomvpn-geosite.dat.tmp

mv -f roscomvpn-geoip.dat.tmp roscomvpn-geoip.dat
mv -f roscomvpn-geosite.dat.tmp roscomvpn-geosite.dat
GEO_SCRIPT
  chmod 0755 /usr/local/sbin/update-roscomvpn-geo.sh

  cat > /etc/systemd/system/update-roscomvpn-geo.service <<'GEO_SERVICE'
[Unit]
Description=Update roscomvpn geoip/geosite data
Wants=network-online.target
After=network-online.target

[Service]
Type=oneshot
ExecStart=/usr/local/sbin/update-roscomvpn-geo.sh
GEO_SERVICE
  chmod 0644 /etc/systemd/system/update-roscomvpn-geo.service

  cat > /etc/systemd/system/update-roscomvpn-geo.timer <<'GEO_TIMER'
[Unit]
Description=Run roscomvpn geo updater every 4 hours

[Timer]
OnBootSec=5min
OnUnitActiveSec=4h
AccuracySec=5min
Persistent=true
Unit=update-roscomvpn-geo.service

[Install]
WantedBy=timers.target
GEO_TIMER
  chmod 0644 /etc/systemd/system/update-roscomvpn-geo.timer

  systemctl daemon-reload
  systemctl enable --now update-roscomvpn-geo.timer >/dev/null 2>&1 || true
  systemctl start update-roscomvpn-geo.service || warn "roscomvpn geo initial update failed — continuing"
  ok "roscomvpn geo updater installed"
}

normalize_remnanode_compose_volumes() {
  local compose="/opt/remnanode/docker-compose.yml"
  [[ -f "$compose" ]] || return 0

  log "Normalizing remnanode compose volumes"
  cp "$compose" "${compose}.bak.$(date +%F-%H%M%S)" || true

  python3 - "$compose" <<'COMPOSE_PY'
from pathlib import Path
import re
import sys

path = Path(sys.argv[1])
s = path.read_text()
required = [
    "      - './roscomvpn-geosite.dat:/usr/local/share/xray/roscomvpn-geosite.dat:ro'",
    "      - './roscomvpn-geoip.dat:/usr/local/share/xray/roscomvpn-geoip.dat:ro'",
    "      - '/opt/certbot/certs:/etc/letsencrypt:ro'",
    "      - '/var/log/remnanode:/var/log/remnanode'",
]
new_block = "    volumes:\n" + "\n".join(required) + "\n"

m = re.search(r'(?ms)^    volumes:\n(?:^      - .+\n)*', s)
if m:
    s = s[:m.start()] + new_block + s[m.end():]
else:
    marker = re.search(r'(?m)^    environment:\n(?:^      - .+\n)+', s)
    if marker:
        s = s[:marker.end()] + new_block + s[marker.end():]
    else:
        s = s.rstrip() + "\n" + new_block

path.write_text(s)
COMPOSE_PY

  docker compose -f "$compose" config >/dev/null
  ok "Compose volumes normalized"
}


normalize_remnanode_compose_environment() {
  local compose="/opt/remnanode/docker-compose.yml"
  [[ "${REMNANODE}" == "1" ]] || return 0
  [[ -f "$compose" ]] || return 0
  [[ -n "${SECRET_KEY:-}" ]] || { err "SECRET_KEY is empty — cannot normalize remnanode compose environment"; exit 1; }

  log "Normalizing remnanode compose environment"
  cp "$compose" "${compose}.compose-env.bak.$(date +%F-%H%M%S)" || true

  SECRET_KEY_ENV="${SECRET_KEY}" NODE_PORT_ENV="${NODE_PORT}" python3 - "$compose" <<'COMPOSE_ENV_PY'
from pathlib import Path
import os
import re
import sys

path = Path(sys.argv[1])
s = path.read_text()
secret = os.environ["SECRET_KEY_ENV"]
node_port = os.environ.get("NODE_PORT_ENV", "2222")
new_block = f"    environment:\n      - NODE_PORT={node_port}\n      - SECRET_KEY={secret}\n"

m = re.search(r'(?ms)^    environment:\n(?:^      - .+\n)*', s)
if m:
    s = s[:m.start()] + new_block + s[m.end():]
else:
    marker = re.search(r'(?m)^    volumes:\n', s)
    if marker:
        s = s[:marker.start()] + new_block + s[marker.start():]
    else:
        s = s.rstrip() + "\n" + new_block

path.write_text(s)
COMPOSE_ENV_PY

  docker compose -f "$compose" config >/dev/null
  ok "Compose environment normalized: NODE_PORT=${NODE_PORT}, SECRET_KEY=<configured>"
}

issue_remnanode_certificate() {
  [[ "${REMNANODE}" == "1" ]] || return 0
  [[ -n "${REMNANODE_DOMAIN:-}" ]] || return 0

  log "Issuing/renewing Docker certbot certificate for ${REMNANODE_DOMAIN}"

  mkdir -p /opt/certbot
  cd /opt/certbot

  cat > docker-compose.yml <<'CERTBOT_COMPOSE'
services:
  certbot:
    container_name: certbot
    image: certbot/certbot
    network_mode: host
    volumes:
      - ./certs:/etc/letsencrypt
      - ./var-lib-letsencrypt:/var/lib/letsencrypt
CERTBOT_COMPOSE

  # Always allow public cert/service ports. HTTP-01 needs 80/tcp; 443 is kept open for TLS/XHTTP.
  iptables -C INPUT -p tcp --dport 80 -j ACCEPT 2>/dev/null || iptables -I INPUT -p tcp --dport 80 -j ACCEPT || true
  iptables -C INPUT -p tcp --dport 443 -j ACCEPT 2>/dev/null || iptables -I INPUT -p tcp --dport 443 -j ACCEPT || true
  iptables -C INPUT -p udp --dport 443 -j ACCEPT 2>/dev/null || iptables -I INPUT -p udp --dport 443 -j ACCEPT || true
  ip6tables -C INPUT -p tcp --dport 80 -j ACCEPT 2>/dev/null || ip6tables -I INPUT -p tcp --dport 80 -j ACCEPT || true
  ip6tables -C INPUT -p tcp --dport 443 -j ACCEPT 2>/dev/null || ip6tables -I INPUT -p tcp --dport 443 -j ACCEPT || true
  ip6tables -C INPUT -p udp --dport 443 -j ACCEPT 2>/dev/null || ip6tables -I INPUT -p udp --dport 443 -j ACCEPT || true

  docker run --rm \
    -v /opt/certbot/certs:/etc/letsencrypt \
    -v /opt/certbot/var-lib-letsencrypt:/var/lib/letsencrypt \
    --network host \
    certbot/certbot certonly --standalone \
    --non-interactive --agree-tos \
    --email admin@proj432.co \
    --cert-name remnanode \
    -d "${REMNANODE_DOMAIN}"

  ls -l /opt/certbot/certs/live/remnanode/ || true

  (
    crontab -l 2>/dev/null | grep -v '/opt/certbot && docker compose run --rm certbot renew' || true
    echo '0 0 28 * * cd /opt/certbot && docker compose run --rm certbot renew >/dev/null 2>&1'
  ) | crontab -

  ok "Certificate ready: /opt/certbot/certs/live/remnanode/fullchain.pem"
}

###############################################################################
# Step 3: remnanode parameters
###############################################################################
if [[ "${REMNANODE}" == "1" ]]; then
  log "Step 3: remnanode parameters"

  # SECRET_KEY is mandatory. On reruns we can reuse existing one, but ask explicitly when TTY is available.
  if [[ -z "${SECRET_KEY:-}" && -f /opt/remnanode/docker-compose.yml ]]; then
    existing_secret="$(grep -E '^\s*-\s*SECRET_KEY=' /opt/remnanode/docker-compose.yml 2>/dev/null | head -n1 | sed -E 's/^\s*-\s*SECRET_KEY=//' || true)"
    if [[ -n "${existing_secret:-}" ]]; then
      if _has_tty; then
        echo "Existing RemnaNode SECRET_KEY found in docker-compose.yml." >/dev/tty || true
        ask_yes_no __use_existing_secret_runtime "Use existing SECRET_KEY" "y"
        if [[ "${__use_existing_secret_runtime}" == "1" ]]; then
          SECRET_KEY="${existing_secret}"
          ok "Existing remnanode SECRET_KEY preserved from docker-compose.yml"
        fi
      else
        SECRET_KEY="${existing_secret}"
        ok "Existing remnanode SECRET_KEY preserved from docker-compose.yml"
      fi
    fi
  fi

  while [[ -z "${SECRET_KEY:-}" ]]; do
    if _has_tty; then
      read_tty_silent SECRET_KEY "Paste RemnaNode SECRET_KEY (required, input hidden): "
      echo "" >/dev/tty || true
    else
      err "SECRET_KEY is required for RemnaNode. Pass --secret-key '<key>' or secret_key='<key>'."
      exit 1
    fi

    if [[ -z "${SECRET_KEY:-}" ]]; then
      echo "SECRET_KEY cannot be empty." >/dev/tty || true
    fi
  done

  ok "RemnaNode SECRET_KEY received"
else
  warn "Step 3: remnanode parameters skipped (--remnanode=${REMNANODE})"
fi

prompt_remnanode_domain

###############################################################################
# Step 4: base packages and core setup
###############################################################################
log "Step 4: base packages and core setup"

aptq "APT update" update
aptq "APT upgrade" upgrade
aptq "Install base packages" install \
  zsh git curl wget ca-certificates gnupg lsb-release apt-transport-https \
  iproute2 ufw htop mc cron ed openssl logrotate jq iperf3 ethtool \
  dnsutils acl fail2ban python3 haproxy

runq "enable cron" systemctl enable --now cron >/dev/null 2>&1 || true
grep -q '^/usr/bin/zsh$' /etc/shells || echo '/usr/bin/zsh' >> /etc/shells

# FD limits and network tuning are handled by external tuning script below.

pick_open_ports
ensure_cert_public_ports
EFFECTIVE_PUBLIC_PORTS="${OPEN_PORTS[*]:-80 443}"

###############################################################################
# TUNING (external, non-interactive)
###############################################################################
if [[ "${RUN_TUNING}" == "1" ]]; then
  log "Kernel/network tuning (external) — apply"
  if curl -fsSL https://raw.githubusercontent.com/akadorkin/vps-network-tuning-script/main/initial.sh | bash -s -- apply; then
    ok "External tuning applied"
  else
    warn "External tuning failed — continuing"
  fi
else
  warn "Tuning skipped (--tuning=${RUN_TUNING})"
fi

###############################################################################
# DOCKER
###############################################################################
log "Installing Docker CE"
DOCKER_LOG="/var/log/install-docker.log"; :> "$DOCKER_LOG"
if ! command -v docker >/dev/null 2>&1; then
  runq "remove old docker keyring" rm -f /usr/share/keyrings/docker-archive-keyring.gpg
  runq "install docker gpg key" bash -lc \
    "curl -fsSL https://download.docker.com/linux/ubuntu/gpg | gpg --batch --yes --dearmor -o /usr/share/keyrings/docker-archive-keyring.gpg >>'$DOCKER_LOG' 2>&1"
  echo "deb [arch=$(dpkg --print-architecture) signed-by=/usr/share/keyrings/docker-archive-keyring.gpg] https://download.docker.com/linux/ubuntu $(lsb_release -cs) stable" \
    > /etc/apt/sources.list.d/docker.list
  aptq "APT update (docker)" update
  aptq "Install Docker CE" install docker-ce docker-ce-cli containerd.io docker-compose-plugin
  runq "enable docker" systemctl enable --now docker
else
  ok "Docker already installed — skipping"
fi

###############################################################################
# USER + SSH
###############################################################################
log "User and SSH setup"

if [[ -n "${USER_NAME:-}" ]]; then
  PASS_GEN=""
  PASS_FILE="/root/initial-user-password.txt"
  PASS_CREATED="0"

  if id -u "${USER_NAME}" >/dev/null 2>&1; then
    ok "User ${USER_NAME} exists — not creating"
  else
    PASS_GEN="$(openssl rand -base64 16)"
    runq "useradd ${USER_NAME}" useradd -m -s /usr/bin/zsh "${USER_NAME}"
    runq "set user password" bash -lc "echo '${USER_NAME}:${PASS_GEN}' | chpasswd"
    PASS_CREATED="1"
    ok "Created user ${USER_NAME}"
  fi

  runq "set user shell zsh" chsh -s /usr/bin/zsh "${USER_NAME}" || true
  runq "add to sudo,docker" usermod -aG sudo,docker "${USER_NAME}" || true

  mkdir -p /etc/sudoers.d
  cat > "/etc/sudoers.d/${USER_NAME}" <<EOF
${USER_NAME} ALL=(ALL) NOPASSWD:ALL
EOF
  chmod 0440 "/etc/sudoers.d/${USER_NAME}"

  HOME_DIR="/home/${USER_NAME}"
  if [[ ! -d "${HOME_DIR}" ]]; then
    mkdir -p "${HOME_DIR}"
    chown "${USER_NAME}:${USER_NAME}" "${HOME_DIR}" || true
  fi
  runq "mkdir ~/.ssh" mkdir -p "${HOME_DIR}/.ssh"
  runq "chmod 700 ~/.ssh" chmod 700 "${HOME_DIR}/.ssh"

  AUTH_SRC=""
  if [[ -f /root/.ssh/authorized_keys && -s /root/.ssh/authorized_keys ]]; then
    AUTH_SRC="/root/.ssh/authorized_keys"
  elif [[ -f /home/ubuntu/.ssh/authorized_keys && -s /home/ubuntu/.ssh/authorized_keys ]]; then
    AUTH_SRC="/home/ubuntu/.ssh/authorized_keys"
  fi

  if [[ -n "$AUTH_SRC" ]]; then
    runq "copy authorized_keys from ${AUTH_SRC}" install -m 0600 "$AUTH_SRC" "${HOME_DIR}/.ssh/authorized_keys"
    runq "chown ~/.ssh" chown -R "${USER_NAME}:${USER_NAME}" "${HOME_DIR}/.ssh"
    ok "SSH keys copied -> ${HOME_DIR}/.ssh/authorized_keys"
  else
    warn "authorized_keys not found for root or ubuntu — SSH keys were NOT copied to ${USER_NAME}"
  fi

  if [[ "${PASS_CREATED}" == "1" ]]; then
    section "🔐 New user credentials"
    echo "  User:     ${USER_NAME}"
    echo "  Password: ${PASS_GEN}"
    printf "%s:%s
" "${USER_NAME}:${PASS_GEN}" > "${PASS_FILE}"
    chmod 600 "${PASS_FILE}" || true
    ok "Saved credentials to: ${PASS_FILE} (root-only)"
  fi

  mkdir -p /opt
  setfacl -R -m "u:${USER_NAME}:rwX" /opt || true
  setfacl -R -d -m "u:${USER_NAME}:rwX" /opt || true
  ok "ACL applied on /opt for ${USER_NAME}"

  for rc in "${HOME_DIR}/.bashrc" "${HOME_DIR}/.zshrc"; do
    touch "$rc"
    if ! grep -q "alias apt='sudo apt'" "$rc" 2>/dev/null; then
      cat >> "$rc" <<'EOF'
alias apt='sudo apt'
alias apt-get='sudo apt-get'
EOF
    fi
    chown "${USER_NAME}:${USER_NAME}" "$rc" || true
  done
  ok "apt aliases added for ${USER_NAME}"

  zsh_stack_for_user "${USER_NAME}" "${HOME_DIR}" || warn "Zsh stack for ${USER_NAME} failed — continuing"
  zsh_stack_for_root "${HOME_DIR}" || warn "Zsh stack for root failed — continuing"
else
  warn "User creation skipped"
  zsh_stack_for_root "/root" || warn "Zsh stack for root failed — continuing"
fi

harden_sshd

###############################################################################
# REMNANODE COMPOSE
###############################################################################
log "Checking remnanode docker-compose.yml"
REMNA_COMPOSE="/opt/remnanode/docker-compose.yml"
if [[ -f "${REMNA_COMPOSE}" ]]; then
  ok "remnanode already installed — ${REMNA_COMPOSE} found, skipping generation"
else
  if [[ "${REMNANODE}" == "1" ]]; then
    log "remnanode not found, creating ${REMNA_COMPOSE}"
    runq "mkdir /opt/remnanode" mkdir -p /opt/remnanode

    mkdir -p /var/log/remnanode
    if [[ -n "${USER_NAME:-}" ]]; then
      setfacl -R -m "u:${USER_NAME}:rwX" /var/log/remnanode || true
      setfacl -R -d -m "u:${USER_NAME}:rwX" /var/log/remnanode || true
    fi

    cat > "${REMNA_COMPOSE}" <<EOF
services:
  remnanode:
    container_name: remnanode
    hostname: remnanode
    image: remnawave/node:latest
    network_mode: host
    cap_add:
      - NET_ADMIN
    restart: always
    ulimits:
      nofile:
        soft: 1048576
        hard: 1048576
    environment:
      - NODE_PORT=${NODE_PORT}
      - SECRET_KEY=${SECRET_KEY}
    volumes:
      - './roscomvpn-geosite.dat:/usr/local/share/xray/roscomvpn-geosite.dat:ro'
      - './roscomvpn-geoip.dat:/usr/local/share/xray/roscomvpn-geoip.dat:ro'
      - '/opt/certbot/certs:/etc/letsencrypt:ro'
      - '/var/log/remnanode:/var/log/remnanode'
EOF
    chmod 0644 "${REMNA_COMPOSE}"
    ok "Created remnanode compose: ${REMNA_COMPOSE}"
  else
    warn "remnanode compose is missing, but REMNANODE=0 — skipping generation"
  fi
fi

if [[ -f "${REMNA_COMPOSE}" ]]; then
  normalize_remnanode_compose_environment
  normalize_remnanode_compose_volumes
  install_roscomvpn_geo_updater
  wait_for_domain_dns
  issue_remnanode_certificate
fi

cat > /etc/logrotate.d/remnanode <<'EOF'
/var/log/remnanode/*.log {
    daily
    rotate 7
    size 50M
    missingok
    notifempty
    compress
    delaycompress
    copytruncate
    create 0640 root adm
}
EOF
chmod 0644 /etc/logrotate.d/remnanode
ok "logrotate for /var/log/remnanode installed"

###############################################################################
# FAIL2BAN
###############################################################################
log "Configuring Fail2ban (sshd + sshd-fast + recidive, incremental bantime)"

touch /var/log/fail2ban.log
chmod 640 /var/log/fail2ban.log || true

cat > /etc/fail2ban/fail2ban.local <<'EOF'
[Definition]
logtarget = /var/log/fail2ban.log
EOF
chmod 0644 /etc/fail2ban/fail2ban.local

cat > /etc/fail2ban/jail.d/00-defaults.local <<'EOF'
[DEFAULT]
banaction = ufw
backend   = systemd

findtime = 5m
maxretry = 2
bantime  = 6h

bantime.increment = true
bantime.factor    = 2
bantime.maxtime   = 4w
bantime.rndtime   = 10m

ignoreip = 127.0.0.1/8 ::1 100.64.0.0/10

usedns = warn
EOF
chmod 0644 /etc/fail2ban/jail.d/00-defaults.local

cat > /etc/fail2ban/jail.d/sshd.local <<EOF
[sshd]
enabled = true
port    = ${SSH_PORT}
mode    = aggressive
EOF
chmod 0644 /etc/fail2ban/jail.d/sshd.local

cat > /etc/fail2ban/jail.d/sshd-fast.local <<EOF
[sshd-fast]
enabled  = true
filter   = sshd
backend  = systemd
banaction = ufw
port     = ${SSH_PORT}
mode     = aggressive
findtime = 2m
maxretry = 2
bantime  = 12h
EOF
chmod 0644 /etc/fail2ban/jail.d/sshd-fast.local

cat > /etc/fail2ban/jail.d/recidive.local <<'EOF'
[recidive]
enabled  = true
logpath  = /var/log/fail2ban.log
findtime = 7d
maxretry = 3
bantime  = 4w
EOF
chmod 0644 /etc/fail2ban/jail.d/recidive.local

runq "enable fail2ban"  systemctl enable --now fail2ban
runq "restart fail2ban" systemctl restart fail2ban

###############################################################################
# RUGOV nftables blacklist (input-only) + cron + logrotate
###############################################################################
log "Installing rugov nftables input-only blacklist updater"

cat > /usr/local/sbin/update-rugov-nftables <<'EOF'
#!/usr/bin/env bash
set -Eeuo pipefail

PATH=/usr/sbin:/usr/bin:/sbin:/bin

BASE_DIR="/etc/nftables.d/rugov"
V4_URL="https://raw.githubusercontent.com/C24Be/AS_Network_List/main/blacklists_nftables/blacklist-v4.nft"
V6_URL="https://raw.githubusercontent.com/C24Be/AS_Network_List/main/blacklists_nftables/blacklist-v6.nft"

mkdir -p "$BASE_DIR"

tmp_v4="$(mktemp)"
tmp_v6="$(mktemp)"
trap 'rm -f "$tmp_v4" "$tmp_v6"' EXIT

curl -fsSL --connect-timeout 10 --max-time 60 "$V4_URL" -o "$tmp_v4"
curl -fsSL --connect-timeout 10 --max-time 60 "$V6_URL" -o "$tmp_v6"

install -m 0644 "$tmp_v4" "$BASE_DIR/blacklist-v4.nft"
install -m 0644 "$tmp_v6" "$BASE_DIR/blacklist-v6.nft"

nft -f "$BASE_DIR/blacklist-v4.nft"
nft -f "$BASE_DIR/blacklist-v6.nft"

nft 'add chain inet filter rugov_input { type filter hook input priority -50; policy accept; }' 2>/dev/null || true
nft flush chain inet filter rugov_input

nft add rule inet filter rugov_input iifname "lo" accept
nft add rule inet filter rugov_input ct state established,related accept
nft add rule inet filter rugov_input iifname "tailscale0" accept
nft add rule inet filter rugov_input ip saddr @blacklist_v4 counter reject
nft add rule inet filter rugov_input ip6 saddr @blacklist_v6 counter reject

nft delete chain inet filter rugov_output 2>/dev/null || true
EOF
chmod 0755 /usr/local/sbin/update-rugov-nftables

cat > /etc/cron.d/update-rugov-nftables <<'EOF'
SHELL=/bin/bash
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin

@reboot root /usr/local/sbin/update-rugov-nftables >> /var/log/update-rugov-nftables.log 2>&1
0 2 * * * root /usr/local/sbin/update-rugov-nftables >> /var/log/update-rugov-nftables.log 2>&1
EOF
chmod 0644 /etc/cron.d/update-rugov-nftables

cat > /etc/logrotate.d/update-rugov-nftables <<'EOF'
/var/log/update-rugov-nftables.log {
    daily
    rotate 14
    missingok
    notifempty
    compress
    delaycompress
    copytruncate
    create 0640 root adm
}
EOF
chmod 0644 /etc/logrotate.d/update-rugov-nftables

runq "apply rugov nftables now" bash -lc '/usr/local/sbin/update-rugov-nftables >> /var/log/update-rugov-nftables.log 2>&1'

###############################################################################
# UFW
###############################################################################
log "Configuring UFW"

if ! command -v ufw >/dev/null 2>&1; then
  aptq "Install UFW" install ufw
fi

if [[ -f /etc/default/ufw ]]; then
  if grep -q '^DEFAULT_FORWARD_POLICY=' /etc/default/ufw; then
    sed -i 's/^DEFAULT_FORWARD_POLICY=.*/DEFAULT_FORWARD_POLICY="ACCEPT"/' /etc/default/ufw || true
  else
    echo 'DEFAULT_FORWARD_POLICY="ACCEPT"' >> /etc/default/ufw
  fi
fi

INTERNET_IFACE="$(ip route get 8.8.8.8 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="dev") print $(i+1)}' | head -n1 || true)"
[[ -n "$INTERNET_IFACE" ]] || INTERNET_IFACE="$(ip route 2>/dev/null | awk '/default/ {for(i=1;i<=NF;i++) if($i=="dev") print $(i+1)}' | head -n1 || true)"

if [[ -z "${INTERNET_IFACE}" ]]; then
  err "Failed to detect INTERNET_IFACE — aborting UFW configuration."
else
  ok "External interface: ${INTERNET_IFACE}"

  runq "ufw reset"             ufw --force reset
  runq "ufw default deny in"   ufw default deny incoming
  runq "ufw default allow out" ufw default allow outgoing

  for port in "${OPEN_PORTS[@]}"; do
    ufw allow in on "${INTERNET_IFACE}" to any port "${port}" proto tcp >/dev/null 2>&1 || true
    ufw allow in on "${INTERNET_IFACE}" to any port "${port}" proto udp >/dev/null 2>&1 || true
  done

  DOCKER_IFACES="$(ip -o link show 2>/dev/null | awk -F': ' '$2 ~ /^(docker0|br-)/ {print $2}' || true)"
  if [[ -n "${DOCKER_IFACES}" ]]; then
    for IFACE in ${DOCKER_IFACES}; do
      ufw allow in on "${IFACE}"  >/dev/null 2>&1 || true
      ufw allow out on "${IFACE}" >/dev/null 2>&1 || true
    done
  fi

  if ip link show tailscale0 >/dev/null 2>&1; then
    # Trust the private tailnet completely: every inbound/outbound protocol and port.
    ufw allow in on tailscale0  >/dev/null 2>&1 || true
    ufw allow out on tailscale0 >/dev/null 2>&1 || true

    # Also add raw iptables accepts so tailscale traffic survives strict UFW/default policies.
    iptables -C INPUT -i tailscale0 -j ACCEPT 2>/dev/null || iptables -I INPUT 1 -i tailscale0 -j ACCEPT || true
    iptables -C OUTPUT -o tailscale0 -j ACCEPT 2>/dev/null || iptables -I OUTPUT 1 -o tailscale0 -j ACCEPT || true
    ip6tables -C INPUT -i tailscale0 -j ACCEPT 2>/dev/null || ip6tables -I INPUT 1 -i tailscale0 -j ACCEPT || true
    ip6tables -C OUTPUT -o tailscale0 -j ACCEPT 2>/dev/null || ip6tables -I OUTPUT 1 -o tailscale0 -j ACCEPT || true

    ok "tailscale0 is fully allowed"
  fi

  # External interface policy: only OPEN_PORTS are allowed.
  # SSH is intentionally not opened by default; add ${SSH_PORT} to --open-ports if public SSH is required.
  if printf ' %s ' "${OPEN_PORTS[@]}" | grep -q " ${SSH_PORT} "; then
    ok "Public SSH is explicitly allowed via open ports: ${SSH_PORT}/tcp+udp"
  else
    ufw deny in on "${INTERNET_IFACE}" to any port "${SSH_PORT}" proto tcp >/dev/null 2>&1 || true
    ufw deny in on "${INTERNET_IFACE}" to any port "${SSH_PORT}" proto udp >/dev/null 2>&1 || true
    ufw deny in on "${INTERNET_IFACE}" to any port 2222 proto tcp >/dev/null 2>&1 || true
    ufw deny in on "${INTERNET_IFACE}" to any port 2222 proto udp >/dev/null 2>&1 || true
    ufw deny in on "${INTERNET_IFACE}" to any port 5443 proto tcp >/dev/null 2>&1 || true
    ufw deny in on "${INTERNET_IFACE}" to any port 5443 proto udp >/dev/null 2>&1 || true
    ufw deny in on "${INTERNET_IFACE}" to any port 5444 proto tcp >/dev/null 2>&1 || true
    ufw deny in on "${INTERNET_IFACE}" to any port 5444 proto udp >/dev/null 2>&1 || true
    ufw deny in on "${INTERNET_IFACE}" to any port 9100 proto tcp >/dev/null 2>&1 || true
    ufw deny in on "${INTERNET_IFACE}" to any port 9100 proto udp >/dev/null 2>&1 || true
    ok "Public SSH is closed; SSH remains available over tailscale0 if Tailscale is up"
  fi

  for rule in \
    "6881:6999/tcp" \
    "6881:6999/udp" \
    "51413/tcp" \
    "51413/udp" \
    "16881/tcp" \
    "16881/udp" \
    "2710/tcp" \
    "2710/udp" \
    "45682/tcp" \
    "45682/udp"
  do
    ufw deny out "$rule" >/dev/null 2>&1 || true
  done

  ok "UFW rules staged; final enable will happen at the end"
fi

###############################################################################
# NODE EXPORTER
###############################################################################
log "Installing node_exporter"

node_exporter_install() {
  set -euo pipefail
  local VERSION="1.9.1"
  local USER="node_exporter"
  local BIN_DIR="/usr/local/bin"
  local SERVICE_FILE="/etc/systemd/system/node_exporter.service"
  local ARCHIVE="node_exporter-${VERSION}.linux-amd64.tar.gz"
  local EXTRACT_DIR="node_exporter-${VERSION}.linux-amd64"
  local DOWNLOAD_URL="https://github.com/prometheus/node_exporter/releases/download/v${VERSION}/${ARCHIVE}"

  wget -q -O "/root/${ARCHIVE}" "$DOWNLOAD_URL"
  tar -xzf "/root/${ARCHIVE}" -C /root
  mv "/root/${EXTRACT_DIR}/node_exporter" "${BIN_DIR}/node_exporter"
  chmod +x "${BIN_DIR}/node_exporter"
  id -u "$USER" >/dev/null 2>&1 || useradd --no-create-home --shell /bin/false "$USER" || true

  cat > "$SERVICE_FILE" <<EOF
[Unit]
Description=Prometheus Node Exporter
After=network.target

[Service]
User=${USER}
Group=${USER}
Type=simple
ExecStart=${BIN_DIR}/node_exporter
Restart=always

[Install]
WantedBy=multi-user.target
EOF

  systemctl daemon-reload
  systemctl enable --now node_exporter
  rm -rf "/root/${ARCHIVE}" "/root/${EXTRACT_DIR}"
}
node_exporter_install || warn "node_exporter install failed — continuing"

###############################################################################
# DNS SWITCHER — fixed Cloudflare
###############################################################################
log "DNS switcher — fixed Cloudflare"
BACKUP_DIR="/etc/dns-switcher-backup"
mkdir -p "$BACKUP_DIR"
[[ -f /etc/systemd/resolved.conf ]] && cp /etc/systemd/resolved.conf "$BACKUP_DIR/resolved.conf.backup.$(date +%Y%m%d_%H%M%S)" || true
resolvectl status > "$BACKUP_DIR/dns_status.backup.$(date +%Y%m%d_%H%M%S)" 2>&1 || true
cat > /etc/systemd/resolved.conf <<'EOF'
# Managed by VPS bootstrap
# DNS profile: Cloudflare

[Resolve]
DNS=1.1.1.1 1.0.0.1
FallbackDNS=9.9.9.9 149.112.112.112
Domains=~.
DNSSEC=no
DNSOverTLS=no
Cache=yes
EOF
systemctl restart systemd-resolved || true
sleep 1
ok "DNS profile: Cloudflare (1.1.1.1 1.0.0.1); backups: ${BACKUP_DIR}"

###############################################################################
# REMNANODE UP
###############################################################################
if [[ -f "${REMNA_COMPOSE}" ]]; then
  log "Starting remnanode (docker compose up -d)"
  runq "remnanode up" bash -lc 'cd /opt/remnanode && docker compose up -d'
else
  warn "remnanode docker-compose.yml not found — skipping remnanode start"
fi

###############################################################################
# FINAL FIREWALL ENABLE
###############################################################################
log "Final firewall enable"

if command -v ufw >/dev/null 2>&1; then
  runq "ufw enable" ufw --force enable || true
  ok "UFW enabled and will start on boot"
else
  warn "ufw binary not found at final enable step"
fi

###############################################################################
# AUTOREMOVE
###############################################################################
aptq "Autoremove" autoremove --purge

exit 0
