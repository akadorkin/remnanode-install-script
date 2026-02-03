#!/usr/bin/env bash
set -Eeuo pipefail

###############################################################################
# VPS bootstrap (user + docker + tailscale + ufw + fail2ban + dns switcher)
# - Interactive port picker (no hardcode required)
# - Tailscale (optional): detect already-auth + already-running; otherwise run `tailscale up`
# - Fail2ban: sshd + sshd-fast + recidive (NO sshd-ddos dependency)
# - DNS switcher: overwrites /etc/systemd/resolved.conf (as requested)
# - Network tuning: calls external script (your repo)
#
# Flags:
#   --user <name>              required if non-interactive
#   --timezone <IANA TZ>       default: Europe/Moscow
#   --reboot <delay>           default: 5m; 0|no|none|skip disables reboot
#   --remnanode 0|1            default: 0
#   --ssh-port <port>          default: env SSH_PORT or 22
#   --ports ask|skip           default: ask if TTY, otherwise skip
#   --open-ports "<list>"      comma/space separated list (overrides dialog)
#   --tuning 0|1               default: 1
#   --dns-switch 0|1           default: 1
#   --dns-profile 1..5         default: auto (interactive if TTY, else 1)
#                              1 = echo "1" and skip interactive (no change)
#                              2 = Google only
#                              3 = Cloudflare only
#                              4 = Quad9
#                              5 = Custom (requires --dns-custom + optional --dns-fallback)
#   --dns-custom "<servers>"   used when --dns-profile 5
#   --dns-fallback "<server>"  used when --dns-profile 5 (default 9.9.9.9)
#   --tailscale 0|1            default: 0
###############################################################################

###############################################################################
# ARG PARSING
###############################################################################
USER_NAME=""
TIMEZONE="Europe/Moscow"
REBOOT_DELAY="5m"
SSH_PORT="${SSH_PORT:-22}"
REMNANODE="0"
PORTS_MODE=""
OPEN_PORTS_RAW=""
RUN_TUNING="1"
RUN_DNS_SWITCH="1"

RUN_TAILSCALE="0"
DNS_PROFILE=""      # 1..5|"" (auto)
DNS_CUSTOM=""       # for profile=5
DNS_FALLBACK=""     # for profile=5

NODE_PORT=""
SECRET_KEY=""

DEFAULT_OPEN_PORTS=(22 1080 1090 443 80 1480 1194)

usage() {
  cat <<'EOF'
Usage: sudo bash initial.sh [options]

Options:
  --user <name> | --user=<name>
  --timezone <IANA> | --timezone=<IANA>              (default: Europe/Moscow)
  --reboot <delay> | --reboot=<delay>                (default: 5m; 0|no|none|skip disables)
  --remnanode 0|1 | --remnanode=0|1                  (default: 0)
  --ssh-port <port> | --ssh-port=<port>              (default: 22)
  --ports ask|skip | --ports=ask|skip                (default: ask if TTY, else skip)
  --open-ports "<list>" | --open-ports="<list>"      comma/space-separated ports

  --tuning 0|1 | --tuning=0|1                         (default: 1)

  --dns-switch 0|1 | --dns-switch=0|1                 (default: 1)
  --dns-profile 1..5 | --dns-profile=1..5             (default: auto)
  --dns-custom "<servers>"                             (for --dns-profile 5)
  --dns-fallback "<server>"                            (for --dns-profile 5; default: 9.9.9.9)

  --tailscale 0|1 | --tailscale=0|1                   (default: 0)
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --user=*)         USER_NAME="${1#*=}"; shift ;;
    --timezone=*)     TIMEZONE="${1#*=}"; shift ;;
    --reboot=*)       REBOOT_DELAY="${1#*=}"; shift ;;
    --remnanode=*)    REMNANODE="${1#*=}"; shift ;;
    --ssh-port=*)     SSH_PORT="${1#*=}"; shift ;;
    --ports=*)        PORTS_MODE="${1#*=}"; shift ;;
    --open-ports=*)   OPEN_PORTS_RAW="${1#*=}"; shift ;;
    --tuning=*)       RUN_TUNING="${1#*=}"; shift ;;
    --dns-switch=*)   RUN_DNS_SWITCH="${1#*=}"; shift ;;
    --dns-profile=*)  DNS_PROFILE="${1#*=}"; shift ;;
    --dns-custom=*)   DNS_CUSTOM="${1#*=}"; shift ;;
    --dns-fallback=*) DNS_FALLBACK="${1#*=}"; shift ;;
    --tailscale=*)    RUN_TAILSCALE="${1#*=}"; shift ;;

    --user)         USER_NAME="${2:-}"; shift 2 ;;
    --timezone)     TIMEZONE="${2:-}"; shift 2 ;;
    --reboot)       REBOOT_DELAY="${2:-}"; shift 2 ;;
    --remnanode)    REMNANODE="${2:-0}"; shift 2 ;;
    --ssh-port)     SSH_PORT="${2:-22}"; shift 2 ;;
    --ports)        PORTS_MODE="${2:-}"; shift 2 ;;
    --open-ports)   OPEN_PORTS_RAW="${2:-}"; shift 2 ;;
    --tuning)       RUN_TUNING="${2:-1}"; shift 2 ;;
    --dns-switch)   RUN_DNS_SWITCH="${2:-1}"; shift 2 ;;
    --dns-profile)  DNS_PROFILE="${2:-}"; shift 2 ;;
    --dns-custom)   DNS_CUSTOM="${2:-}"; shift 2 ;;
    --dns-fallback) DNS_FALLBACK="${2:-}"; shift 2 ;;
    --tailscale)    RUN_TAILSCALE="${2:-0}"; shift 2 ;;

    -h|--help) usage; exit 0 ;;
    *) echo "Unknown arg: $1"; usage; exit 1 ;;
  esac
done

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

ts_iso() { date -Iseconds; }

color() {
  local code="$1"; shift || true
  if [[ -t 1 ]]; then
    printf "%s%s%s" "$code" "$*" "$c_reset"
  else
    printf "%s" "$*"
  fi
}

hdr() {
  echo
  color "${c_bold}${c_cyan}" "==> $*"
  echo
}

log()  { color "${c_bold}${c_cyan}" "==>"; echo " $*"; }
ok()   { color "${c_grn}" "OK "; echo " $*"; }
warn() { color "${c_yel}" "WARN"; echo " $*"; }
err()  { color "${c_red}" "ERR "; echo " $*"; }

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

###############################################################################
# SSHD HELPERS
###############################################################################
SSHD_CONFIG="/etc/ssh/sshd_config"
get_sshd_effective() {
  local key="$1"
  if [[ -f "$SSHD_CONFIG" ]]; then
    awk -v k="$key" '
      BEGIN{IGNORECASE=1; v=""}
      /^[[:space:]]*#/ {next}
      /^[[:space:]]*$/ {next}
      { if (tolower($1)==tolower(k) && NF>=2) { v=$2 } }
      END{ if (v=="") print "(unset)"; else print v }' "$SSHD_CONFIG"
  else
    echo "(no_config)"
  fi
}

###############################################################################
# PORTS PICKER
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

pick_open_ports() {
  OPEN_PORTS=("${DEFAULT_OPEN_PORTS[@]}")

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
  echo
  echo "Open ports on external interface (TCP+UDP)."
  echo "Default: ${def}"
  echo "Enter ports (space/comma-separated), or empty for default."
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

###############################################################################
# START
###############################################################################
require_root
export DEBIAN_FRONTEND=noninteractive
export NEEDRESTART_MODE=a

log "Parameters: user='${USER_NAME:-<ask>}' timezone='${TIMEZONE}' reboot='${REBOOT_DELAY}' remnanode='${REMNANODE}' ssh_port='${SSH_PORT}' tuning='${RUN_TUNING}' dns-switch='${RUN_DNS_SWITCH}' dns-profile='${DNS_PROFILE:-<auto>}' tailscale='${RUN_TAILSCALE}'"

if [[ -z "${USER_NAME}" ]]; then
  if _is_tty; then
    read_tty USER_NAME "Enter username to create (e.g., akadorkin): "
  fi
  [[ -n "$USER_NAME" ]] || { err "Username is empty (provide --user)"; exit 1; }
fi
ok "User: $USER_NAME"
HOME_DIR="/home/${USER_NAME}"

###############################################################################
# STEP 0: HOSTNAME (interactive if TTY)
###############################################################################
log "Step 0: hostname"
CURRENT_HOST="$(hostname 2>/dev/null || true)"
NEW_HOST=""
if _is_tty; then
  read_tty NEW_HOST "Enter hostname (press Enter to keep '${CURRENT_HOST}'): "
fi
if [[ -n "${NEW_HOST:-}" ]]; then
  runq "hostnamectl set-hostname" hostnamectl set-hostname "${NEW_HOST}" || true
  ok "Hostname set to: ${NEW_HOST}"
else
  ok "Hostname unchanged: ${CURRENT_HOST}"
fi

###############################################################################
# PORTS
###############################################################################
pick_open_ports

###############################################################################
# REMNANODE: ASK EARLY (interactive even with curl|bash via /dev/tty)
###############################################################################
if [[ "${REMNANODE}" == "1" ]]; then
  log "remnanode=1 -> requesting parameters"

  NODE_PORT="${NODE_PORT:-2222}"

  if _has_tty; then
    read_tty NODE_PORT "Enter NODE_PORT for remnanode (default: 2222): "
    [[ -n "${NODE_PORT}" ]] || NODE_PORT="2222"
    read_tty_silent SECRET_KEY "Paste SECRET_KEY (input hidden): "
  else
    warn "/dev/tty is not available — cannot prompt for remnanode parameters"
  fi

  [[ -n "${NODE_PORT:-}" ]] || NODE_PORT="2222"
  if [[ -z "${SECRET_KEY:-}" ]]; then
    err "SECRET_KEY is empty — remnanode compose will not be created"
    REMNANODE="0"
  else
    ok "remnanode parameters received"
  fi
fi

###############################################################################
# FD LIMITS
###############################################################################
apply_fd_limits() {
  log "FD limits (kernel + systemd defaults)"

  install -m 0644 /dev/stdin /etc/sysctl.d/99-fd.conf <<'EOF_FD'
fs.file-max = 2097152
fs.nr_open = 2097152
EOF_FD

  mkdir -p /etc/systemd/system.conf.d
  install -m 0644 /dev/stdin /etc/systemd/system.conf.d/99-limits.conf <<'EOF_SYS'
[Manager]
DefaultLimitNOFILE=1048576
DefaultTasksMax=infinity
EOF_SYS

  runq "sysctl --system" sysctl --system || true
  runq "systemd daemon-reexec" systemctl daemon-reexec || true
  ok "FD limits applied"
}

###############################################################################
# APT (quiet, logged)
###############################################################################
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
    err "$what — failed. Tail of log:"; tail -n 60 "$APT_LOG" || true
    echo "Full log: $APT_LOG"
    exit 1
  fi
}

aptq "APT update" update
aptq "APT upgrade" upgrade
aptq "Install base packages" install \
  zsh git curl wget ca-certificates gnupg lsb-release apt-transport-https \
  iproute2 ufw htop mc cron ed openssl logrotate jq iperf3 ethtool \
  dnsutils

runq "enable cron" systemctl enable --now cron >/dev/null 2>&1 || true
grep -q '^/usr/bin/zsh$' /etc/shells || echo '/usr/bin/zsh' >> /etc/shells

apply_fd_limits

###############################################################################
# TIMEZONE
###############################################################################
log "Configuring timezone -> ${TIMEZONE}"
runq "link /etc/localtime" ln -sf "/usr/share/zoneinfo/${TIMEZONE}" /etc/localtime || true
runq "timedatectl set-timezone" timedatectl set-timezone "${TIMEZONE}" || true
ok "Timezone configured"

###############################################################################
# DOCKER
###############################################################################
log "Installing Docker CE (quiet)"
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
PASS_GEN=""
if id -u "${USER_NAME}" >/dev/null 2>&1; then
  ok "User ${USER_NAME} exists — not creating"
else
  PASS_GEN="$(openssl rand -base64 16)"
  runq "useradd ${USER_NAME}" useradd -m -s /usr/bin/zsh "${USER_NAME}"
  runq "set user password" bash -lc "echo '${USER_NAME}:${PASS_GEN}' | chpasswd"
  ok "Created user ${USER_NAME}"
fi

runq "set user shell zsh" chsh -s /usr/bin/zsh "${USER_NAME}" || true
runq "add to sudo,docker" usermod -aG sudo,docker "${USER_NAME}" || true

install -m 0440 /dev/stdin "/etc/sudoers.d/${USER_NAME}" <<EOF_SUDO
${USER_NAME} ALL=(ALL) NOPASSWD:ALL
EOF_SUDO

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
else
  warn "authorized_keys not found for root or ubuntu — SSH keys were NOT copied to ${USER_NAME}"
fi

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

    install -m 0644 /dev/stdin "${REMNA_COMPOSE}" <<EOF_DC
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
EOF_DC
    ok "Created remnanode compose: ${REMNA_COMPOSE}"
  else
    warn "remnanode compose is missing, but REMNANODE=0 — skipping generation"
  fi
fi

###############################################################################
# TAILSCALE (optional)
###############################################################################
TAILSCALE_LOG="/var/log/install-tailscale.log"; :> "$TAILSCALE_LOG"
INTERNET_IFACE="$(ip route show default 2>/dev/null | awk '/default/ {print $5; exit}' || true)"

ensure_tailscale_up() {
  if systemctl is-active --quiet tailscaled 2>/dev/null; then
    local ip4=""
    ip4="$(tailscale ip -4 2>/dev/null || true)"
    if [[ -n "$ip4" ]]; then
      ok "Tailscale already authorized and running"
      echo "Tailscale IPv4: $ip4"
      return 0
    fi
  fi

  log "Running tailscale up (waiting for authorization)"
  set +e
  tailscale up --advertise-exit-node --ssh | tee /tmp/tailscale-up.log
  local rc=${PIPESTATUS[0]}
  set -e

  if [[ $rc -ne 0 ]]; then
    warn "tailscale up returned non-zero (rc=$rc). Continuing."
  fi

  local url=""
  url="$(grep -Eo 'https://login\.tailscale\.com/[a-zA-Z0-9/_-]+' /tmp/tailscale-up.log | head -n1 || true)"
  if [[ -n "$url" ]]; then
    echo "Open to authorize: $url"
  else
    warn "Authorization URL not found (maybe already authorized)."
  fi

  if _is_tty; then
    local _=""
    read_tty _ "Press Enter after authorizing this device in Tailscale..."
  fi

  local ip4=""
  ip4="$(tailscale ip -4 2>/dev/null || true)"
  echo "Tailscale IPv4: ${ip4:-not assigned}"
}

if [[ "${RUN_TAILSCALE}" == "1" ]]; then
  log "Tailscale setup (install + sysctl forwarding + UDP GRO)"
  if ! command -v tailscale >/dev/null 2>&1; then
    runq "install tailscale" bash -lc 'curl -fsSL https://tailscale.com/install.sh | sh >>/var/log/install-tailscale.log 2>&1'
  else
    ok "Tailscale already installed — skipping install"
  fi

  install -m 0644 /dev/stdin /etc/sysctl.d/99-tailscale-forwarding.conf <<'EOF_SYSCTL'
net.ipv4.ip_forward=1
net.ipv6.conf.all.forwarding=1
net.ipv4.conf.all.rp_filter=0
net.ipv4.conf.default.rp_filter=0
EOF_SYSCTL
  runq "sysctl --system" sysctl --system || true

  if [[ -n "${INTERNET_IFACE:-}" ]]; then
    runq "ethtool gro on"            ethtool -K "${INTERNET_IFACE}" gro on || true
    runq "ethtool rx-udp-gro-fwd on" ethtool -K "${INTERNET_IFACE}" rx-udp-gro-forwarding on || true
  fi

  ensure_tailscale_up
else
  warn "Tailscale disabled (--tailscale=${RUN_TAILSCALE})"
fi

###############################################################################
# FAIL2BAN
###############################################################################
log "Configuring Fail2ban (sshd + sshd-fast + recidive, incremental bantime)"
aptq "Install fail2ban" install fail2ban

touch /var/log/fail2ban.log
chmod 640 /var/log/fail2ban.log || true

install -m 0644 /dev/stdin /etc/fail2ban/fail2ban.local <<'EOF_F2B_LOCAL'
[Definition]
logtarget = /var/log/fail2ban.log
EOF_F2B_LOCAL

install -m 0644 /dev/stdin /etc/fail2ban/jail.d/00-defaults.local <<'EOF_F2B_DEFAULTS'
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
EOF_F2B_DEFAULTS

install -m 0644 /dev/stdin /etc/fail2ban/jail.d/sshd.local <<EOF_SSHD
[sshd]
enabled = true
port    = ${SSH_PORT}
mode    = aggressive
EOF_SSHD

install -m 0644 /dev/stdin /etc/fail2ban/jail.d/sshd-fast.local <<EOF_SSHD_FAST
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
EOF_SSHD_FAST

install -m 0644 /dev/stdin /etc/fail2ban/jail.d/recidive.local <<'EOF_RECIDIVE'
[recidive]
enabled  = true
logpath  = /var/log/fail2ban.log
findtime = 7d
maxretry = 3
bantime  = 4w
EOF_RECIDIVE

runq "enable fail2ban"  systemctl enable --now fail2ban
runq "restart fail2ban" systemctl restart fail2ban

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

# Detect external iface reliably
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

  # Docker interfaces: open all (in/out) on docker0/br-*
  DOCKER_IFACES="$(ip -o link show 2>/dev/null | awk -F': ' '$2 ~ /^(docker0|br-)/ {print $2}' || true)"
  if [[ -n "${DOCKER_IFACES}" ]]; then
    for IFACE in ${DOCKER_IFACES}; do
      ufw allow in on "${IFACE}"  >/dev/null 2>&1 || true
      ufw allow out on "${IFACE}" >/dev/null 2>&1 || true
    done
  fi

  # Tailscale interface: open all if present
  if ip link show tailscale0 >/dev/null 2>&1; then
    ufw allow in on tailscale0  >/dev/null 2>&1 || true
    ufw allow out on tailscale0 >/dev/null 2>&1 || true
  fi

  runq "ufw enable" ufw --force enable
fi

###############################################################################
# NODE EXPORTER
###############################################################################
log "Installing node_exporter (after UFW)"
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
  useradd --no-create-home --shell /bin/false "$USER" || true

  cat > "$SERVICE_FILE" <<EOF_SVC
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
EOF_SVC

  systemctl daemon-reload
  systemctl enable --now node_exporter
  rm -rf "/root/${ARCHIVE}" "/root/${EXTRACT_DIR}"
}
node_exporter_install || warn "node_exporter install failed — continuing"

###############################################################################
# TUNING (external)
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
# DNS SWITCHER
###############################################################################
if [[ "${RUN_DNS_SWITCH}" == "1" ]]; then
  log "DNS switcher — will overwrite /etc/systemd/resolved.conf"

  dns_apply_profile() {
    local profile="${1:-}"
    local dns="" fb=""

    if [[ "$profile" == "1" ]]; then
      echo "1"
      return 0
    fi

    case "$profile" in
      2) dns="8.8.8.8 8.8.4.4"; fb="9.9.9.9" ;;
      3) dns="1.1.1.1 1.0.0.1"; fb="9.9.9.9" ;;
      4) dns="9.9.9.9 149.112.112.112"; fb="1.1.1.1" ;;
      5)
        dns="${DNS_CUSTOM:-}"
        fb="${DNS_FALLBACK:-9.9.9.9}"
        [[ -n "$dns" ]] || { warn "dns-profile=5 requires --dns-custom"; return 1; }
        ;;
      *)
        return 2
        ;;
    esac

    local BACKUP_DIR="/etc/dns-switcher-backup"
    mkdir -p "$BACKUP_DIR"
    [[ -f /etc/systemd/resolved.conf ]] && cp /etc/systemd/resolved.conf "$BACKUP_DIR/resolved.conf.backup.$(date +%Y%m%d_%H%M%S)" || true
    resolvectl status > "$BACKUP_DIR/dns_status.backup.$(date +%Y%m%d_%H%M%S)" 2>&1 || true

    cat > /etc/systemd/resolved.conf <<EOF
# Managed by DNS Switcher
# Original configuration backed up to ${BACKUP_DIR}

[Resolve]
DNS=${dns}
FallbackDNS=${fb}
Domains=~.
DNSSEC=no
DNSOverTLS=no
Cache=yes
EOF

    systemctl restart systemd-resolved || true
    sleep 1
    ok "DNS switch completed. Backups saved to: ${BACKUP_DIR}"
    return 0
  }

  if [[ -n "${DNS_PROFILE:-}" ]]; then
    dns_apply_profile "${DNS_PROFILE}" || warn "DNS profile apply failed — continuing"
  else
    if ! _is_tty; then
      dns_apply_profile "1" || true
    else
      echo "Choose DNS servers:"
      echo "1) No change (echo 1)"
      echo "2) Google only"
      echo "3) Cloudflare only"
      echo "4) Quad9"
      echo "5) Custom"
      echo
      choice=""
      read_tty choice "Enter choice (1-5) [default: 1]: "
      choice="${choice:-1}"
      if [[ "$choice" == "5" ]]; then
        read_tty DNS_CUSTOM "Enter primary DNS servers (space-separated): "
        read_tty DNS_FALLBACK "Enter fallback DNS server [default: 9.9.9.9]: "
        DNS_FALLBACK="${DNS_FALLBACK:-9.9.9.9}"
      fi
      DNS_PROFILE="$choice"
      dns_apply_profile "$DNS_PROFILE" || warn "DNS switcher failed — continuing"
    fi
  fi
else
  warn "DNS switcher skipped (--dns-switch=${RUN_DNS_SWITCH})"
fi

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
# AUTOREMOVE + OPTIONAL REBOOT
###############################################################################
aptq "Autoremove" autoremove --purge

case "${REBOOT_DELAY}" in
  0|no|none|skip|"")
    echo "Reboot disabled (--reboot=${REBOOT_DELAY})."
    ;;
  30s|30sec|30)
    echo "Reboot scheduled in 30 seconds"
    shutdown -r +0.5 >/dev/null 2>&1 || shutdown -r now
    ;;
  5m|5min|300)
    echo "Reboot scheduled in 5 minutes"
    shutdown -r +5 >/dev/null 2>&1 || shutdown -r now
    ;;
  *)
    echo "Reboot scheduled in ${REBOOT_DELAY}"
    shutdown -r +"${REBOOT_DELAY}" >/dev/null 2>&1 || shutdown -r now
    ;;
esac

###############################################################################
# FINAL REPORT
###############################################################################
emoji_service() {
  local unit="$1"
  if systemctl is-active --quiet "$unit" 2>/dev/null; then echo "✅"; else echo "❌"; fi
}

tailscale_magicdns_full() {
  if command -v tailscale >/dev/null 2>&1 && command -v jq >/dev/null 2>&1; then
    tailscale status --json 2>/dev/null | jq -r '.Self.DNSName // empty' | head -n1
  else
    echo ""
  fi
}

external_ip() {
  curl -fsSL ifconfig.me 2>/dev/null || curl -fsSL https://api.ipify.org 2>/dev/null || true
}

ip_identity() {
  local ip="$1"
  [[ -n "$ip" ]] || { echo ""; return 0; }
  curl -fsSL "https://ipinfo.io/${ip}/json" 2>/dev/null || true
}

flag_from_country() {
  local cc="${1:-}"
  [[ "$cc" =~ ^[A-Za-z]{2}$ ]] || { echo ""; return 0; }
  cc="$(echo "$cc" | tr '[:lower:]' '[:upper:]')"

  local a b code1 code2 esc
  a="${cc:0:1}"
  b="${cc:1:1}"

  code1=$(( 127462 + $(printf '%d' "'$a") - 65 ))
  code2=$(( 127462 + $(printf '%d' "'$b") - 65 ))

  # Build literal \Uxxxxxxxx escapes, then expand them via %b
  printf -v esc '\\U%08X\\U%08X' "$code1" "$code2"
  printf '%b' "$esc"
}

remna_status() {
  if ! command -v docker >/dev/null 2>&1; then
    echo "  Status:              ❌ docker missing"
    return 0
  fi
  if ! docker ps --format '{{.Names}}' | grep -qx 'remnanode'; then
    if docker ps -a --format '{{.Names}}' | grep -qx 'remnanode'; then
      echo "  Status:              ❌ stopped"
    else
      echo "  Status:              ⚠️ not found"
    fi
    return 0
  fi
  echo "  Status:              ✅ running"
  local started
  started="$(docker inspect -f '{{.State.StartedAt}}' remnanode 2>/dev/null || true)"
  if [[ -n "$started" ]]; then
    echo "  Started:             ${started}"
    local now_s start_s
    now_s="$(date +%s)"
    start_s="$(date -d "$started" +%s 2>/dev/null || echo 0)"
    if [[ "$start_s" -gt 0 ]]; then
      local diff=$((now_s-start_s))
      local h=$((diff/3600)) m=$(((diff%3600)/60))
      echo "  Uptime:              ⏱️ ${h}h ${m}m"
    fi
  fi
}

sys_summary() {
  local up cores ram_mib root_line
  up="$(uptime -p 2>/dev/null || uptime)"
  cores="$(nproc 2>/dev/null || echo "?")"
  ram_mib="$(awk '/MemTotal:/ {printf "%d", $2/1024}' /proc/meminfo 2>/dev/null || echo "?")"
  root_line="$(df -hP / 2>/dev/null | awk 'NR==2{print $2 " total, " $3 " used, " $4 " free (" $5 ")"}' || true)"
  echo "  Uptime:              ${up}"
  echo "  CPU cores:           ${cores}"
  echo "  RAM:                 ${ram_mib} MiB"
  echo "  /:                   ${root_line:-?}"
}

SSH_PASS_AUTH="$(get_sshd_effective PasswordAuthentication)"
SSH_ROOT_LOGIN="$(get_sshd_effective PermitRootLogin)"
F2B_JAILS="$(fail2ban-client status 2>/dev/null | sed -n 's/.*Jail list:\s*//p' | tr -d '\r' || true)"
[[ -z "${F2B_JAILS:-}" ]] && F2B_JAILS="(unknown)"

EXT_IP="$(external_ip || true)"; [[ -z "$EXT_IP" ]] && EXT_IP="unknown"
IP_JSON="$(ip_identity "$EXT_IP" || true)"
CC="$(echo "$IP_JSON" | jq -r '.country // empty' 2>/dev/null || true)"
CITY="$(echo "$IP_JSON" | jq -r '.city // empty' 2>/dev/null || true)"
REGION="$(echo "$IP_JSON" | jq -r '.region // empty' 2>/dev/null || true)"
ORG="$(echo "$IP_JSON" | jq -r '.org // empty' 2>/dev/null || true)"
FLAG="$(flag_from_country "$CC" 2>/dev/null || true)"

TS_IP_NOW="$(tailscale ip -4 2>/dev/null || true)"
TS_DNS_NOW="$(tailscale_magicdns_full || true)"
[[ -z "${TS_DNS_NOW:-}" ]] && TS_DNS_NOW="(unavailable)"

TCP_CC="$(sysctl -n net.ipv4.tcp_congestion_control 2>/dev/null || echo '-')"
QDISC="$(sysctl -n net.core.default_qdisc 2>/dev/null || echo '-')"
FWD="$(sysctl -n net.ipv4.ip_forward 2>/dev/null || echo '-')"
CTMAX="$(sysctl -n net.netfilter.nf_conntrack_max 2>/dev/null || echo '-')"
NOFILE="$(systemctl show --property DefaultLimitNOFILE 2>/dev/null | cut -d= -f2 || echo '-')"

echo
echo "============================================================"
echo " ✅ Setup completed: $(ts_iso)"
echo "============================================================"

hdr "🔥 Ports"
echo "  Interface:           ${INTERNET_IFACE:-unknown}"
echo "  Open ports:          ${OPEN_PORTS[*]}"

hdr "🔥 Firewall (UFW)"
ufw status verbose 2>/dev/null || echo "UFW status unavailable"

hdr "🧩 Core services"
echo "  $(emoji_service docker) docker"
echo "  $(emoji_service tailscaled) tailscaled"
echo "  $(emoji_service fail2ban) fail2ban"
echo "  $(emoji_service ufw) ufw"
echo "  $(emoji_service node_exporter) node_exporter"
echo "  $(emoji_service iperf3) iperf3"

hdr "📦 Remnanode"
remna_status

hdr "🔒 Security"
echo "  SSH port:              ${SSH_PORT}"
echo "  PasswordAuthentication: ${SSH_PASS_AUTH}"
echo "  PermitRootLogin:        ${SSH_ROOT_LOGIN}"
echo "  Fail2ban jails:         ${F2B_JAILS}"

hdr "🧪 Tuning quick checks"
echo "  tcp cc:              ${TCP_CC}"
echo "  qdisc:               ${QDISC}"
echo "  forward:             ${FWD}"
echo "  ct max:              ${CTMAX}"
echo "  nofile:              ${NOFILE}"

hdr "📦 Logs"
echo "  APT:                 ${APT_LOG}"
echo "  Docker:              /var/log/install-docker.log"
echo "  Tailscale:           /var/log/install-tailscale.log"

hdr "🌐 Network identity"
if [[ "$EXT_IP" != "unknown" ]]; then
  echo "  External IP:         ${EXT_IP} ${FLAG}"
  if [[ -n "${CITY}${REGION}${CC}" ]]; then
    echo "  Location:            ${CITY}${CITY:+, }${REGION}${REGION:+, }${CC}"
  fi
  [[ -n "$ORG" ]] && echo "  Provider/ASN:        ${ORG}"
else
  echo "  External IP:         unknown"
fi

hdr "🛡️ Tailscale"
if command -v tailscale >/dev/null 2>&1; then
  echo "  IPv4:                ${TS_IP_NOW:-not assigned}"
  echo "  MagicDNS:            ${TS_DNS_NOW}"
else
  echo "  (tailscale not installed)"
fi

hdr "🧾 System summary"
sys_summary

hdr "▶️ Run again"
echo "  sudo bash initial.sh --user=${USER_NAME} --timezone=${TIMEZONE} --remnanode=${REMNANODE} --reboot=0 --tailscale=${RUN_TAILSCALE} --dns-switch=${RUN_DNS_SWITCH} --dns-profile=${DNS_PROFILE:-1}"

exit 0
