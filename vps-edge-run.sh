#!/usr/bin/env bash
set -Eeuo pipefail

###############################################################################
# VPS bootstrap
# Order:
#   Step 0: hostname
#   Step 1: tailscale install/auth (optional, EARLY)
#   Step 2: remnanode secret prompt (optional)
#   Then everything else
#
# Notes:
# - Tailscale uses: tailscale up --ssh --advertise-exit-node
# - Public SSH is denied via UFW when tailscale is enabled
# - SSH remains allowed on tailscale0
# - If reboot is disabled, UFW rules are staged but UFW is NOT enabled
# - Automatic reboot has been removed from the pipeline
###############################################################################

###############################################################################
# ARG PARSING
###############################################################################
USER_NAME=""
TIMEZONE="Europe/Moscow"
REBOOT_DELAY="0"   # deprecated, ignored
SSH_PORT="${SSH_PORT:-22}"
REMNANODE="0"
PORTS_MODE=""
OPEN_PORTS_RAW=""
RUN_TUNING="1"
RUN_DNS_SWITCH="1"

RUN_TAILSCALE="0"
DNS_PROFILE=""
DNS_CUSTOM=""
DNS_FALLBACK=""

NODE_PORT="2222"
SECRET_KEY=""

DEFAULT_OPEN_PORTS=(1080 1090 443 80 1480 1194)

usage() {
  cat <<'EOF'
Usage: sudo bash initial.sh [options]

Options:
  --user <name> | --user=<name>
  --timezone <IANA> | --timezone=<IANA>              (default: Europe/Moscow)
  --reboot <delay> | --reboot=<delay>                (deprecated, ignored)
  --remnanode 0|1 | --remnanode=0|1                  (default: 0)
  --ssh-port <port> | --ssh-port=<port>              (default: 22)
  --ports ask|skip | --ports=ask|skip                (default: ask if TTY, else skip)
  --open-ports "<list>" | --open-ports="<list>"      comma/space-separated ports
  --tuning 0|1 | --tuning=0|1                        (default: 1)
  --dns-switch 0|1 | --dns-switch=0|1                (default: 1)
  --dns-profile 1..5 | --dns-profile=1..5            (default: auto)
  --dns-custom "<servers>"
  --dns-fallback "<server>"
  --tailscale 0|1 | --tailscale=0|1                  (default: 0)
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
    --reboot)       REBOOT_DELAY="${2:-0}"; shift 2 ;;
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

  install -m 0644 /dev/stdin /etc/sysctl.d/99-fd.conf <<'EOF'
fs.file-max = 2097152
fs.nr_open = 2097152
EOF

  mkdir -p /etc/systemd/system.conf.d
  install -m 0644 /dev/stdin /etc/systemd/system.conf.d/99-limits.conf <<'EOF'
[Manager]
DefaultLimitNOFILE=1048576
DefaultTasksMax=infinity
EOF

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

ensure_tailscale_up() {
  if systemctl is-active --quiet tailscaled 2>/dev/null; then
    local ip4=""
    ip4="$(tailscale ip -4 2>/dev/null || true)"
    if [[ -n "$ip4" ]]; then
      ok "Tailscale already authorized and running"
      return 0
    fi
  fi

  log "Running tailscale up --ssh (waiting for authorization)"
  set +e
  tailscale up --ssh --advertise-exit-node | tee /tmp/tailscale-up.log
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

  if _has_tty; then
    local _=""
    read_tty _ "Press Enter after authorizing this device in Tailscale..."
  fi
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

  install -m 0644 /dev/stdin "${drop_dir}/99-initial-hardening.conf" <<EOF
# Managed by initial.sh
Port ${SSH_PORT}
PermitRootLogin no
PasswordAuthentication no
KbdInteractiveAuthentication no
ChallengeResponseAuthentication no
PubkeyAuthentication yes
EOF

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

  [[ -f "${user_home}/.zshrc" ]] && cp "${user_home}/.zshrc" "${root_home}/.zshrc" || true
  [[ -f "${user_home}/.p10k.zsh" ]] && cp "${user_home}/.p10k.zsh" "${root_home}/.p10k.zsh" || true
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
# START
###############################################################################
require_root
export DEBIAN_FRONTEND=noninteractive
export NEEDRESTART_MODE=a

log "Parameters: user='${USER_NAME:-<ask>}' timezone='${TIMEZONE}' reboot='${REBOOT_DELAY}' remnanode='${REMNANODE}' ssh_port='${SSH_PORT}' tuning='${RUN_TUNING}' dns-switch='${RUN_DNS_SWITCH}' dns-profile='${DNS_PROFILE:-<auto>}' tailscale='${RUN_TAILSCALE}'"

if [[ -z "${USER_NAME}" ]]; then
  if _has_tty; then
    read_tty USER_NAME "Enter username to create (e.g., akadorkin): "
  fi
  [[ -n "$USER_NAME" ]] || { err "Username is empty (provide --user)"; exit 1; }
fi
ok "User: $USER_NAME"
HOME_DIR="/home/${USER_NAME}"

###############################################################################
# Step 0: hostname
###############################################################################
log "Step 0: hostname"
CURRENT_HOST="$(hostname 2>/dev/null || true)"
NEW_HOST=""
if _has_tty; then
  read_tty NEW_HOST "Enter hostname (press Enter to keep '${CURRENT_HOST}'): "
fi
if [[ -n "${NEW_HOST:-}" ]]; then
  runq "hostnamectl set-hostname" hostnamectl set-hostname "${NEW_HOST}" || true
  ok "Hostname set to: ${NEW_HOST}"
else
  ok "Hostname unchanged: ${CURRENT_HOST}"
fi

###############################################################################
# Step 1: tailscale install
###############################################################################
if [[ "${RUN_TAILSCALE}" == "1" ]]; then
  log "Step 1: tailscale install"

  aptq "APT update" update
  aptq "Install base packages for tailscale step" install curl jq ca-certificates iproute2 ethtool

  INTERNET_IFACE="$(ip route show default 2>/dev/null | awk '/default/ {print $5; exit}' || true)"

  if ! command -v tailscale >/dev/null 2>&1; then
    runq "install tailscale" bash -lc 'curl -fsSL https://tailscale.com/install.sh | sh >>/var/log/install-tailscale.log 2>&1'
  else
    ok "Tailscale already installed — skipping install"
  fi

  install -m 0644 /dev/stdin /etc/sysctl.d/99-tailscale-forwarding.conf <<'EOF'
net.ipv4.ip_forward=1
net.ipv6.conf.all.forwarding=1
net.ipv4.conf.all.rp_filter=0
net.ipv4.conf.default.rp_filter=0
EOF
  runq "sysctl --system" sysctl --system || true

  if [[ -n "${INTERNET_IFACE:-}" ]]; then
    runq "ethtool gro on" ethtool -K "${INTERNET_IFACE}" gro on || true
    runq "ethtool rx-udp-gro-fwd on" ethtool -K "${INTERNET_IFACE}" rx-udp-gro-forwarding on || true
  fi

  ensure_tailscale_up

  TS_IP_EARLY="$(tailscale ip -4 2>/dev/null || true)"
  TS_DNS_EARLY="$(tailscale_magicdns_full || true)"

  section "🛡️ Tailscale authorized"
  echo "  Tailscale IPv4: ${TS_IP_EARLY:-not assigned}"
  echo "  Tailscale DNS:  ${TS_DNS_EARLY:-not assigned}"
else
  warn "Step 1: tailscale skipped (--tailscale=${RUN_TAILSCALE})"
fi

###############################################################################
# Step 2: remnanode parameters
###############################################################################
if [[ "${REMNANODE}" == "1" ]]; then
  log "Step 2: remnanode parameters"
  if _has_tty; then
    read_tty_silent SECRET_KEY "Paste SECRET_KEY (input hidden): "
  else
    warn "/dev/tty is not available — cannot prompt for remnanode parameters"
  fi

  if [[ -z "${SECRET_KEY:-}" ]]; then
    err "SECRET_KEY is empty — remnanode compose will not be created"
    REMNANODE="0"
  else
    ok "remnanode parameters received"
  fi
else
  warn "Step 2: remnanode parameters skipped (--remnanode=${REMNANODE})"
fi

###############################################################################
# Step 3: base packages and core setup
###############################################################################
log "Step 3: base packages and core setup"

aptq "APT update" update
aptq "APT upgrade" upgrade
aptq "Install base packages" install \
  zsh git curl wget ca-certificates gnupg lsb-release apt-transport-https \
  iproute2 ufw htop mc cron ed openssl logrotate jq iperf3 ethtool \
  dnsutils acl fail2ban

runq "enable cron" systemctl enable --now cron >/dev/null 2>&1 || true
grep -q '^/usr/bin/zsh$' /etc/shells || echo '/usr/bin/zsh' >> /etc/shells

apply_fd_limits

log "Configuring timezone -> ${TIMEZONE}"
runq "link /etc/localtime" ln -sf "/usr/share/zoneinfo/${TIMEZONE}" /etc/localtime || true
runq "timedatectl set-timezone" timedatectl set-timezone "${TIMEZONE}" || true
ok "Timezone configured"

pick_open_ports

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

install -m 0440 /dev/stdin "/etc/sudoers.d/${USER_NAME}" <<EOF
${USER_NAME} ALL=(ALL) NOPASSWD:ALL
EOF

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
  printf "%s:%s\n" "${USER_NAME}:${PASS_GEN}" > "${PASS_FILE}"
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
    setfacl -R -m "u:${USER_NAME}:rwX" /var/log/remnanode || true
    setfacl -R -d -m "u:${USER_NAME}:rwX" /var/log/remnanode || true

    install -m 0644 /dev/stdin "${REMNA_COMPOSE}" <<EOF
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
      - NODE_PORT=2222
      - SECRET_KEY=${SECRET_KEY}
    volumes:
      - '/var/log/remnanode:/var/log/remnanode'
EOF
    ok "Created remnanode compose: ${REMNA_COMPOSE}"
  else
    warn "remnanode compose is missing, but REMNANODE=0 — skipping generation"
  fi
fi

install -m 0644 /dev/stdin /etc/logrotate.d/remnanode <<'EOF'
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
ok "logrotate for /var/log/remnanode installed"

###############################################################################
# FAIL2BAN
###############################################################################
log "Configuring Fail2ban (sshd + sshd-fast + recidive, incremental bantime)"

touch /var/log/fail2ban.log
chmod 640 /var/log/fail2ban.log || true

install -m 0644 /dev/stdin /etc/fail2ban/fail2ban.local <<'EOF'
[Definition]
logtarget = /var/log/fail2ban.log
EOF

install -m 0644 /dev/stdin /etc/fail2ban/jail.d/00-defaults.local <<'EOF'
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

install -m 0644 /dev/stdin /etc/fail2ban/jail.d/sshd.local <<EOF
[sshd]
enabled = true
port    = ${SSH_PORT}
mode    = aggressive
EOF

install -m 0644 /dev/stdin /etc/fail2ban/jail.d/sshd-fast.local <<EOF
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

install -m 0644 /dev/stdin /etc/fail2ban/jail.d/recidive.local <<'EOF'
[recidive]
enabled  = true
logpath  = /var/log/fail2ban.log
findtime = 7d
maxretry = 3
bantime  = 4w
EOF

runq "enable fail2ban"  systemctl enable --now fail2ban
runq "restart fail2ban" systemctl restart fail2ban

###############################################################################
# RUGOV nftables blacklist (input-only) + cron + logrotate
###############################################################################
log "Installing rugov nftables input-only blacklist updater"

install -m 0755 /dev/stdin /usr/local/sbin/update-rugov-nftables <<'EOF'
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

install -m 0644 /dev/stdin /etc/cron.d/update-rugov-nftables <<'EOF'
0 2 * * * root /usr/local/sbin/update-rugov-nftables >> /var/log/update-rugov-nftables.log 2>&1
EOF

install -m 0644 /dev/stdin /etc/logrotate.d/update-rugov-nftables <<'EOF'
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
    ufw allow in on tailscale0  >/dev/null 2>&1 || true
    ufw allow out on tailscale0 >/dev/null 2>&1 || true
    ufw allow in on tailscale0 to any port "${SSH_PORT}" proto tcp >/dev/null 2>&1 || true
  fi

  if [[ "${RUN_TAILSCALE}" == "1" ]]; then
    ufw deny in on "${INTERNET_IFACE}" to any port "${SSH_PORT}" proto tcp >/dev/null 2>&1 || true
    ok "SSH is restricted to tailscale0 only"
  else
    warn "tailscale disabled — leaving public SSH open on ${SSH_PORT}/tcp"
    ufw allow in on "${INTERNET_IFACE}" to any port "${SSH_PORT}" proto tcp >/dev/null 2>&1 || true
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

  case "${REBOOT_DELAY}" in
    0|no|none|skip|"")
      warn "Reboot disabled — UFW rules staged, but firewall remains disabled to avoid lockout"
      ;;
    *)
      runq "ufw enable" ufw --force enable
      ;;
  esac
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
  useradd --no-create-home --shell /bin/false "$USER" || true

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
# AUTOREMOVE
###############################################################################
aptq "Autoremove" autoremove --purge
ok "Automatic reboot removed from pipeline"

###############################################################################
# FINAL REPORT
###############################################################################
emoji_service() {
  local unit="$1"
  if systemctl is-active --quiet "$unit" 2>/dev/null; then echo "✅"; else echo "❌"; fi
}

external_ip4() {
  curl -4 -fsSL ifconfig.me 2>/dev/null || curl -4 -fsSL https://api.ipify.org 2>/dev/null || true
}

ip_identity() {
  local ip="$1"
  [[ -n "$ip" ]] || { echo ""; return 0; }
  curl -fsSL "https://ipinfo.io/${ip}/json" 2>/dev/null || true
}

iface_ipv4() {
  local ifc="${1:-}"
  [[ -n "$ifc" ]] || { echo ""; return 0; }
  ip -4 -o addr show dev "$ifc" scope global 2>/dev/null | awk '{print $4}' | cut -d/ -f1 | head -n1 || true
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

  printf -v esc '\\U%08X\\U%08X' "$code1" "$code2"
  printf '%b' "$esc"
}

remna_status() {
  if ! command -v docker >/dev/null 2>&1; then
    echo "  Status:        ❌ docker missing"
    return 0
  fi

  if ! docker ps --format '{{.Names}}' | grep -qx 'remnanode'; then
    if docker ps -a --format '{{.Names}}' | grep -qx 'remnanode'; then
      echo "  Status:        ❌ stopped"
    else
      echo "  Status:        ⚠️ not found"
    fi
    return 0
  fi

  echo "  Status:        ✅ running"

  local started
  started="$(docker inspect -f '{{.State.StartedAt}}' remnanode 2>/dev/null || true)"
  if [[ -n "$started" ]]; then
    echo "  Started:       ${started}"
  fi
}

sys_summary() {
  local up cores ram_mib root_line
  up="$(uptime -p 2>/dev/null || uptime)"
  cores="$(nproc 2>/dev/null || echo "?")"
  ram_mib="$(awk '/MemTotal:/ {printf "%d", $2/1024}' /proc/meminfo 2>/dev/null || echo "?")"
  root_line="$(df -hP / 2>/dev/null | awk 'NR==2{print $2 " total, " $3 " used, " $4 " free (" $5 ")"}' || true)"

  echo "  Uptime:        ${up}"
  echo "  CPU cores:     ${cores}"
  echo "  RAM:           ${ram_mib} MiB"
  echo "  Root FS:       ${root_line:-?}"
}

SSH_PASS_AUTH="$(get_sshd_effective passwordauthentication)"
SSH_ROOT_LOGIN="$(get_sshd_effective permitrootlogin)"
[[ -z "${SSH_PASS_AUTH:-}" ]] && SSH_PASS_AUTH="unknown"
[[ -z "${SSH_ROOT_LOGIN:-}" ]] && SSH_ROOT_LOGIN="unknown"

F2B_JAILS="$(fail2ban-client status 2>/dev/null | sed -n 's/.*Jail list:\s*//p' | tr -d '\r' || true)"
[[ -z "${F2B_JAILS:-}" ]] && F2B_JAILS="(unknown)"

EXT_IP4="$(external_ip4 || true)"; [[ -z "$EXT_IP4" ]] && EXT_IP4="unknown"
IFACE_IP4="$(iface_ipv4 "${INTERNET_IFACE:-}" || true)"
IP_JSON="$(ip_identity "$EXT_IP4" || true)"
CC="$(echo "$IP_JSON" | jq -r '.country // empty' 2>/dev/null || true)"
CITY="$(echo "$IP_JSON" | jq -r '.city // empty' 2>/dev/null || true)"
REGION="$(echo "$IP_JSON" | jq -r '.region // empty' 2>/dev/null || true)"
ORG="$(echo "$IP_JSON" | jq -r '.org // empty' 2>/dev/null || true)"
FLAG="$(flag_from_country "$CC" 2>/dev/null || true)"

TS_IP_NOW="${TS_IP_EARLY:-$(tailscale ip -4 2>/dev/null || true)}"
TS_DNS_NOW="${TS_DNS_EARLY:-$(tailscale_magicdns_full || true)}"
[[ -z "${TS_DNS_NOW:-}" ]] && TS_DNS_NOW="(unavailable)"

TCP_CC="$(sysctl -n net.ipv4.tcp_congestion_control 2>/dev/null || echo '-')"
QDISC="$(sysctl -n net.core.default_qdisc 2>/dev/null || echo '-')"
FWD="$(sysctl -n net.ipv4.ip_forward 2>/dev/null || echo '-')"
CTMAX="$(sysctl -n net.netfilter.nf_conntrack_max 2>/dev/null || echo '-')"
NOFILE="$(systemctl show --property DefaultLimitNOFILE 2>/dev/null | cut -d= -f2 || echo '-')"

section "✅ Setup completed: $(date -Iseconds)"

echo "  Tailscale IPv4: ${TS_IP_NOW:-not assigned}"
echo "  Tailscale DNS:  ${TS_DNS_NOW}"
echo "  External IPv4:  ${EXT_IP4} ${FLAG}"
[[ -n "${CITY}${REGION}${CC}" ]] && echo "  Location:       ${CITY}${CITY:+, }${REGION}${REGION:+, }${CC}"
[[ -n "$ORG" ]] && echo "  Provider/ASN:   ${ORG}"
echo "  Open ports:     ${OPEN_PORTS[*]}"
echo "  SSH port:       ${SSH_PORT}"
if [[ "${RUN_TAILSCALE}" == "1" ]]; then
  echo "  SSH access:     tailscale0 only"
else
  echo "  SSH access:     public + local"
fi
echo "  PasswordAuth:   ${SSH_PASS_AUTH}"
echo "  RootLogin:      ${SSH_ROOT_LOGIN}"
echo "  Fail2ban jails: ${F2B_JAILS}"
echo "  tcp cc:         ${TCP_CC}"
echo "  qdisc:          ${QDISC}"
echo "  forward:        ${FWD}"
echo "  ct max:         ${CTMAX}"
echo "  nofile:         ${NOFILE}"

section "🧩 Services"
echo "  docker:         $(emoji_service docker)"
echo "  tailscaled:     $(emoji_service tailscaled)"
echo "  fail2ban:       $(emoji_service fail2ban)"
echo "  ufw:            $(emoji_service ufw)"
echo "  node_exporter:  $(emoji_service node_exporter)"

section "📦 Remnanode"
remna_status

section "📦 Logs"
echo "  APT:            ${APT_LOG}"
echo "  Docker:         /var/log/install-docker.log"
echo "  Tailscale:      /var/log/install-tailscale.log"
echo "  Remnanode:      /var/log/remnanode"
echo "  Rugov:          /var/log/update-rugov-nftables.log"
echo "  Fail2ban:       /var/log/fail2ban.log"

section "🧾 System"
sys_summary

ok "Automatic reboot removed from pipeline"

exit 0
