#!/usr/bin/env bash
set -euo pipefail

###############################################################################
# ARG PARSING
###############################################################################
USER_NAME=""
TIMEZONE="Europe/Moscow"
REBOOT_DELAY="5m"   # 30s | 5m | 300 | 0|no|none|skip - no reboot
SSH_PORT="${SSH_PORT:-22}"
REMNANODE="0"       # 0 - do not touch remnanode, 1 - ask params and create compose if missing

# remnanode params (asked early if REMNANODE=1)
NODE_PORT=""
SECRET_KEY=""

# Ports that must be open on the external interface
OPEN_PORTS=(1080 1090 443 80 1480 1194)

while [[ $# -gt 0 ]]; do
  case "$1" in
    --user=*)      USER_NAME="${1#*=}"; shift ;;
    --timezone=*)  TIMEZONE="${1#*=}"; shift ;;
    --reboot=*)    REBOOT_DELAY="${1#*=}"; shift ;;
    --remnanode=*) REMNANODE="${1#*=}"; shift ;;
    --user)      USER_NAME="${2:-}"; shift 2 ;;
    --timezone)  TIMEZONE="${2:-}"; shift 2 ;;
    --reboot)    REBOOT_DELAY="${2:-}"; shift 2 ;;
    --remnanode) REMNANODE="${2:-0}"; shift 2 ;;
    *) echo "Unknown arg: $1"; exit 1 ;;
  esac
done

###############################################################################
# OUTPUT HELPERS
###############################################################################
log()  { echo -e "\033[1;36m==>\033[0m $*"; }
ok()   { echo -e "\033[1;32m✔\033[0m $*"; }
warn() { echo -e "\033[1;33m!\033[0m $*"; }
err()  { echo -e "\033[1;31m✖\033[0m $*"; }

runq(){
  local msg="$1"; shift
  echo -n "   $msg ... "
  if "$@" >/dev/null 2>&1; then
    echo "ok"
  else
    echo "fail"
    return 1
  fi
}

require_root(){ [[ ${EUID:-$(id -u)} -eq 0 ]] || { err "Run as root (sudo required)"; exit 1; }; }

read_tty(){
  local __var="$1" __prompt="$2" __v=""
  read -rp "$__prompt" __v </dev/tty || true
  printf -v "$__var" '%s' "$__v"
}

read_tty_silent(){
  local __var="$1" __prompt="$2" __v=""
  read -rsp "$__prompt" __v </dev/tty || true
  echo >/dev/tty || true
  printf -v "$__var" '%s' "$__v"
}

###############################################################################
# SSHD HELPERS
###############################################################################
SSHD_CONFIG="/etc/ssh/sshd_config"
get_sshd_effective(){
  local key="$1"
  if [[ -f "$SSHD_CONFIG" ]]; then
    awk -v k="$key" '
      BEGIN{IGNORECASE=1; v=""}
      /^[[:space:]]*#/ {next}
      /^[[:space:]]*$/ {next}
      {
        if (tolower($1)==tolower(k) && NF>=2) { v=$2 }
      }
      END{
        if (v=="") print "(unset)";
        else print v
      }' "$SSHD_CONFIG"
  else
    echo "(no_config)"
  fi
}

restart_sshd(){
  systemctl restart ssh 2>/dev/null || systemctl restart sshd 2>/dev/null || true
}

###############################################################################
# START
###############################################################################
require_root
export DEBIAN_FRONTEND=noninteractive
export NEEDRESTART_MODE=a

log "Parameters: user='${USER_NAME:-<ask>}' timezone='${TIMEZONE}' reboot='${REBOOT_DELAY}' remnanode='${REMNANODE}'"

if [[ -z "${USER_NAME}" ]]; then
  read_tty USER_NAME "Enter username to create (e.g., akadorkin): "
  [[ -n "$USER_NAME" ]] || { err "Username is empty"; exit 1; }
fi
echo "User: $USER_NAME"

HOME_DIR="/home/${USER_NAME}"

###############################################################################
# STEP 0: HOSTNAME (always interactive)
###############################################################################
log "Step 0: hostname"
CURRENT_HOST="$(hostname 2>/dev/null || true)"
read_tty NEW_HOST "Enter hostname (press Enter to keep '${CURRENT_HOST}'): "
if [[ -n "${NEW_HOST}" ]]; then
  runq "hostnamectl set-hostname" hostnamectl set-hostname "${NEW_HOST}" || true
  ok "Hostname set to: ${NEW_HOST}"
else
  ok "Hostname unchanged: ${CURRENT_HOST}"
fi

###############################################################################
# REMNANODE: ASK EARLY
###############################################################################
if [[ "${REMNANODE}" == "1" ]]; then
  log "remnanode=1 -> requesting parameters"
  read_tty NODE_PORT "Enter NODE_PORT for remnanode (default: 2222): "
  [[ -n "${NODE_PORT}" ]] || NODE_PORT="2222"

  read_tty_silent SECRET_KEY "Paste SECRET_KEY (input hidden): "
  if [[ -z "${SECRET_KEY}" ]]; then
    err "SECRET_KEY is empty — remnanode compose will not be created"
    REMNANODE="0"
  else
    ok "remnanode parameters received"
  fi
fi

###############################################################################
# FD LIMITS (kernel + systemd defaults)
###############################################################################
apply_fd_limits() {
  log "FD limits (kernel + systemd defaults)"

  install -m 0644 /dev/stdin /etc/sysctl.d/99-fd.conf <<'EOF_FD'
# Max open files system-wide
fs.file-max = 2097152
# Per-process hard ceiling (must be >= systemd LimitNOFILE values)
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
    echo "Full log: $APT_LOG"; exit 1
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
# DOCKER (quiet via runq)
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
# ZSH/OMZ/P10K + USER CONFIG
###############################################################################
log "Configuring Zsh / oh-my-zsh / powerlevel10k for ${USER_NAME}"

if [[ ! -d "${HOME_DIR}/.oh-my-zsh" ]]; then
  runq "oh-my-zsh install (user)" su - "${USER_NAME}" -c \
    'RUNZSH=no KEEP_ZSHRC=yes CHSH=no sh -c "$(curl -fsSL https://raw.githubusercontent.com/ohmyzsh/ohmyzsh/master/tools/install.sh)"'
fi

ZSH_PATH="${HOME_DIR}/.oh-my-zsh"
ZSH_CUSTOM="${ZSH_PATH}/custom"
runq "mkdir zsh custom" su - "${USER_NAME}" -c "mkdir -p ${ZSH_CUSTOM}/plugins ${ZSH_CUSTOM}/themes"

if [[ ! -d "${ZSH_CUSTOM}/plugins/zsh-autosuggestions" ]]; then
  runq "plugin zsh-autosuggestions" su - "${USER_NAME}" -c \
    "git clone --depth=1 https://github.com/zsh-users/zsh-autosuggestions ${ZSH_CUSTOM}/plugins/zsh-autosuggestions"
fi
if [[ ! -d "${ZSH_CUSTOM}/plugins/zsh-completions" ]]; then
  runq "plugin zsh-completions" su - "${USER_NAME}" -c \
    "git clone --depth=1 https://github.com/zsh-users/zsh-completions ${ZSH_CUSTOM}/plugins/zsh-completions"
fi
if [[ ! -d "${ZSH_CUSTOM}/plugins/zsh-syntax-highlighting" ]]; then
  runq "plugin zsh-syntax-highlighting" su - "${USER_NAME}" -c \
    "git clone --depth=1 https://github.com/zsh-users/zsh-syntax-highlighting ${ZSH_CUSTOM}/plugins/zsh-syntax-highlighting"
fi
if [[ ! -d "${ZSH_CUSTOM}/themes/powerlevel10k" ]]; then
  runq "theme powerlevel10k" su - "${USER_NAME}" -c \
    "git clone --depth=1 https://github.com/romkatv/powerlevel10k.git ${ZSH_CUSTOM}/themes/powerlevel10k"
fi

if [[ ! -d "${HOME_DIR}/.fzf" ]]; then
  runq "fzf clone (user)" su - "${USER_NAME}" -c 'git clone --depth 1 https://github.com/junegunn/fzf.git ~/.fzf'
  runq "fzf install (user)" su - "${USER_NAME}" -c 'yes | ~/.fzf/install --key-bindings --completion --no-bash --no-fish --no-update-rc'
fi

runq "download .zshrc" curl -fsSL "https://kadorkin.io/zshrc" -o "${HOME_DIR}/.zshrc"
runq "download .p10k"  curl -fsSL "https://kadorkin.io/p10k"  -o "${HOME_DIR}/.p10k.zsh"
runq "chown zsh files" chown "${USER_NAME}:${USER_NAME}" "${HOME_DIR}/.zshrc" "${HOME_DIR}/.p10k.zsh"

if ! grep -q 'FZF_BASE=' "${HOME_DIR}/.zshrc"; then
  cat >> "${HOME_DIR}/.zshrc" <<'EOF_FZF'
# Linux fallback for oh-my-zsh fzf plugin
if command -v fzf >/dev/null 2>&1; then
  export FZF_BASE="${FZF_BASE:-$HOME/.fzf}"
fi
EOF_FZF
  runq "chown .zshrc" chown "${USER_NAME}:${USER_NAME}" "${HOME_DIR}/.zshrc"
fi
ok "Zsh stack for ${USER_NAME} is ready"

###############################################################################
# ZSH/OMZ/P10K FOR ROOT
###############################################################################
log "Configuring Zsh / oh-my-zsh / powerlevel10k for root"

ROOT_HOME="/root"
USER_OMZ="${HOME_DIR}/.oh-my-zsh"
if [[ -d "$USER_OMZ" && ! -d "${ROOT_HOME}/.oh-my-zsh" ]]; then
  log "Copying oh-my-zsh from ${USER_NAME} to root"
  cp -a "$USER_OMZ" "${ROOT_HOME}/.oh-my-zsh"
  chown -R root:root "${ROOT_HOME}/.oh-my-zsh"
fi

if [[ ! -d "${ROOT_HOME}/.oh-my-zsh" ]]; then
  log "Installing oh-my-zsh for root (from the Internet)"
  if RUNZSH=no KEEP_ZSHRC=yes CHSH=no \
       sh -c "$(curl -fsSL https://raw.githubusercontent.com/ohmyzsh/ohmyzsh/master/tools/install.sh)"; then
    ok "oh-my-zsh installed for root"
  else
    warn "oh-my-zsh install (root) failed — continuing without it"
  fi
else
  ok "oh-my-zsh for root already exists"
fi

ROOT_ZSH_PATH="${ROOT_HOME}/.oh-my-zsh"
ROOT_ZSH_CUSTOM="${ROOT_ZSH_PATH}/custom"
mkdir -p "${ROOT_ZSH_CUSTOM}/plugins" "${ROOT_ZSH_CUSTOM}/themes"

if [[ ! -d "${ROOT_HOME}/.fzf" ]]; then
  log "Installing fzf for root"
  runq "fzf clone (root)" git clone --depth 1 https://github.com/junegunn/fzf.git "${ROOT_HOME}/.fzf"
  runq "fzf install (root)" bash -lc 'yes | ~/.fzf/install --key-bindings --completion --no-bash --no-fish --no-update-rc'
else
  ok "fzf for root already exists"
fi

if [[ -f "${HOME_DIR}/.zshrc" ]]; then
  runq "copy .zshrc to root" cp "${HOME_DIR}/.zshrc" "${ROOT_HOME}/.zshrc"
  chown root:root "${ROOT_HOME}/.zshrc"
fi
if [[ -f "${HOME_DIR}/.p10k.zsh" ]]; then
  runq "copy .p10k.zsh to root" cp "${HOME_DIR}/.p10k.zsh" "${ROOT_HOME}/.p10k.zsh"
  chown root:root "${ROOT_HOME}/.p10k.zsh"
fi

chsh -s /usr/bin/zsh root || true

disable_omz_updates_in_zshrc() {
  local zrc="$1"
  [[ -f "$zrc" ]] || return 0
  grep -q 'DISABLE_AUTO_UPDATE'  "$zrc" 2>/dev/null || echo 'DISABLE_AUTO_UPDATE="true"' >> "$zrc"
  grep -q 'DISABLE_UPDATE_PROMPT' "$zrc" 2>/dev/null || echo 'DISABLE_UPDATE_PROMPT=true' >> "$zrc"
  grep -q ":omz:update"          "$zrc" 2>/dev/null || echo "zstyle ':omz:update' mode disabled" >> "$zrc"
}

disable_omz_updates_in_zshrc "${HOME_DIR}/.zshrc"
disable_omz_updates_in_zshrc "/root/.zshrc"

while IFS= read -r -d '' f; do
  disable_omz_updates_in_zshrc "$f" || true
done < <(find /home -maxdepth 3 -type f -name ".zshrc" -print0 2>/dev/null || true)

###############################################################################
# IPERF3 SERVER
###############################################################################
if command -v iperf3 >/dev/null 2>&1; then
  log "iperf3 service"
  install -m 0644 /dev/stdin /etc/systemd/system/iperf3.service <<'EOF_IPERF'
[Unit]
Description=iperf3 server
After=network.target

[Service]
ExecStart=/usr/bin/iperf3 -s
Restart=always
User=root

[Install]
WantedBy=multi-user.target
EOF_IPERF
  runq "daemon-reload" systemctl daemon-reload
  runq "enable iperf3" systemctl enable --now iperf3
fi

###############################################################################
# LOGROTATE (remnanode)
###############################################################################
log "logrotate for remnanode"
install -m 0644 /dev/stdin /etc/logrotate.d/remnanode <<'EOF_LR'
/var/log/remnanode/*.log {
    size 50M
    rotate 5
    compress
    missingok
    notifempty
    copytruncate
}
EOF_LR
runq "mkdir /var/log/remnanode" mkdir -p /var/log/remnanode
runq "chmod /var/log/remnanode" chmod 755 /var/log/remnanode
ok "logrotate configured"

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
# TAILSCALE (install + sysctl/ethtool prep + tailscale up)
###############################################################################
log "Tailscale setup (install + sysctl forwarding + UDP GRO)"

TAILSCALE_LOG="/var/log/install-tailscale.log"; :> "$TAILSCALE_LOG"
if ! command -v tailscale >/dev/null 2>&1; then
  runq "install tailscale" bash -lc 'curl -fsSL https://tailscale.com/install.sh | sh >>/var/log/install-tailscale.log 2>&1'
else
  ok "Tailscale already installed — skipping install"
fi

# Prepare system for Tailscale (kept as a dedicated file, and protected in tuning)
install -m 0644 /dev/stdin /etc/sysctl.d/99-tailscale-forwarding.conf <<'EOF_SYSCTL'
net.ipv4.ip_forward=1
net.ipv6.conf.all.forwarding=1
net.ipv4.conf.all.rp_filter=0
net.ipv4.conf.default.rp_filter=0
EOF_SYSCTL
runq "sysctl --system" sysctl --system || true

INTERNET_IFACE="$(ip route show default | awk '/default/ {print $5; exit}')"
if [[ -n "${INTERNET_IFACE:-}" ]]; then
  runq "ethtool gro on"              ethtool -K "${INTERNET_IFACE}" gro on || true
  runq "ethtool rx-udp-gro-fwd on"   ethtool -K "${INTERNET_IFACE}" rx-udp-gro-forwarding on || true
fi

# Optional SSH hardening
log "SSH hardening (PasswordAuthentication no + PermitRootLogin no)"
read_tty SSH_HARDEN "Apply SSH hardening now? [y/N]: "
case "${SSH_HARDEN,,}" in
  y|yes)
    if [[ -f "$SSHD_CONFIG" ]]; then
      sed -i 's/^[[:space:]]*#\?[[:space:]]*PasswordAuthentication[[:space:]].*/PasswordAuthentication no/' "$SSHD_CONFIG" || true
      sed -i 's/^[[:space:]]*#\?[[:space:]]*PermitRootLogin[[:space:]].*/PermitRootLogin no/' "$SSHD_CONFIG" || true

      grep -qi '^[[:space:]]*PasswordAuthentication[[:space:]]' "$SSHD_CONFIG" || echo 'PasswordAuthentication no' >> "$SSHD_CONFIG"
      grep -qi '^[[:space:]]*PermitRootLogin[[:space:]]' "$SSHD_CONFIG" || echo 'PermitRootLogin no' >> "$SSHD_CONFIG"

      runq "restart sshd" bash -lc 'systemctl restart ssh 2>/dev/null || systemctl restart sshd 2>/dev/null || true'
      ok "SSH hardening applied"
    else
      warn "sshd_config not found — skipping hardening"
    fi
    ;;
  *)
    warn "SSH hardening skipped"
    ;;
esac

###############################################################################
# FAIL2BAN (aggressive: sshd + sshd-ddos + recidive, exponential bantime)
###############################################################################
log "Installing and configuring Fail2ban (aggressive: sshd + sshd-ddos + recidive, exponential bantime)"
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

install -m 0644 /dev/stdin /etc/fail2ban/jail.d/sshd-ddos.local <<EOF_SSHD_DDOS
[sshd-ddos]
enabled  = true
port     = ${SSH_PORT}
mode     = aggressive
findtime = 2m
maxretry = 2
bantime  = 12h
EOF_SSHD_DDOS

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

fail2ban-client ping >/dev/null 2>&1 && ok "fail2ban is responding" || warn "fail2ban-client ping failed"
fail2ban-client status sshd 2>/dev/null || true
fail2ban-client status sshd-ddos 2>/dev/null || true
fail2ban-client status recidive 2>/dev/null || true

# tailscale up — capture URL only
log "Running tailscale up (waiting for authorization)"
set +e
tailscale up --advertise-exit-node --ssh | tee /tmp/tailscale-up.log
set -e

TAILSCALE_URL="$(grep -Eo 'https://login\.tailscale\.com/[a-zA-Z0-9/_-]+' /tmp/tailscale-up.log | head -n1 || true)"
if [[ -n "$TAILSCALE_URL" ]]; then
  echo "Open to authorize: $TAILSCALE_URL"
else
  echo "Authorization URL not found. If tailscale is already authorized — this is OK."
  echo "Otherwise run manually:"
  echo "  tailscale up --advertise-exit-node --ssh"
fi
read_tty _ "Press Enter after authorizing this device in Tailscale..."
TS_IP="$(tailscale ip -4 2>/dev/null || true)"
echo "Tailscale IPv4: ${TS_IP:-not assigned}"

###############################################################################
# UFW (base policy + docker + tailscale0). NO CRON. NO BLOCKLIST.
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
  log "UFW DEFAULT_FORWARD_POLICY=ACCEPT"
fi

INTERNET_IFACE="$(ip route get 8.8.8.8 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="dev") print $(i+1)}' | head -n1 || true)"
[[ -n "$INTERNET_IFACE" ]] || INTERNET_IFACE="$(ip route | awk '/default/ {for(i=1;i<=NF;i++) if($i=="dev") print $(i+1)}' | head -n1 || true)"

if [[ -z "${INTERNET_IFACE}" ]]; then
  err "Failed to detect INTERNET_IFACE — aborting UFW configuration."
else
  ok "External interface: ${INTERNET_IFACE}"

  runq "ufw reset"             ufw --force reset
  runq "ufw default deny in"   ufw default deny incoming
  runq "ufw default allow out" ufw default allow outgoing

  for port in "${OPEN_PORTS[@]}"; do
    log "Opening port ${port} on ${INTERNET_IFACE} (tcp/udp)"
    ufw allow in on "${INTERNET_IFACE}" to any port "${port}" proto tcp
    ufw allow in on "${INTERNET_IFACE}" to any port "${port}" proto udp
  done

  runq "ufw allow in on tailscale0"  ufw allow in on tailscale0
  runq "ufw allow out on tailscale0" ufw allow out on tailscale0

  DOCKER_IFACES="$(ip -o link show | awk -F': ' '$2 ~ /^(docker0|br-)/ {print $2}' || true)"
  if [[ -n "${DOCKER_IFACES}" ]]; then
    for IFACE in ${DOCKER_IFACES}; do
      log "Allowing all traffic on Docker interface ${IFACE}"
      ufw allow in on "${IFACE}"
      ufw allow out on "${IFACE}"
    done
  else
    warn "No Docker interfaces (docker0/br-*) found — skipping Docker-specific rules"
  fi

  runq "ufw enable" ufw --force enable
  ufw status verbose || true
fi

###############################################################################
# NODE EXPORTER (embedded)
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
  local NODE_EXPORTER_PORT=9100

  step() { echo -e "\n[$1/10] $2"; }

  echo -e "\nStarting Node Exporter ${VERSION} install..."

  step 1 "Skipping system package update (embedded mode)"
  step 2 "Downloading Node Exporter archive"
  wget -q -O "/root/${ARCHIVE}" "$DOWNLOAD_URL"

  step 3 "Extracting archive"
  tar -xzf "/root/${ARCHIVE}" -C /root

  step 4 "Installing binary to ${BIN_DIR}"
  mv "/root/${EXTRACT_DIR}/node_exporter" "${BIN_DIR}/node_exporter"
  chmod +x "${BIN_DIR}/node_exporter"

  step 5 "Creating system user: ${USER}"
  useradd --no-create-home --shell /bin/false "$USER" || true

  step 6 "Creating systemd service file"
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

  step 7 "Enabling and starting systemd service"
  systemctl daemon-reload
  systemctl enable node_exporter
  systemctl start node_exporter

  step 8 "Cleaning up"
  rm -rf "/root/${ARCHIVE}" "/root/${EXTRACT_DIR}"

  step 9 "Verifying service status"
  systemctl status node_exporter --no-pager || true

  step 10 "Firewall note"
  if command -v ufw >/dev/null 2>&1; then
    ufw status || true
    if ufw status | grep -q "Status: active"; then
      echo "UFW is active. If you want remote scraping, allow ${NODE_EXPORTER_PORT}/tcp explicitly."
    fi
  fi

  echo
  echo "Node Exporter installed."
  echo "Check: systemctl status node_exporter --no-pager"
  echo "Binary: ${BIN_DIR}/node_exporter"
  echo "Service: ${SERVICE_FILE}"
  echo "Port: ${NODE_EXPORTER_PORT}"
  echo
}

node_exporter_install

###############################################################################
# KERNEL / NETWORK TUNING (embedded apply)
###############################################################################
log "Kernel/network tuning (embedded) — apply"

edge_tuning_apply() {
  set -Eeuo pipefail

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
  ok2()   { _pfx; color "$c_grn" "OK";    printf " %s\n" "$*"; }
  warn2() { _pfx; color "$c_yel" "WARN";  printf " %s\n" "$*"; }
  err2()  { _pfx; color "$c_red" "ERROR"; printf " %s\n" "$*"; }
  die2()  { err2 "$*"; exit 1; }
  hdr2()  { echo; color "$c_bold$c_cyan" "$*"; echo; }

  host_short() { hostname -s 2>/dev/null || hostname; }

  need_root2() {
    if [[ "${EUID:-$(id -u)}" -eq 0 ]]; then return 0; fi
    die2 "Not root. Run with sudo/root."
  }

  backup_dir=""
  moved_dir=""
  manifest=""

  mkbackup2() {
    local tsd="${BACKUP_TS:-${EDGE_BACKUP_TS:-}}"
    [[ -n "$tsd" ]] || tsd="$(date +%Y%m%d-%H%M%S)"
    backup_dir="/root/edge-tuning-backup-${tsd}"
    moved_dir="${backup_dir}/moved"
    manifest="${backup_dir}/MANIFEST.tsv"
    mkdir -p "$backup_dir" "$moved_dir"
    : > "$manifest"
  }

  backup_file2() {
    local src="$1"
    [[ -f "$src" ]] || return 0
    local rel="${src#/}"
    local dst="${backup_dir}/files/${rel}"
    mkdir -p "$(dirname "$dst")"
    cp -a "$src" "$dst"
    printf "COPY\t%s\t%s\n" "$src" "$dst" >> "$manifest"
  }

  move_aside2() {
    local src="$1"
    [[ -f "$src" ]] || return 0
    local rel="${src#/}"
    local dst="${moved_dir}/${rel}"
    mkdir -p "$(dirname "$dst")"
    mv -f "$src" "$dst"
    printf "MOVE\t%s\t%s\n" "$src" "$dst" >> "$manifest"
  }

  to_int() { local s="${1:-}"; if [[ "$s" =~ ^[0-9]+$ ]]; then echo "$s"; else echo 0; fi; }
  imax() { local a b; a="$(to_int "${1:-0}")"; b="$(to_int "${2:-0}")"; [[ "$a" -ge "$b" ]] && echo "$a" || echo "$b"; }
  clamp() { local v lo hi; v="$(to_int "${1:-0}")"; lo="$(to_int "${2:-0}")"; hi="$(to_int "${3:-0}")"; [[ "$v" -lt "$lo" ]] && v="$lo"; [[ "$v" -gt "$hi" ]] && v="$hi"; echo "$v"; }

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

  row_kv() { local k="$1" v="$2"; printf "%-12s | %s\n" "$k" "$v"; }

  print_before_after_all() {
    hdr2 "Before -> After (all)"
    printf "%-12s-+-%-24s-+-%-24s\n" "$(printf '%.0s-' {1..12})" "$(printf '%.0s-' {1..24})" "$(printf '%.0s-' {1..24})"

    row3() {
      local k="$1" b="$2" a="$3"
      if [[ "$b" != "$a" ]]; then
        printf "%-12s | %-24s | %-24s\n" "$k" "$(color "$c_grn" "$b")" "$(color "$c_grn" "$a")"
      else
        printf "%-12s | %-24s | %-24s\n" "$k" "$b" "$a"
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
    row3 "Auto reboot" "$(_unattended_state "$B_UNATT")" "$(_unattended_state "$A_UNATT")"
    row3 "Reboot time" "$(_unattended_time "$B_UNATT")"  "$(_unattended_time "$A_UNATT")"
  }

  on_apply_fail() {
    local code=$?
    err2 "Apply failed (exit code=$code)."
    warn2 "Rollback hint: see backup manifest under /root/edge-tuning-backup-*"
    exit "$code"
  }

  apply_cmd() {
    need_root2
    trap on_apply_fail ERR

    mkbackup2
    snapshot_before

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

    # ---- swap sizing ----
    backup_file2 /etc/fstab
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

    # ---- sysctl ----
    backup_file2 /etc/sysctl.conf
    shopt -s nullglob
    for f in /etc/sysctl.d/*.conf; do
      [[ -f "$f" ]] || continue
      case "$f" in
        /etc/sysctl.d/90-edge-network.conf|/etc/sysctl.d/92-edge-safe.conf|/etc/sysctl.d/95-edge-forward.conf|/etc/sysctl.d/96-edge-vm.conf|/etc/sysctl.d/99-edge-conntrack.conf) continue ;;
        /etc/sysctl.d/99-tailscale-forwarding.conf) continue ;; # keep tailscale file untouched
      esac
      if grep -Eq 'nf_conntrack_|tcp_congestion_control|default_qdisc|ip_forward|somaxconn|netdev_max_backlog|tcp_rmem|tcp_wmem|rmem_max|wmem_max|vm\.swappiness|vfs_cache_pressure|tcp_syncookies|tcp_max_tw_buckets|tcp_keepalive|tcp_mtu_probing|tcp_fin_timeout|tcp_tw_reuse|tcp_slow_start_after_idle|tcp_rfc1337' "$f"; then
        move_aside2 "$f"
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
    backup_file2 /etc/modules-load.d/edge-conntrack.conf
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
      grep -qE '^\s*DefaultLimitNOFILE\s*=' "$f" && move_aside2 "$f"
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
      grep -qE '^\s*[*a-zA-Z0-9._-]+\s+(soft|hard)\s+nofile\s+' "$f" && move_aside2 "$f"
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
      move_aside2 "$f"
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
    backup_file2 /etc/apt/apt.conf.d/99-edge-unattended.conf
    cat > /etc/apt/apt.conf.d/99-edge-unattended.conf <<'EOM'
Unattended-Upgrade::Automatic-Reboot "false";
Unattended-Upgrade::Automatic-Reboot-Time "04:00";
EOM

    # ---- logrotate ----
    backup_file2 /etc/logrotate.conf
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
    backup_file2 /etc/logrotate.d/edge-all-text-logs
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
    backup_file2 /etc/tmpfiles.d/edge-tmp.conf
    cat > /etc/tmpfiles.d/edge-tmp.conf <<'EOM'
D /tmp            1777 root root 7d
D /var/tmp        1777 root root 14d
EOM
    systemd-tmpfiles --create >/dev/null 2>&1 || true

    snapshot_after
    ok2 "Applied. Backup: $backup_dir"
    hdr2 "Run"
    row_kv "Host"   "$(color "$c_bold" "$(host_short)")"
    row_kv "Mode"   "$(color "$c_bold" "apply")"
    row_kv "Backup" "$(color "$c_bold" "$backup_dir")"
    print_before_after_all
    echo "BACKUP_DIR=$backup_dir"
  }

  apply_cmd
}

edge_tuning_apply

###############################################################################
# DNS SWITCHER (embedded, interactive)
###############################################################################
log "DNS switcher (embedded) — interactive"

dns_switcher_run() {
  set -euo pipefail

  local DEFAULT_DNS="8.8.8.8 8.8.4.4 1.1.1.1 1.0.0.1"
  local DEFAULT_FALLBACK="9.9.9.9"
  local BACKUP_DIR="/etc/dns-switcher-backup"

  print_header() {
    echo ""
    echo "========================================"
    echo "         DNS Switcher for Linux"
    echo "========================================"
    echo ""
  }

  check_compatibility() {
    if ! command -v systemctl >/dev/null 2>&1; then
      echo "systemd not found. This DNS switcher requires systemd-resolved."
      return 1
    fi

    if ! systemctl is-active --quiet systemd-resolved; then
      echo "systemd-resolved is not running. Starting it..."
      systemctl start systemd-resolved
      systemctl enable systemd-resolved
    fi
    return 0
  }

  show_current_dns() {
    echo "Current DNS configuration:"
    echo ""
    resolvectl status | grep -E "DNS Servers|DNS Domain|Fallback DNS" || true
    echo ""
  }

  get_dns_servers() {
    echo "Choose DNS servers:"
    echo ""
    echo "1) Google + Cloudflare (default)"
    echo "   Primary: 8.8.8.8, 8.8.4.4, 1.1.1.1, 1.0.0.1"
    echo "   Fallback: 9.9.9.9 (Quad9)"
    echo ""
    echo "2) Google only"
    echo "   Primary: 8.8.8.8, 8.8.4.4"
    echo "   Fallback: 9.9.9.9"
    echo ""
    echo "3) Cloudflare only"
    echo "   Primary: 1.1.1.1, 1.0.0.1"
    echo "   Fallback: 9.9.9.9"
    echo ""
    echo "4) Quad9"
    echo "   Primary: 9.9.9.9, 149.112.112.112"
    echo "   Fallback: 1.1.1.1"
    echo ""
    echo "5) Custom"
    echo ""

    local choice=""
    read_tty choice "Enter choice (1-5) [default: 1]: "

    case "$choice" in
      2) DNS_SERVERS="8.8.8.8 8.8.4.4"; FALLBACK_DNS="9.9.9.9" ;;
      3) DNS_SERVERS="1.1.1.1 1.0.0.1"; FALLBACK_DNS="9.9.9.9" ;;
      4) DNS_SERVERS="9.9.9.9 149.112.112.112"; FALLBACK_DNS="1.1.1.1" ;;
      5)
        read_tty DNS_SERVERS "Enter primary DNS servers (space-separated): "
        read_tty FALLBACK_DNS "Enter fallback DNS server [default: 9.9.9.9]: "
        [[ -n "${DNS_SERVERS}" ]] || { echo "Primary DNS servers cannot be empty"; return 1; }
        [[ -n "${FALLBACK_DNS}" ]] || FALLBACK_DNS="9.9.9.9"
        ;;
      1|"")
        DNS_SERVERS="$DEFAULT_DNS"
        FALLBACK_DNS="$DEFAULT_FALLBACK"
        ;;
      *)
        echo "Invalid choice. Using default."
        DNS_SERVERS="$DEFAULT_DNS"
        FALLBACK_DNS="$DEFAULT_FALLBACK"
        ;;
    esac
    echo ""
    return 0
  }

  create_backup() {
    echo "Creating backup..."
    mkdir -p "$BACKUP_DIR"
    if [[ -f /etc/systemd/resolved.conf ]]; then
      cp /etc/systemd/resolved.conf "$BACKUP_DIR/resolved.conf.backup.$(date +%Y%m%d_%H%M%S)"
      echo "Backed up /etc/systemd/resolved.conf"
    fi
    resolvectl status > "$BACKUP_DIR/dns_status.backup.$(date +%Y%m%d_%H%M%S)" 2>&1 || true
    echo ""
  }

  configure_dns() {
    echo "Configuring DNS servers..."

    cat > /etc/systemd/resolved.conf <<EOF
# Managed by DNS Switcher
# Original configuration backed up to ${BACKUP_DIR}

[Resolve]
DNS=${DNS_SERVERS}
FallbackDNS=${FALLBACK_DNS}
Domains=~.
DNSSEC=no
DNSOverTLS=no
Cache=yes
EOF

    echo "Updated /etc/systemd/resolved.conf"
    echo "Restarting systemd-resolved..."
    systemctl restart systemd-resolved
    sleep 2
    echo "systemd-resolved restarted"
    echo ""
  }

  restart_pbr() {
    if [[ -f /opt/setup-pbr.sh ]]; then
      echo "Restarting policy-based routing..."
      /opt/setup-pbr.sh
      echo "Policy-based routing restarted"
      echo ""
    fi
  }

  verify_dns() {
    echo "Verifying DNS configuration..."
    echo ""
    resolvectl status | grep -E "DNS Servers|DNS Domain|Fallback DNS" || true
    echo ""
    echo "DNS configuration applied."
    echo ""
  }

  test_dns() {
    echo "Testing DNS resolution..."
    if nslookup google.com >/dev/null 2>&1; then
      echo "DNS resolution looks OK"
    else
      echo "DNS test inconclusive"
    fi
    echo ""
  }

  show_tips() {
    echo "Tips:"
    echo "  Monitor DNS queries: sudo tcpdump -i any port 53 -n -Q out"
    echo "  Verify after reboot: sudo resolvectl status | grep -E \"DNS Servers|DNS Domain\""
    echo ""
  }

  print_header
  if ! check_compatibility; then
    warn "DNS switcher skipped (systemd-resolved not available)"
    return 0
  fi

  show_current_dns
  local DNS_SERVERS="" FALLBACK_DNS=""
  get_dns_servers || return 1

  create_backup
  configure_dns
  restart_pbr
  verify_dns
  test_dns
  show_tips

  echo "DNS switch completed. Backups saved to: ${BACKUP_DIR}"
  echo ""
}

dns_switcher_run

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
get_journald_caps_now() {
  local f="/etc/systemd/journald.conf.d/90-edge.conf"
  if [[ -f "$f" ]]; then
    local s r
    s="$(awk -F= '/^\s*SystemMaxUse=/{print $2}' "$f" | tr -d ' ' | head -n1)"
    r="$(awk -F= '/^\s*RuntimeMaxUse=/{print $2}' "$f" | tr -d ' ' | head -n1)"
    echo "${s:-?}/${r:-?}"
  else
    echo "-"
  fi
}

get_unattended_now() {
  local reboot time
  reboot="$(grep -Rhs 'Unattended-Upgrade::Automatic-Reboot' /etc/apt/apt.conf.d/*.conf 2>/dev/null \
    | sed -nE 's/.*Automatic-Reboot\s+"([^"]+)".*/\1/p' | tail -n1 || true)"
  time="$(grep -Rhs 'Unattended-Upgrade::Automatic-Reboot-Time' /etc/apt/apt.conf.d/*.conf 2>/dev/null \
    | sed -nE 's/.*Automatic-Reboot-Time\s+"([^"]+)".*/\1/p' | tail -n1 || true)"
  [[ -z "${reboot:-}" ]] && reboot="-"
  [[ -z "${time:-}" ]] && time="-"
  echo "${reboot} / ${time}"
}

get_swap_now() {
  local s
  s="$(/sbin/swapon --noheadings --show=NAME,SIZE 2>/dev/null | awk '{$1=$1; print}' | tr '\n' ';' | sed 's/;$//' || true)"
  [[ -n "$s" ]] && echo "$s" || echo "none"
}

get_dns_now() {
  resolvectl status 2>/dev/null | awk '
    /DNS Servers:/ {p=1; print; next}
    /Fallback DNS:/ {p=0; print; next}
    p && /^[[:space:]]+[0-9]/ {print}
  ' | sed 's/[[:space:]]\+$//'
}

tailscale_magicdns_full() {
  if command -v tailscale >/dev/null 2>&1 && command -v jq >/dev/null 2>&1; then
    tailscale status --json 2>/dev/null | jq -r '.Self.DNSName // empty' | head -n1
  else
    echo ""
  fi
}

list_changed_files() {
  cat <<'EOF_FILES'
/etc/systemd/resolved.conf                      (dns switcher)
/etc/dns-switcher-backup/*                      (dns backups)
/etc/sysctl.d/90-edge-network.conf              (tuning)
/etc/sysctl.d/92-edge-safe.conf                 (tuning)
/etc/sysctl.d/95-edge-forward.conf              (tuning)
/etc/sysctl.d/96-edge-vm.conf                   (tuning)
/etc/sysctl.d/99-edge-conntrack.conf            (tuning)
/etc/modules-load.d/edge-conntrack.conf         (tuning)
/etc/systemd/system.conf.d/90-edge.conf         (tuning)
/etc/security/limits.d/90-edge.conf             (tuning)
/etc/systemd/journald.conf.d/90-edge.conf       (tuning)
/etc/apt/apt.conf.d/99-edge-unattended.conf     (tuning)
/etc/logrotate.conf                             (tuning)
/etc/logrotate.d/edge-all-text-logs             (tuning)
/etc/tmpfiles.d/edge-tmp.conf                   (tuning)
/etc/sysctl.d/99-tailscale-forwarding.conf      (tailscale forwarding)
/etc/systemd/system/node_exporter.service       (node_exporter)
/usr/local/bin/node_exporter                    (node_exporter)
/etc/logrotate.d/remnanode                      (remnanode logs)
/etc/fail2ban/*                                 (fail2ban hardening)
/var/log/fail2ban.log                           (fail2ban log)
EOF_FILES
}

EXT_IP="$(curl -fsSL ifconfig.me 2>/dev/null || curl -fsSL https://api.ipify.org 2>/dev/null || true)"
[[ -z "$EXT_IP" ]] && EXT_IP="unknown"

SSH_PASS_AUTH="$(get_sshd_effective PasswordAuthentication)"
SSH_ROOT_LOGIN="$(get_sshd_effective PermitRootLogin)"

TS_IP_NOW="$(tailscale ip -4 2>/dev/null || true)"
TS_DNS_NOW="$(tailscale_magicdns_full || true)"
[[ -z "${TS_DNS_NOW:-}" ]] && TS_DNS_NOW="(unavailable; run: tailscale status --json | jq -r .Self.DNSName)"

echo
echo "Setup completed."
echo
echo "Autoremove: done (see ${APT_LOG})"
echo
echo "Logs:"
echo "  - APT:       ${APT_LOG}"
echo "  - Docker:    /var/log/install-docker.log"
echo "  - Tailscale: /var/log/install-tailscale.log"
echo
echo "UFW:"
echo "  - Incoming: deny (except ports: ${OPEN_PORTS[*]} on ${INTERNET_IFACE:-unknown})"
echo "  - Outgoing: allow"
echo "  - tailscale0: allow in/out"
echo "  - Docker interfaces (docker0/br-*): allow in/out (if found)"
echo
echo "SSH:"
echo "  - SSH port variable: ${SSH_PORT}"
echo "  - PasswordAuthentication: ${SSH_PASS_AUTH}"
echo "  - PermitRootLogin:       ${SSH_ROOT_LOGIN}"
echo
echo "Fail2ban:"
echo "  - status: $(systemctl is-active fail2ban 2>/dev/null || echo 'unknown')"
echo "  - jails:  $(fail2ban-client status 2>/dev/null | sed -n 's/.*Jail list:\s*//p' | tr -d '\r' || true)"
echo
echo "External IP: ${EXT_IP}"
echo "Tailscale IPv4: ${TS_IP_NOW:-not assigned}"
echo "Tailscale MagicDNS: ${TS_DNS_NOW}"
if [[ -n "${PASS_GEN:-}" ]]; then
  echo "Generated password for ${USER_NAME}: ${PASS_GEN}"
else
  echo "Generated password for ${USER_NAME}: (unchanged)"
fi

echo
echo "====================== WHAT CHANGED (SUMMARY) ======================"
echo "Hostname:"
echo "  - current: $(hostname -f 2>/dev/null || hostname)"
echo
echo "DNS (systemd-resolved):"
if systemctl is-active --quiet systemd-resolved 2>/dev/null; then
  get_dns_now | sed 's/^/  - /'
else
  echo "  - systemd-resolved: not active"
fi
echo
echo "Kernel/sysctl highlights:"
echo "  - tcp_congestion_control: $(sysctl -n net.ipv4.tcp_congestion_control 2>/dev/null || echo '-')"
echo "  - default_qdisc:          $(sysctl -n net.core.default_qdisc 2>/dev/null || echo '-')"
echo "  - ip_forward (v4):        $(sysctl -n net.ipv4.ip_forward 2>/dev/null || echo '-')"
echo "  - ip_forward (v6):        $(sysctl -n net.ipv6.conf.all.forwarding 2>/dev/null || echo '-')"
echo "  - nf_conntrack_max:       $(sysctl -n net.netfilter.nf_conntrack_max 2>/dev/null || echo '-')"
echo "  - tcp_max_tw_buckets:     $(sysctl -n net.ipv4.tcp_max_tw_buckets 2>/dev/null || echo '-')"
echo "  - swappiness:             $(sysctl -n vm.swappiness 2>/dev/null || echo '-')"
echo
echo "Swap:"
echo "  - $(get_swap_now)"
echo
echo "Limits/logging:"
echo "  - systemd DefaultLimitNOFILE: $(systemctl show --property DefaultLimitNOFILE 2>/dev/null | cut -d= -f2 || echo '-')"
echo "  - journald caps (System/Runtime): $(get_journald_caps_now)"
echo "  - unattended reboot: $(get_unattended_now)"
echo
echo "Services:"
echo "  - tailscaled:    $(systemctl is-active tailscaled 2>/dev/null || echo 'unknown')"
echo "  - node_exporter: $(systemctl is-active node_exporter 2>/dev/null || echo 'unknown')"
echo "  - docker:        $(systemctl is-active docker 2>/dev/null || echo 'unknown')"
echo "  - fail2ban:      $(systemctl is-active fail2ban 2>/dev/null || echo 'unknown')"
echo
echo "Key files created/overwritten by this script:"
list_changed_files | sed 's/^/  - /'
echo "===================================================================="
echo
echo "Run again:"
echo "  sudo bash initial.sh --user=${USER_NAME} --timezone=${TIMEZONE} --remnanode=${REMNANODE} --reboot=0"
echo
