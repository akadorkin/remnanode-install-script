#!/usr/bin/env bash
set -euo pipefail

# ---------------------- ПАРСИНГ АРГОВ ----------------------
USER_NAME=""
TIMEZONE="Europe/Moscow"
REBOOT_DELAY="5m"   # 30s | 5m | 300 | 0|none|skip - без ребута
SSH_PORT="${SSH_PORT:-22}"
REMNANODE="0"       # 0 - не трогаем remnanode, 1 - спросить параметры и создать compose, если его нет
DNS_SWITCH="0"      # 0/1 — запуск dns-switcher после node-exporter

# remnanode params (asked early if REMNANODE=1)
NODE_PORT=""
SECRET_KEY=""

# hostname (asked interactively, no flags)
HOST_NAME=""

# Порты, которые должны быть открыты на внешнем интерфейсе
OPEN_PORTS=(1080 1090 443 80 1480 1194)

while [[ $# -gt 0 ]]; do
  case "$1" in
    --user=*) USER_NAME="${1#*=}"; shift ;;
    --timezone=*) TIMEZONE="${1#*=}"; shift ;;
    --reboot=*) REBOOT_DELAY="${1#*=}"; shift ;;
    --remnanode=*) REMNANODE="${1#*=}"; shift ;;
    --dns-switch=*) DNS_SWITCH="${1#*=}"; shift ;;

    --user) USER_NAME="${2:-}"; shift 2 ;;
    --timezone) TIMEZONE="${2:-}"; shift 2 ;;
    --reboot) REBOOT_DELAY="${2:-}"; shift 2 ;;
    --remnanode) REMNANODE="${2:-0}"; shift 2 ;;
    --dns-switch) DNS_SWITCH="${2:-0}"; shift 2 ;;

    --nettest=*|--nettest) # deprecated: accepted for backward compatibility, ignored
      shift ;;
    *) echo "Unknown arg: $1"; exit 1 ;;
  esac
done

# ---------------------- УТИЛИТЫ ВЫВОДА ----------------------
log() { echo -e "\033[1;36m==>\033[0m $*"; }
ok()  { echo -e "\033[1;32m✔\033[0m $*"; }
warn(){ echo -e "\033[1;33m!\033[0m $*"; }
err() { echo -e "\033[1;31m✖\033[0m $*"; }

runq(){
  local msg="$1"; shift
  echo -n "   $msg … "
  if "$@" >/dev/null 2>&1; then
    echo "ok"
  else
    echo "fail"
    return 1
  fi
}

require_root(){ [[ $EUID -eq 0 ]] || { err "Run as root"; exit 1; }; }
read_tty(){ local __var="$1" __prompt="$2" __v=""; read -rp "$__prompt" __v </dev/tty || true; printf -v "$__var" '%s' "$__v"; }
read_tty_silent(){
  local __var="$1" __prompt="$2" __v=""
  read -rsp "$__prompt" __v </dev/tty || true
  echo >/dev/tty || true
  printf -v "$__var" '%s' "$__v"
}

# ---------------------- DOWNLOAD HELPERS (keep files in /root) ----------------------
download_to_root() {
  local url="$1"
  local name="$2"
  local out="/root/${name}"

  runq "download ${name}" curl -fsSL "$url" -o "$out"
  chmod +x "$out" || true
  echo "$out"
}

run_local() {
  # run_local "msg" "command..."
  local msg="$1"; shift
  runq "$msg" bash -lc "$* < /dev/null"
}

# ---------------------- SSHD HELPERS ----------------------
SSHD_CONFIG="/etc/ssh/sshd_config"
get_sshd_effective(){
  # Возвращает "ключ значение" последнего (побеждает последний) некомментированного вхождения ключа.
  # Пример: get_sshd_effective PasswordAuthentication -> "yes/no/(unset)"
  local key="$1"
  if [[ -f "$SSHD_CONFIG" ]]; then
    local val
    val="$(awk -v k="$key" '
      BEGIN{IGNORECASE=1; v=""}
      /^[[:space:]]*#/ {next}
      /^[[:space:]]*$/ {next}
      {
        if (tolower($1)==tolower(k) && NF>=2) {
          v=$2
        }
      }
      END{
        if (v=="") print "(unset)";
        else print v
      }' "$SSHD_CONFIG")"
    echo "$val"
  else
    echo "(no_config)"
  fi
}

restart_sshd(){
  # На разных дистрах сервис может называться ssh или sshd
  systemctl restart ssh 2>/dev/null || systemctl restart sshd 2>/dev/null || true
}

require_root
export DEBIAN_FRONTEND=noninteractive
export NEEDRESTART_MODE=a

# ---------------------- STEP 0: HOSTNAME (interactive, no flags) ----------------------
log "Шаг 0: hostname (интерактивно)"
read_tty HOST_NAME "Задать hostname? (Enter чтобы пропустить): "
if [[ -n "${HOST_NAME}" ]]; then
  runq "hostnamectl set-hostname" hostnamectl set-hostname "${HOST_NAME}" || true
  if [[ -f /etc/hosts ]]; then
    if grep -qE '^[[:space:]]*127\.0\.1\.1[[:space:]]+' /etc/hosts; then
      sed -i -E "s/^[[:space:]]*127\.0\.1\.1[[:space:]]+.*/127.0.1.1\t${HOST_NAME}/" /etc/hosts || true
    else
      echo -e "127.0.1.1\t${HOST_NAME}" >> /etc/hosts
    fi
  fi
  ok "hostname установлен: ${HOST_NAME}"
else
  warn "hostname пропущен"
fi

log "Параметры: user='${USER_NAME:-<ask>}' timezone='${TIMEZONE}' reboot='${REBOOT_DELAY}' remnanode='${REMNANODE}' dns-switch='${DNS_SWITCH}'"
if [[ -z "${USER_NAME}" ]]; then
  read_tty USER_NAME "Введите имя пользователя для создания (например, akadorkin): "
  [[ -n "$USER_NAME" ]] || { err "user пуст"; exit 1; }
fi
echo "Пользователь: $USER_NAME"

HOME_DIR="/home/${USER_NAME}"

# ---------------------- REMNANODE: СПРОСИТЬ СРАЗУ ----------------------
if [[ "${REMNANODE}" == "1" ]]; then
  log "remnanode=1 → запрошу параметры сразу"
  read_tty NODE_PORT "Введите NODE_PORT для remnanode (по умолчанию 2222): "
  [[ -n "${NODE_PORT}" ]] || NODE_PORT="2222"

  read_tty_silent SECRET_KEY "Вставь SECRET_KEY целиком (ввод скрыт): "
  if [[ -z "${SECRET_KEY}" ]]; then
    err "SECRET_KEY пуст — remnanode compose не будет создан"
    REMNANODE="0"
  else
    ok "Параметры remnanode получены"
  fi
fi

# ---------------------- FD LIMITS (kernel + systemd defaults) ----------------------
apply_fd_limits() {
  log "FD лимиты (kernel + systemd defaults)"

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

  ok "FD лимиты применены"
}

# ---------------------- PERF PROFILE (download to /root and run locally) ----------------------
apply_perf_profile() {
  log "Perf-профиль сети (vps-network-tuning-script: initial.sh apply)"
  local PERF_SH
  PERF_SH="$(download_to_root \
    "https://raw.githubusercontent.com/akadorkin/vps-network-tuning-script/main/initial.sh" \
    "vps-network-tuning-initial.sh")"

  run_local "vps-network-tuning apply" "sudo bash '${PERF_SH}' apply" || true
  ok "Perf-профиль применён"
}

# ---------------------- ТАЙМЗОНА ----------------------
log "Настройка таймзоны → ${TIMEZONE}"
runq "link /etc/localtime" ln -sf "/usr/share/zoneinfo/${TIMEZONE}" /etc/localtime || true
runq "timedatectl set-timezone" timedatectl set-timezone "${TIMEZONE}" || true
ok "Таймзона готова"

# ---------------------- APT ТИХО В ЛОГ ----------------------
APT_LOG="/var/log/inital-apt.log"; :> "$APT_LOG"
aptq() {
  local what="$1"; shift
  log "$what"
  if apt-get -y -qq -o Dpkg::Use-Pty=0 \
       -o Dpkg::Options::='--force-confdef' \
       -o Dpkg::Options::='--force-confold' \
       "$@" >>"$APT_LOG" 2>&1; then
    ok "$what — ok"
  else
    err "$what — ошибка. См. хвост лога ниже:"; tail -n 60 "$APT_LOG" || true
    echo "Полный лог: $APT_LOG"; exit 1
  fi
}
aptq "APT update" update
aptq "APT upgrade" upgrade
aptq "Установка базовых пакетов" install \
  zsh git curl wget ca-certificates gnupg lsb-release apt-transport-https \
  iproute2 ufw htop mc cron ed openssl logrotate jq iperf3 ethtool

runq "enable cron" systemctl enable --now cron >/dev/null 2>&1 || true
grep -q '^/usr/bin/zsh$' /etc/shells || echo '/usr/bin/zsh' >> /etc/shells

# FD + perf после базовых пакетов
apply_fd_limits
apply_perf_profile

# ---------------------- DOCKER (ТИХО, через runq) ----------------------
log "Установка Docker CE (тихо)"
DOCKER_LOG="/var/log/install-docker.log"; :> "$DOCKER_LOG"
if ! command -v docker >/dev/null 2>&1; then
  runq "rm old docker keyring" rm -f /usr/share/keyrings/docker-archive-keyring.gpg
  runq "install docker gpg key" bash -lc \
    "curl -fsSL https://download.docker.com/linux/ubuntu/gpg | gpg --batch --yes --dearmor -o /usr/share/keyrings/docker-archive-keyring.gpg >>'$DOCKER_LOG' 2>&1"
  echo "deb [arch=$(dpkg --print-architecture) signed-by=/usr/share/keyrings/docker-archive-keyring.gpg] https://download.docker.com/linux/ubuntu $(lsb_release -cs) stable" \
    > /etc/apt/sources.list.d/docker.list
  aptq "APT update (docker)" update
  aptq "Установка Docker CE" install docker-ce docker-ce-cli containerd.io docker-compose-plugin
  runq "enable docker" systemctl enable --now docker
else
  ok "Docker уже установлен — пропускаю"
fi

# ---------------------- ПОЛЬЗОВАТЕЛЬ + SSH ----------------------
log "Пользователь и SSH"
PASS_GEN=""
if id -u "${USER_NAME}" >/dev/null 2>&1; then
  ok "User ${USER_NAME} существует — не создаю"
else
  PASS_GEN="$(openssl rand -base64 16)"
  runq "useradd ${USER_NAME}" useradd -m -s /usr/bin/zsh "${USER_NAME}"
  runq "set user password" bash -lc "echo '${USER_NAME}:${PASS_GEN}' | chpasswd"
  ok "Создан пользователь ${USER_NAME}"
fi
runq "chsh zsh" chsh -s /usr/bin/zsh "${USER_NAME}" || true
runq "add to sudo,docker" usermod -aG sudo,docker "${USER_NAME}" || true
install -m 0440 /dev/stdin "/etc/sudoers.d/${USER_NAME}" <<EOF_SUDO
${USER_NAME} ALL=(ALL) NOPASSWD:ALL
EOF_SUDO

runq "mkdir ~/.ssh" mkdir -p "${HOME_DIR}/.ssh"
runq "chmod 700 ~/.ssh" chmod 700 "${HOME_DIR}/.ssh"

# Копируем authorized_keys: сначала пробуем root, затем ubuntu
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
  warn "authorized_keys не найден ни у root, ни у ubuntu — ключи для ${USER_NAME} не скопированы"
fi

# ---------------------- ZSH/OMZ/P10K + КОНФИГИ ДЛЯ USER_NAME ----------------------
log "Настройка Zsh/oh-my-zsh/p10k для ${USER_NAME}"
if [[ ! -d "${HOME_DIR}/.oh-my-zsh" ]]; then
  runq "oh-my-zsh install" su - "${USER_NAME}" -c 'RUNZSH=no KEEP_ZSHRC=yes CHSH=no sh -c "$(curl -fsSL https://raw.githubusercontent.com/ohmyzsh/ohmyzsh/master/tools/install.sh)"'
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
  runq "fzf clone" su - "${USER_NAME}" -c 'git clone --depth 1 https://github.com/junegunn/fzf.git ~/.fzf'
  runq "fzf install" su - "${USER_NAME}" -c 'yes | ~/.fzf/install --key-bindings --completion --no-bash --no-fish --no-update-rc'
fi

runq "download .zshrc"   curl -fsSL "https://kadorkin.io/zshrc" -o "${HOME_DIR}/.zshrc"
runq "download .p10k"    curl -fsSL "https://kadorkin.io/p10k"  -o "${HOME_DIR}/.p10k.zsh"
runq "chown zsh files"   chown "${USER_NAME}:${USER_NAME}" "${HOME_DIR}/.zshrc" "${HOME_DIR}/.p10k.zsh"

if ! grep -q 'FZF_BASE=' "${HOME_DIR}/.zshrc"; then
  cat >> "${HOME_DIR}/.zshrc" <<'EOF_FZF'
# Linux fallback for oh-my-zsh fzf plugin
if command -v fzf >/dev/null 2>&1; then
  export FZF_BASE="${FZF_BASE:-$HOME/.fzf}"
fi
EOF_FZF
  runq "chown .zshrc" chown "${USER_NAME}:${USER_NAME}" "${HOME_DIR}/.zshrc"
fi
ok "Zsh стэк для ${USER_NAME} готов"

# ---------------------- ZSH/OMZ/P10K ДЛЯ root ----------------------
log "Настройка Zsh/oh-my-zsh/p10k для root"

ROOT_HOME="/root"
USER_OMZ="${HOME_DIR}/.oh-my-zsh"
if [[ -d "$USER_OMZ" && ! -d "${ROOT_HOME}/.oh-my-zsh" ]]; then
  log "Копирую oh-my-zsh от ${USER_NAME} для root"
  cp -a "$USER_OMZ" "${ROOT_HOME}/.oh-my-zsh"
  chown -R root:root "${ROOT_HOME}/.oh-my-zsh"
fi

if [[ ! -d "${ROOT_HOME}/.oh-my-zsh" ]]; then
  log "Пытаюсь установить oh-my-zsh для root из интернета"
  if RUNZSH=no KEEP_ZSHRC=yes CHSH=no \
       sh -c "$(curl -fsSL https://raw.githubusercontent.com/ohmyzsh/ohmyzsh/master/tools/install.sh)"; then
    ok "oh-my-zsh установлен для root"
  else
    warn "oh-my-zsh install (root) завершился с ошибкой — продолжаю без него"
  fi
else
  ok "oh-my-zsh для root уже есть"
fi

ROOT_ZSH_PATH="${ROOT_HOME}/.oh-my-zsh"
ROOT_ZSH_CUSTOM="${ROOT_ZSH_PATH}/custom"
mkdir -p "${ROOT_ZSH_CUSTOM}/plugins" "${ROOT_ZSH_CUSTOM}/themes"

if [[ ! -d "${ROOT_HOME}/.fzf" ]]; then
  log "Устанавливаю fzf для root"
  runq "fzf clone (root)" git clone --depth 1 https://github.com/junegunn/fzf.git "${ROOT_HOME}/.fzf"
  runq "fzf install (root)" bash -lc 'yes | ~/.fzf/install --key-bindings --completion --no-bash --no-fish --no-update-rc'
else
  ok "fzf для root уже есть"
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

# ---- disable OMZ auto-update for all users (and root) ----
disable_omz_updates_one(){
  local zrc="$1"
  [[ -f "$zrc" ]] || return 0
  if ! grep -q 'DISABLE_AUTO_UPDATE' "$zrc" 2>/dev/null; then
    echo 'DISABLE_AUTO_UPDATE="true"' >> "$zrc"
  fi
  if ! grep -q 'DISABLE_UPDATE_PROMPT' "$zrc" 2>/dev/null; then
    echo 'DISABLE_UPDATE_PROMPT=true' >> "$zrc"
  fi
  if ! grep -q ":omz:update" "$zrc" 2>/dev/null; then
    echo "zstyle ':omz:update' mode disabled" >> "$zrc"
  fi
}

for zrc in "/root/.zshrc" /home/*/.zshrc; do
  [[ -e "$zrc" ]] || continue
  disable_omz_updates_one "$zrc"
done

# ---------------------- IPERF3 ----------------------
if command -v iperf3 >/dev/null 2>&1; then
  log "Сервис iperf3"
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

# ---------------------- LOGROTATE ----------------------
log "logrotate для remnanode"
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
ok "logrotate готов"

# ---------------------- REMNANODE COMPOSE ----------------------
log "Проверка remnanode docker-compose.yml"
REMNA_COMPOSE="/opt/remnanode/docker-compose.yml"
if [[ -f "${REMNA_COMPOSE}" ]]; then
  ok "remnanode уже установлен — ${REMNA_COMPOSE} найден, генерация пропущена"
else
  if [[ "${REMNANODE}" == "1" ]]; then
    log "remnanode не найден, создаю /opt/remnanode/docker-compose.yml"
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
    ok "docker-compose.yml для remnanode создан: ${REMNA_COMPOSE}"
  else
    warn "remnanode compose отсутствует, но REMNANODE=0 — генерация пропущена"
  fi
fi

# ---------------------- TAILSCALE (ТИХО, через runq) ----------------------
# (оставлено как в старом скрипте — без изменений)
log "Готовлю систему для Tailscale (IP forwarding + UDP GRO)"
install -m 0644 /dev/stdin /etc/sysctl.d/99-tailscale-forwarding.conf <<'EOF_SYSCTL'
net.ipv4.ip_forward=1
net.ipv6.conf.all.forwarding=1
net.ipv4.conf.all.rp_filter=0
net.ipv4.conf.default.rp_filter=0
EOF_SYSCTL
runq "sysctl --system" sysctl --system

INTERNET_IFACE="$(ip route show default | awk '/default/ {print $5; exit}')"
if [[ -n "${INTERNET_IFACE:-}" ]]; then
  runq "ethtool gro on" ethtool -K "${INTERNET_IFACE}" gro on || true
  runq "ethtool rx-udp-gro-fwd on" ethtool -K "${INTERNET_IFACE}" rx-udp-gro-forwarding on || true
fi

TAILSCALE_LOG="/var/log/install-tailscale.log"; :> "$TAILSCALE_LOG"
if ! command -v tailscale >/dev/null 2>&1; then
  runq "install tailscale" bash -lc 'curl -fsSL https://tailscale.com/install.sh | sh >>/var/log/install-tailscale.log 2>&1'
fi

# SSH hardening (опционально, с подтверждением)
log "SSH hardening (PasswordAuthentication no + PermitRootLogin no)"
read_tty SSH_HARDEN "Применить SSH hardening сейчас? [y/N]: "
case "${SSH_HARDEN,,}" in
  y|yes)
    if [[ -f "$SSHD_CONFIG" ]]; then
      sed -i 's/^[[:space:]]*#\?[[:space:]]*PasswordAuthentication[[:space:]].*/PasswordAuthentication no/' "$SSHD_CONFIG" || true
      sed -i 's/^[[:space:]]*#\?[[:space:]]*PermitRootLogin[[:space:]].*/PermitRootLogin no/' "$SSHD_CONFIG" || true
      grep -qi '^[[:space:]]*PasswordAuthentication[[:space:]]' "$SSHD_CONFIG" || echo 'PasswordAuthentication no' >> "$SSHD_CONFIG"
      grep -qi '^[[:space:]]*PermitRootLogin[[:space:]]' "$SSHD_CONFIG" || echo 'PermitRootLogin no' >> "$SSHD_CONFIG"
      runq "restart sshd" bash -lc 'systemctl restart ssh 2>/dev/null || systemctl restart sshd 2>/dev/null || true'
      ok "SSH hardening применён"
    else
      warn "sshd_config не найден — пропускаю hardening"
    fi
    ;;
  *)
    warn "SSH hardening пропущен"
    ;;
esac

# tailscale up — берём только URL
log "Запуск tailscale up (ожидание авторизации)"
set +e
tailscale up --advertise-exit-node --ssh | tee /tmp/tailscale-up.log
set -e

TAILSCALE_URL="$(grep -Eo 'https://login\.tailscale\.com/[a-zA-Z0-9/_-]+' /tmp/tailscale-up.log | head -n1 || true)"
if [[ -n "$TAILSCALE_URL" ]]; then
  echo "🔗 Открой для авторизации: $TAILSCALE_URL"
else
  echo "⚠️ Ссылка авторизации не найдена. Если tailscale уже был авторизован — всё ок."
  echo "   Если нет, запусти вручную:"
  echo "   tailscale up --advertise-exit-node --ssh"
fi
read_tty _ "Нажми Enter после авторизации устройства в Tailscale…"
TS_IP="$(tailscale ip -4 2>/dev/null || true)"
echo "🌐 Tailscale IP: ${TS_IP:-не назначен}"

# ---------------------- UFW: базовая политика + docker + blocklist ----------------------
log "Настройка UFW"

if ! command -v ufw >/dev/null 2>&1; then
  aptq "Установка UFW" install ufw
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
  err "Не удалось определить INTERNET_IFACE — отменяю настройку UFW."
else
  ok "Внешний интерфейс: ${INTERNET_IFACE}"

  runq "ufw reset"             ufw --force reset
  runq "ufw default deny in"   ufw default deny incoming
  runq "ufw default allow out" ufw default allow outgoing

  for port in "${OPEN_PORTS[@]}"; do
    log "Открываю порт ${port} на ${INTERNET_IFACE} (tcp/udp)"
    ufw allow in on "${INTERNET_IFACE}" to any port "${port}" proto tcp
    ufw allow in on "${INTERNET_IFACE}" to any port "${port}" proto udp
  done

  runq "ufw allow in on tailscale0"  ufw allow in on tailscale0
  runq "ufw allow out on tailscale0" ufw allow out on tailscale0

  DOCKER_IFACES="$(ip -o link show | awk -F': ' '$2 ~ /^(docker0|br-)/ {print $2}' || true)"
  if [[ -n "${DOCKER_IFACES}" ]]; then
    for IFACE in ${DOCKER_IFACES}; do
      log "Разрешаю весь трафик на Docker-интерфейсе ${IFACE}"
      ufw allow in on "${IFACE}"
      ufw allow out on "${IFACE}"
    done
  else
    warn "Docker-интерфейсы (docker0/br-*) не найдены — пропускаю специальные правила для них"
  fi

  install -m 0644 /dev/stdin /etc/cron.d/enable-ufw <<'EOF'
@reboot root ufw --force enable && ufw reload
EOF

  runq "ufw enable" ufw --force enable
  ufw status verbose || true
fi

# ===== Blocklist updater (идемпотентный) =====
BLOCK_SCRIPT=/usr/local/bin/ufw-blocklist-update.sh
install -m 0755 /dev/stdin "$BLOCK_SCRIPT" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
LIST_URL="https://raw.githubusercontent.com/C24Be/AS_Network_List/main/blacklists/blacklist_with_comments.txt"
LOG_FILE=/var/log/ufw-blocklist.log
TAG="BL"

{
  echo "===== $(date '+%F %T') Starting UFW blocklist update ====="

  mapfile -t TO_DELETE < <(ufw status numbered | sed -n 's/^\[\([0-9]\+\)\]\s\+\(.*\) (# '"$TAG"')/\1/p' | tac)
  for n in "${TO_DELETE[@]:-}"; do
    echo "Deleting rule #$n"
    yes | ufw delete "$n" || true
  done

  mapfile -t NETS < <(curl -fsSL "$LIST_URL" \
    | sed '/^#/d;/^$/d;s/^ *//;s/ *$//' \
    | grep -E '^[0-9.]+/[0-9]{1,2}$|^[0-9A-Fa-f:]+/[0-9]{1,3}$')

  for net in "${NETS[@]}"; do
    echo "Deny from $net"
    ufw --force insert 1 deny from "$net" to any comment "$TAG"
  done

  echo "===== Done ====="
} >> "$LOG_FILE" 2>&1
EOF

touch /var/log/ufw-blocklist.log
install -m 0644 /dev/stdin /etc/cron.d/ufw-blocklist <<'EOF'
0 4 * * * root /usr/local/bin/ufw-blocklist-update.sh
EOF

# ---------------------- NODE EXPORTER (важно: после UFW) ----------------------
log "Установка node-exporter (важно: после UFW)"
NODE_SH="$(download_to_root \
  "https://raw.githubusercontent.com/hteppl/sh/master/node_install.sh" \
  "node_install.sh")"
run_local "node_exporter install" "bash '${NODE_SH}'" || true

# ---------------------- DNS SWITCHER (опционально, после node-exporter) ----------------------
if [[ "${DNS_SWITCH}" == "1" ]]; then
  log "dns-switch=1 → запускаю dns-switcher"
  DNS_SH="$(download_to_root \
    "https://raw.githubusercontent.com/AndreyTimoschuk/dns-switcher/main/dns-switcher.sh" \
    "dns-switcher.sh")"
  run_local "run dns-switcher" "sudo bash '${DNS_SH}'" || true
else
  ok "dns-switch=0 — пропускаю dns-switcher"
fi

# ---------------------- REMNANODE UP ----------------------
if [[ -f "${REMNA_COMPOSE}" ]]; then
  log "Запуск remnanode (docker compose up -d)"
  runq "remnanode up" bash -lc 'cd /opt/remnanode && docker compose up -d'
else
  warn "remnanode docker-compose.yml не найден — запуск remnanode пропущен"
fi

# ---------------------- AUTOREMOVE + REBOOT (опциональный) ----------------------
aptq "Autoremove" autoremove --purge

case "${REBOOT_DELAY}" in
  0|no|none|skip|"")
    echo "⚠️ Перезагрузка отключена (параметр --reboot=${REBOOT_DELAY})."
    ;;
  30s|30sec|30)
    echo "⚠️ Перезагрузка через 30 секунд"
    shutdown -r +0.5 >/dev/null 2>&1 || shutdown -r now
    ;;
  5m|5min|300)
    echo "⚠️ Перезагрузка через 5 минут"
    shutdown -r +5 >/dev/null 2>&1 || shutdown -r now
    ;;
  *)
    echo "⚠️ Перезагрузка через ${REBOOT_DELAY}"
    shutdown -r +"${REBOOT_DELAY}" >/dev/null 2>&1 || shutdown -r now
    ;;
esac

# ---------------------- ФИНАЛ ----------------------
echo
echo "✅ Готово."
echo "Логи:"
echo "  • APT:               $APT_LOG"
echo "  • Docker:            /var/log/install-docker.log"
echo "  • Tailscale:         /var/log/install-tailscale.log"
echo

# ВНЕШНИЙ IP
EXT_IP="$(curl -fsSL ifconfig.me 2>/dev/null || curl -fsSL https://api.ipify.org 2>/dev/null || true)"
[[ -z "$EXT_IP" ]] && EXT_IP="не определён"

# SSH effective values
SSH_PASS_AUTH="$(get_sshd_effective PasswordAuthentication)"
SSH_ROOT_LOGIN="$(get_sshd_effective PermitRootLogin)"

echo "UFW:"
echo "  • Входящие: deny (кроме портов: ${OPEN_PORTS[*]} на интерфейсе ${INTERNET_IFACE:-unknown})"
echo "  • Исходящие: allow"
echo "  • tailscale0: полный доступ in/out"
echo "  • Docker-интерфейсы (docker0/br-*): полный доступ in/out (если найдены)"
echo "SSH:"
echo "  • Порт SSH (переменная): ${SSH_PORT}"
echo "  • PasswordAuthentication: ${SSH_PASS_AUTH}"
echo "  • PermitRootLogin:       ${SSH_ROOT_LOGIN}"
echo "FD/perf:"
echo "  • fs.file-max: $(cat /proc/sys/fs/file-max 2>/dev/null || echo 'n/a')"
echo "  • fs.nr_open:  $(cat /proc/sys/fs/nr_open 2>/dev/null || echo 'n/a')"
echo "  • systemd DefaultLimitNOFILE: $(systemctl show --property=DefaultLimitNOFILE 2>/dev/null | cut -d= -f2 || echo 'n/a')"
echo "🌐 Внешний IP: ${EXT_IP}"
echo "🧅  Tailscale IP: ${TS_IP:-не назначен}"
if [[ -n "${PASS_GEN:-}" ]]; then
  echo "🔑 Пароль для ${USER_NAME}: ${PASS_GEN}"
else
  echo "🔑 Пароль для ${USER_NAME}: (не менялся)"
fi