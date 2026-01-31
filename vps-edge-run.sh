#!/usr/bin/env bash
set -Eeuo pipefail

###############################################################################
# vps-edge-run.sh
# - DNS switcher (optional, early)
# - Tailscale (optional, early; idempotent; no reset)
# - External kernel/system tuning (calls your tuning script; backup+rollback in that script)
# - Docker + remnanode (optional; early inputs only if compose missing)
# - User (optional/interactive) + Zsh stack for all /home/* users + root
# - UFW: WAN only 443 (+ tailscale UDP 41641 when enabled), Tailscale allow-all, Docker bridges allow-all
# - iperf3 installed always + systemd server enabled always
###############################################################################

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
# Args + defaults
###############################################################################
CMD="${1:-}"; shift || true

ARG_USER=""
ARG_TIMEZONE="Europe/Moscow"
ARG_REBOOT="5m"

ARG_TAILSCALE=""         # 0/1, if empty -> interactive
ARG_DNS_SWITCHER=""      # 0/1, if empty -> interactive
ARG_DNS_PROFILE="1"      # 1..5
ARG_REMNANODE=""         # 0/1, if empty -> interactive
ARG_SSH_HARDEN=""        # 0/1, if empty -> interactive
ARG_OPEN_WAN_443=""      # 0/1, if empty -> interactive

# External tuning
ARG_TUNING=""            # 0/1, if empty -> enabled by default
TUNING_URL="${TUNING_URL:-https://raw.githubusercontent.com/akadorkin/vps-network-tuning-script/main/initial.sh}"

# remnanode inputs (asked early if needed)
NODE_PORT=""
SECRET_KEY=""

# URLs
DNS_SWITCHER_URL="${DNS_SWITCHER_URL:-https://raw.githubusercontent.com/AndreyTimoschuk/dns-switcher/main/dns-switcher.sh}"
ZSHRC_URL="${ZSHRC_URL:-https://raw.githubusercontent.com/akadorkin/remnanode-install-script/refs/heads/main/main/zshrc}"
P10K_URL="${P10K_URL:-https://raw.githubusercontent.com/akadorkin/remnanode-install-script/refs/heads/main/main/p10k}"

# Logs
APT_LOG="/var/log/vps-edge-apt.log"
DNS_LOG="/var/log/vps-edge-dns-switcher.log"
TS_LOG="/var/log/vps-edge-tailscale.log"
DOCKER_LOG="/var/log/vps-edge-docker.log"
TUNING_LOG="/var/log/vps-edge-tuning.log"
ERR_LOG="/var/log/vps-edge-error.log"

touch "$APT_LOG" "$DNS_LOG" "$TS_LOG" "$DOCKER_LOG" "$TUNING_LOG" "$ERR_LOG" 2>/dev/null || true

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
    --tuning=*)        ARG_TUNING="${1#*=}"; shift ;;

    --user)          ARG_USER="${2:-}"; shift 2 ;;
    --timezone)      ARG_TIMEZONE="${2:-}"; shift 2 ;;
    --reboot)        ARG_REBOOT="${2:-}"; shift 2 ;;
    --tailscale)     ARG_TAILSCALE="${2:-}"; shift 2 ;;
    --dns-switcher)  ARG_DNS_SWITCHER="${2:-}"; shift 2 ;;
    --dns-profile)   ARG_DNS_PROFILE="${2:-}"; shift 2 ;;
    --remnanode)     ARG_REMNANODE="${2:-}"; shift 2 ;;
    --ssh-harden)    ARG_SSH_HARDEN="${2:-}"; shift 2 ;;
    --open-wan-443)  ARG_OPEN_WAN_443="${2:-}"; shift 2 ;;
    --tuning)        ARG_TUNING="${2:-}"; shift 2 ;;
    *) die "Unknown arg: $1" ;;
  esac
done

usage() {
  cat <<'EOF'
Usage:
  sudo ./vps-edge-run.sh apply [flags]
  sudo ./vps-edge-run.sh status

Flags (apply):
  --user <name>                Create/ensure user (optional; interactive if omitted)
  --timezone <TZ>              Default: Europe/Moscow
  --reboot <5m|30s|skip|none>  Default: 5m

  --dns-switcher 0|1
  --dns-profile 1..5

  --tailscale 0|1
  --tuning 0|1                 Call external tuning script (default: 1)
  --remnanode 0|1
  --ssh-harden 0|1
  --open-wan-443 0|1

Examples:
  sudo ./vps-edge-run.sh apply --reboot=skip --tailscale=1 --tuning=1 --open-wan-443=1 --ssh-harden=1 --user akadorkin
EOF
}

###############################################################################
# APT helper
###############################################################################
export DEBIAN_FRONTEND=noninteractive
export NEEDRESTART_MODE=a

aptq() {
  local what="$1"; shift
  local cmd="${1:-}"; shift || true

  local opts=(-y -qq -o Dpkg::Use-Pty=0)
  if [[ "$cmd" != "update" ]]; then
    opts+=(
      -o Dpkg::Options::='--force-confdef'
      -o Dpkg::Options::='--force-confold'
    )
  fi

  if apt-get "${opts[@]}" "$cmd" "$@" >>"$APT_LOG" 2>&1; then
    ok "$what"
  else
    err "$what failed. Tail:"
    tail -n 80 "$APT_LOG" || true
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
}

###############################################################################
# Docker install (idempotent, Debian/Ubuntu aware)
###############################################################################
docker_install() {
  hdr "🐳 Docker"
  if command -v docker >/dev/null 2>&1; then
    ok "docker already installed"
    return 0
  fi

  : >"$DOCKER_LOG" || true

  local os_id=""
  os_id="$(. /etc/os-release 2>/dev/null; echo "${ID:-}")"
  local docker_os="ubuntu"
  [[ "$os_id" == "debian" ]] && docker_os="debian"

  if [[ ! -f /etc/apt/keyrings/docker.gpg ]]; then
    mkdir -p /etc/apt/keyrings
    curl -fsSL "https://download.docker.com/linux/${docker_os}/gpg" \
      | gpg --batch --yes --dearmor -o /etc/apt/keyrings/docker.gpg >>"$DOCKER_LOG" 2>&1 || true
    chmod a+r /etc/apt/keyrings/docker.gpg || true
  fi

  local codename=""
  codename="$(. /etc/os-release 2>/dev/null; echo "${VERSION_CODENAME:-}")"
  [[ -n "$codename" ]] || codename="$(lsb_release -cs 2>/dev/null || true)"
  [[ -n "$codename" ]] || die "Cannot detect distro codename"

  echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/${docker_os} ${codename} stable" \
    > /etc/apt/sources.list.d/docker.list

  aptq "APT update (docker)" update
  aptq "Install Docker CE" install docker-ce docker-ce-cli containerd.io docker-compose-plugin

  systemctl enable --now docker >>"$DOCKER_LOG" 2>&1 || true
  ok "docker installed"
}

###############################################################################
# Tailscale (idempotent; safe)
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

tailscale_is_up() { tailscale status >/dev/null 2>&1; }
tailscale_ip4() { tailscale ip -4 2>/dev/null | head -n1 || true; }

tailscale_magicdns_name() {
  local name=""
  if command -v jq >/dev/null 2>&1 && tailscale status --json >/dev/null 2>&1; then
    name="$(tailscale status --json 2>/dev/null | jq -r '.Self.DNSName // empty' 2>/dev/null || true)"
  fi
  if [[ -z "$name" ]]; then
    name="$(tailscale status 2>/dev/null | awk 'NR==1{print $2}' | sed 's/^\(.*\)\.$/\1/' || true)"
  fi
  name="${name%.}"
  echo "$name"
}

tailscale_apply() {
  hdr "🧠 Tailscale (early)"
  tailscale_install_if_needed

  if tailscale_is_up; then
    local ip name
    ip="$(tailscale_ip4)"
    [[ -n "$ip" ]] && ok "tailscale is up (ip ${ip})" || ok "tailscale is up"
    name="$(tailscale_magicdns_name)"
    [[ -n "$name" ]] && ok "MagicDNS: ${name}" || warn "MagicDNS name not available."
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

  [[ -n "$ip" ]] && ok "tailscale is up (ip ${ip})" || warn "tailscale IP not detected (maybe still pending auth)."
  local name
  name="$(tailscale_magicdns_name)"
  [[ -n "$name" ]] && ok "MagicDNS: ${name}" || warn "MagicDNS name not available."
}

###############################################################################
# External tuning (your script)
###############################################################################
TUNING_BACKUP_DIR=""

tuning_apply_external() {
  hdr "🧠 Kernel + system tuning (external)"

  : >"$TUNING_LOG" || true

  info "Calling: ${TUNING_URL} apply --reboot=skip"
  set +e
  # IMPORTANT: run with reboot=skip, big script will decide about reboot itself
  curl -fsSL "$TUNING_URL" | bash -s -- apply --reboot=skip 2>&1 | tee -a "$TUNING_LOG"
  local rc=${PIPESTATUS[1]}
  set -e

  # Best-effort parse BACKUP_DIR=... if your tuning script prints it
  local b=""
  b="$(grep -Eo 'BACKUP_DIR=/root/edge-tuning-backup-[0-9]{8}-[0-9]{6}' "$TUNING_LOG" | tail -n1 | cut -d= -f2 || true)"
  [[ -n "$b" ]] && TUNING_BACKUP_DIR="$b"

  if [[ "$rc" -ne 0 ]]; then
    err "External tuning failed (rc=${rc}). See log: $TUNING_LOG"
    [[ -n "$TUNING_BACKUP_DIR" ]] && warn "Tuning rollback hint: sudo BACKUP_DIR=${TUNING_BACKUP_DIR} bash -s -- rollback (same tuning script)"
    return "$rc"
  fi

  ok "External tuning applied"
  [[ -n "$TUNING_BACKUP_DIR" ]] && ok "Tuning backup: $TUNING_BACKUP_DIR"
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
  aptq "Install zsh stack packages" install zsh git curl wget ca-certificates jq

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

  sed -i 's/^[[:space:]]*#\?[[:space:]]*PasswordAuthentication[[:space:]].*/PasswordAuthentication no/' "$cfg" || true
  sed -i 's/^[[:space:]]*#\?[[:space:]]*PermitRootLogin[[:space:]].*/PermitRootLogin no/' "$cfg" || true

  grep -qi '^[[:space:]]*PasswordAuthentication[[:space:]]' "$cfg" || echo 'PasswordAuthentication no' >> "$cfg"
  grep -qi '^[[:space:]]*PermitRootLogin[[:space:]]' "$cfg" || echo 'PermitRootLogin no' >> "$cfg"

  systemctl restart ssh 2>/dev/null || systemctl restart sshd 2>/dev/null || true
  ok "SSH hardening applied"
}

###############################################################################
# UFW firewall (SAFE for SSH + Tailscale)
###############################################################################
detect_wan_iface() {
  local internet_iface=""
  internet_iface="$(ip route get 8.8.8.8 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="dev") print $(i+1)}' | head -n1 || true)"
  [[ -n "$internet_iface" ]] || internet_iface="$(ip route show default 2>/dev/null | awk '/default/ {print $5; exit}' || true)"
  echo "$internet_iface"
}

ssh_session_failsafe_allow() {
  # If running under SSH, allow current remote IP to current SSH port on WAN iface
  local wan_if="$1"
  [[ -n "$wan_if" ]] || return 0

  local ssh_port=""
  ssh_port="$(ss -ltn 2>/dev/null | awk '$4 ~ /:22$/ {found=1} END{ if(found) print 22 }' || true)"
  [[ -n "$ssh_port" ]] || ssh_port="22"

  local rip=""
  if [[ -n "${SSH_CONNECTION:-}" ]]; then
    rip="$(awk '{print $1}' <<<"$SSH_CONNECTION" 2>/dev/null || true)"
  fi

  if [[ -n "$rip" ]]; then
    # Only allow from that single IP
    ufw allow in on "$wan_if" from "$rip" to any port "$ssh_port" proto tcp >/dev/null 2>&1 || true
    ok "Failsafe: allow SSH from ${rip} to ${wan_if}:${ssh_port}/tcp"
  fi
}

ufw_apply() {
  hdr "🧱 Firewall (UFW)"

  if ! command -v ufw >/dev/null 2>&1; then
    aptq "Install UFW" install ufw
  fi

  # Make forwarding policy ACCEPT (Docker/Tailscale routing cases)
  if [[ -f /etc/default/ufw ]]; then
    if grep -q '^DEFAULT_FORWARD_POLICY=' /etc/default/ufw; then
      sed -i 's/^DEFAULT_FORWARD_POLICY=.*/DEFAULT_FORWARD_POLICY="ACCEPT"/' /etc/default/ufw || true
    else
      echo 'DEFAULT_FORWARD_POLICY="ACCEPT"' >> /etc/default/ufw
    fi
  fi

  local wan_if=""
  wan_if="$(detect_wan_iface)"
  [[ -n "$wan_if" ]] || { warn "Cannot detect WAN iface; skipping UFW"; return 0; }
  ok "WAN iface: ${wan_if}"

  # Record current status before touching
  ufw status verbose >>"$ERR_LOG" 2>&1 || true

  ufw --force reset >/dev/null 2>&1 || true
  ufw default deny incoming >/dev/null 2>&1 || true
  ufw default allow outgoing >/dev/null 2>&1 || true

  # Critical: don't lock yourself out if running via SSH
  ssh_session_failsafe_allow "$wan_if"

  # WAN 443 (optional)
  if [[ "${ARG_OPEN_WAN_443}" == "1" ]]; then
    ufw allow in on "$wan_if" to any port 443 proto tcp >/dev/null 2>&1 || true
    ufw allow in on "$wan_if" to any port 443 proto udp >/dev/null 2>&1 || true
    ok "WAN (${wan_if}): allow 443/tcp, 443/udp"
  else
    warn "WAN (${wan_if}): no inbound ports opened by policy (open-wan-443=0)"
  fi

  # If Tailscale enabled: allow UDP 41641 on WAN for direct peer-to-peer
  if [[ "${ARG_TAILSCALE}" == "1" ]]; then
    ufw allow in on "$wan_if" to any port 41641 proto udp >/dev/null 2>&1 || true
    ok "WAN (${wan_if}): allow 41641/udp for tailscale P2P"
  fi

  # Tailscale interface allow-all (only if exists)
  if ip link show tailscale0 >/dev/null 2>&1; then
    ufw allow in on tailscale0 >/dev/null 2>&1 || true
    ufw allow out on tailscale0 >/dev/null 2>&1 || true
    ok "Tailscale (tailscale0): allow all (in/out)"
  else
    warn "tailscale0 not found (tailscale disabled or not up yet)."
  fi

  # Docker bridges allow-all
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
  ufw status verbose 2>/dev/null || true
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
    return 0
  else
    warn "remnanode start failed (see $ERR_LOG)"
    return 1
  fi
}

remnanode_logrotate_apply() {
  hdr "🗂️  Remnanode logrotate"
  aptq "Ensure logrotate installed" install logrotate
  mkdir -p /var/log/remnanode
  cat >/etc/logrotate.d/remnanode <<'EOF'
/var/log/remnanode/*.log {
    size 50M
    rotate 5
    compress
    missingok
    notifempty
    copytruncate
}
EOF
  ok "logrotate config written: /etc/logrotate.d/remnanode"
  logrotate -vf /etc/logrotate.d/remnanode >>"$ERR_LOG" 2>&1 || true
  ok "logrotate test completed"
}

remnanode_status_line() {
  if command -v docker >/dev/null 2>&1; then
    docker ps --format '{{.Names}} {{.Status}}' 2>/dev/null | awk '$1=="remnanode"{ $1=""; sub(/^ /,""); print "remnanode " $0 }' | head -n1 || true
  fi
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
# Apply / status
###############################################################################
on_apply_fail() {
  local code=$?
  err "Apply failed (exit code=$code)."
  err "See logs: ${ERR_LOG}, ${APT_LOG}, ${TS_LOG}, ${TUNING_LOG}"
  exit "$code"
}

apply_cmd() {
  need_root "$@"
  trap on_apply_fail ERR

  is_debian_like || die "This script expects Debian/Ubuntu (apt)."

  # Defaults
  if [[ -z "${ARG_TUNING}" ]]; then ARG_TUNING="1"; fi

  if [[ -z "${ARG_USER}" ]]; then
    if [[ -t 0 ]]; then read_tty ARG_USER "User to create/ensure (leave empty to skip): "; fi
  fi

  if [[ -z "${ARG_DNS_SWITCHER}" ]]; then
    if [[ -t 0 ]]; then
      local a="n"; read_tty a "Run DNS switcher early? [y/N]: "
      [[ "${a,,}" == "y" || "${a,,}" == "yes" ]] && ARG_DNS_SWITCHER="1" || ARG_DNS_SWITCHER="0"
    else
      ARG_DNS_SWITCHER="0"
    fi
  fi

  if [[ -z "${ARG_TAILSCALE}" ]]; then
    if [[ -t 0 ]]; then
      local a="y"; read_tty a "Enable Tailscale early? [Y/n]: "
      [[ -z "$a" || "${a,,}" == "y" || "${a,,}" == "yes" ]] && ARG_TAILSCALE="1" || ARG_TAILSCALE="0"
    else
      ARG_TAILSCALE="1"
    fi
  fi

  if [[ -z "${ARG_REMNANODE}" ]]; then
    if [[ -t 0 ]]; then
      local a="n"; read_tty a "Install/start remnanode? [y/N]: "
      [[ "${a,,}" == "y" || "${a,,}" == "yes" ]] && ARG_REMNANODE="1" || ARG_REMNANODE="0"
    else
      ARG_REMNANODE="0"
    fi
  fi

  if [[ -z "${ARG_SSH_HARDEN}" ]]; then
    if [[ -t 0 ]]; then
      local a="n"; read_tty a "Apply SSH hardening? [y/N]: "
      [[ "${a,,}" == "y" || "${a,,}" == "yes" ]] && ARG_SSH_HARDEN="1" || ARG_SSH_HARDEN="0"
    else
      ARG_SSH_HARDEN="0"
    fi
  fi

  if [[ -z "${ARG_OPEN_WAN_443}" ]]; then
    if [[ -t 0 ]]; then
      local a="y"; read_tty a "Open WAN only 443 via UFW? [Y/n]: "
      [[ -z "$a" || "${a,,}" == "y" || "${a,,}" == "yes" ]] && ARG_OPEN_WAN_443="1" || ARG_OPEN_WAN_443="0"
    else
      ARG_OPEN_WAN_443="1"
    fi
  fi

  if [[ "${ARG_REMNANODE}" == "1" ]]; then
    remnanode_collect_inputs_early
  fi

  ensure_packages "📦 Packages" \
    curl wget ca-certificates gnupg lsb-release apt-transport-https \
    jq iproute2 ethtool openssl logrotate cron ufw iperf3 git zsh mc

  timezone_apply

  if [[ "${ARG_DNS_SWITCHER}" == "1" ]]; then
    dns_apply
  fi

  # Tailscale first (so firewall can safely allow tailscale0 and not lock you out)
  if [[ "${ARG_TAILSCALE}" == "1" ]]; then
    tailscale_apply
  fi

  # External tuning (your script)
  if [[ "${ARG_TUNING}" == "1" ]]; then
    tuning_apply_external
  else
    warn "External tuning skipped (--tuning=0)"
  fi

  # Docker / remnanode
  if [[ "${ARG_REMNANODE}" == "1" ]]; then
    docker_install
  fi

  if [[ -n "${ARG_USER}" ]]; then
    create_or_ensure_user "${ARG_USER}"
  else
    USER_CREATED="0"
    USER_PASS=""
  fi

  zsh_apply_all_users

  if [[ "${ARG_SSH_HARDEN}" == "1" ]]; then
    ssh_harden_apply
  fi

  # Firewall after tailscale attempt (safe) + opens 41641/udp if tailscale enabled
  ufw_apply

  iperf3_server_apply

  if [[ "${ARG_REMNANODE}" == "1" ]]; then
    remnanode_apply
    remnanode_logrotate_apply
  fi

  hdr "🧹 Autoremove"
  aptq "Autoremove" autoremove --purge

  hdr "🧾 Summary"
  echo "Host:        $(host_short)"
  echo "Timezone:    ${ARG_TIMEZONE}"
  echo "Tailscale:   ${ARG_TAILSCALE}"
  echo "UFW WAN 443: ${ARG_OPEN_WAN_443}"
  echo "Tuning:      ${ARG_TUNING}"
  [[ -n "${TUNING_BACKUP_DIR:-}" ]] && echo "Tuning backup: ${TUNING_BACKUP_DIR}"
  if [[ -n "${ARG_USER:-}" ]]; then
    if [[ "${USER_CREATED:-0}" == "1" ]]; then
      echo "User:        ${ARG_USER}"
      echo "Password:    ${USER_PASS}"
    else
      echo "User:        ${ARG_USER}"
      echo "Password:    (unchanged)"
    fi
  fi
  if command -v tailscale >/dev/null 2>&1; then
    echo "Tailscale IP: $(tailscale_ip4 || true)"
    echo "MagicDNS:     $(tailscale_magicdns_name || true)"
  fi
  echo "Logs:"
  echo "  - APT:       ${APT_LOG}"
  echo "  - DNS:       ${DNS_LOG}"
  echo "  - Tailscale: ${TS_LOG}"
  echo "  - Docker:    ${DOCKER_LOG}"
  echo "  - Tuning:    ${TUNING_LOG}"
  echo "  - Error:     ${ERR_LOG}"

  maybe_reboot
}

status_cmd() {
  hdr "📊 Current"
  echo "Host: $(host_short)"
  echo "UFW:"
  ufw status verbose 2>/dev/null || echo "ufw not available"
  echo
  echo "Tailscale:"
  if command -v tailscale >/dev/null 2>&1; then
    tailscale status 2>/dev/null || true
  else
    echo "tailscale not installed"
  fi
}

###############################################################################
# Main
###############################################################################
case "$CMD" in
  apply)    apply_cmd ;;
  status)   status_cmd ;;
  ""|help|-h|--help) usage; exit 0 ;;
  *) usage; exit 1 ;;
esac
