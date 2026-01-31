#!/usr/bin/env bash
set -Eeuo pipefail

###############################################################################
# VPS Edge Router / Node Bootstrap Script
#
# ABSOLUTELY NO WARRANTY:
# This script modifies system settings (kernel/sysctl, SSH, firewall, logs, etc).
# You run it at your own risk. It may break networking, access (SSH), services,
# or performance depending on your environment. Always test on a fresh VM first.
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
      MOVE)
        [[ -f "$b" ]] || continue
        mkdir -p "$(dirname "$a")"
        mv -f "$b" "$a"
        ;;
    esac
  done < "$man"
}

latest_backup_dir() { ls -1dt /root/edge-tuning-backup-* 2>/dev/null | head -n1 || true; }

###############################################################################
# APT helper
###############################################################################
export DEBIAN_FRONTEND=noninteractive
export NEEDRESTART_MODE=a

APT_LOG="/var/log/vps-edge-apt.log"
DNS_LOG="/var/log/vps-edge-dns-switcher.log"
TS_LOG="/var/log/vps-edge-tailscale.log"
DOCKER_LOG="/var/log/vps-edge-docker.log"
NODE_EXPORTER_LOG="/var/log/vps-edge-node-exporter.log"
ERR_LOG="/var/log/vps-edge-error.log"

touch "$APT_LOG" "$DNS_LOG" "$TS_LOG" "$DOCKER_LOG" "$NODE_EXPORTER_LOG" "$ERR_LOG" 2>/dev/null || true

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

Key env:
  EDGE_TAILSCALE_REQUIRE_ENTER=1  -> always require Enter after URL is shown (even if tailscale0 exists)

EOF
}

###############################################################################
# Hostname (interactive)
###############################################################################
hostname_apply_interactive() {
  hdr "🏷️ Hostname"
  local cur newh
  cur="$(hostname 2>/dev/null || echo "")"
  echo "Current: ${cur:-?}"
  if _has_dev_tty; then
    read_tty newh "Enter new hostname (press Enter to keep current): "
    if [[ -n "${newh:-}" ]]; then
      backup_file /etc/hostname
      backup_file /etc/hosts
      hostnamectl set-hostname "$newh" >>"$ERR_LOG" 2>&1 || true
      ok "Hostname set to: $newh"
    else
      ok "Hostname unchanged"
    fi
  else
    warn "No /dev/tty available -> hostname unchanged"
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
# Docker install (idempotent)
###############################################################################
docker_install() {
  hdr "🐳 Docker"
  if command -v docker >/dev/null 2>&1; then
    ok "docker already installed"
    return 0
  fi

  : >"$DOCKER_LOG" || true

  mkdir -p /etc/apt/keyrings
  if [[ ! -f /etc/apt/keyrings/docker.gpg ]]; then
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
# Zsh stack (kept, simplified)
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

  curl -fsSL "$ZSHRC_URL" -o "${home}/.zshrc" >>"$ERR_LOG" 2>&1 || true
  curl -fsSL "$P10K_URL" -o "${home}/.p10k.zsh" >>"$ERR_LOG" 2>&1 || true
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
# Node Exporter (async)
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
# Tailscale (FIXED): live output, show URL, wait for up to finish, Enter if no tailscale0
###############################################################################
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

tailscale_ip4() { tailscale ip -4 2>/dev/null | head -n1 || true; }
extract_tailscale_url_from_line() {
  # prints url if present
  echo "$1" | grep -Eo 'https://login\.tailscale\.com/[a-zA-Z0-9/_-]+' | head -n1 || true
}

tailscale_apply() {
  hdr "🧠 Tailscale (early, hand-mode)"
  : >"$TS_LOG" 2>/dev/null || true

  tailscale_install_if_needed || true
  tailscale_restart_daemon

  # if already configured, just show IP and go on
  local ip=""
  ip="$(tailscale_ip4)"
  if [[ -n "${ip:-}" ]]; then
    ok "tailscale already up (ip ${ip})"
    return 0
  fi

  info "Running: tailscale up --ssh"
  local tmp="/tmp/tailscale-up.log"
  local fifo="/tmp/tailscale-up.fifo.$$"
  : >"$tmp" || true
  rm -f "$fifo" 2>/dev/null || true
  mkfifo "$fifo"

  # Start tailscale up with line-buffering, tee to tmp+log, and stream to fifo for parsing
  (
    stdbuf -oL -eL tailscale up --ssh 2>&1 \
      | tee -a "$tmp" \
      | tee -a "$TS_LOG" \
      > "$fifo"
  ) &
  local up_pid=$!

  local url=""
  local shown_url="0"
  local drainer_pid=""

  # Read lines until we show URL (then start drainer) OR the process exits
  while IFS= read -r line; do
    # keep a minimal echo to resemble native output (but not spam with timestamps)
    # you already see our log lines; this is tailscale output if any:
    [[ -n "$line" ]] && echo "$line"

    if [[ -z "$url" ]]; then
      url="$(extract_tailscale_url_from_line "$line")"
      if [[ -n "$url" && "$shown_url" == "0" ]]; then
        echo
        echo "To authenticate, visit:"
        echo
        echo "        $url"
        echo
        shown_url="1"

        # Start drainer so tailscale output won't block while we wait for user
        cat "$fifo" >/dev/null 2>&1 &
        drainer_pid=$!
        break
      fi
    fi
  done < "$fifo" || true

  # If URL still not found quickly, don't hang parsing; drain and continue with a warning,
  # but we still wait for the tailscale up process to finish (like manual flow).
  if [[ -z "$url" ]]; then
    warn "Auth URL not found in output (yet). If needed, run manually: tailscale up --ssh"
    cat "$fifo" >/dev/null 2>&1 &
    drainer_pid=$!
  fi

  # Ask Enter ALWAYS if tailscale0 missing; and also when forced
  local need_enter="0"
  if ! ip link show tailscale0 >/dev/null 2>&1; then
    need_enter="1"
  fi
  if [[ "${EDGE_TAILSCALE_REQUIRE_ENTER:-0}" == "1" ]]; then
    need_enter="1"
  fi

  if _has_dev_tty && [[ "$need_enter" == "1" ]]; then
    read_tty _ "✅ Approved the device? Press Enter to continue… "
  fi

  # Now wait until tailscale up finishes (this is the only waiting we do)
  wait "$up_pid" 2>/dev/null || true

  # Stop drainer if running
  if [[ -n "${drainer_pid:-}" ]] && kill -0 "$drainer_pid" 2>/dev/null; then
    kill "$drainer_pid" 2>/dev/null || true
  fi

  rm -f "$fifo" 2>/dev/null || true

  ip="$(tailscale_ip4)"
  if [[ -n "${ip:-}" ]]; then
    ok "tailscale ip -4: ${ip}"
  else
    warn "tailscale ip -4 is still empty. Check: tailscale status"
  fi
}

###############################################################################
# DNS switcher (near end)
###############################################################################
dns_apply() {
  hdr "🌐 DNS switcher"
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
}

###############################################################################
# Tuning (sysctl etc.) near end
###############################################################################
detect_hw_profile() {
  HW_CPU="$(nproc 2>/dev/null || echo 1)"
  HW_RAM_MB="$(awk '/MemTotal/ {print int($2/1024)}' /proc/meminfo 2>/dev/null || echo 1024)"
}

apply_sysctl_file() {
  local f="/etc/sysctl.d/99-edge.conf"
  backup_file "$f"

  detect_hw_profile

  # simple sizing
  local ct_max=$(( HW_RAM_MB * 64 + HW_CPU * 8192 ))
  [[ "$ct_max" -lt 65536 ]] && ct_max=65536
  [[ "$ct_max" -gt 1048576 ]] && ct_max=1048576
  local ct_buckets=$(( ct_max / 4 ))
  [[ "$ct_buckets" -lt 16384 ]] && ct_buckets=16384
  [[ "$ct_buckets" -gt 262144 ]] && ct_buckets=262144

  cat >"$f" <<EOF
# Managed by vps-edge-run.sh
net.ipv4.ip_forward=1
net.core.default_qdisc=fq
net.ipv4.tcp_congestion_control=bbr

net.netfilter.nf_conntrack_max=${ct_max}
net.netfilter.nf_conntrack_buckets=${ct_buckets}

net.ipv4.tcp_syncookies=1
net.ipv4.tcp_rfc1337=1
net.ipv4.tcp_keepalive_time=60
net.ipv4.tcp_keepalive_intvl=10
net.ipv4.tcp_keepalive_probes=6

net.core.somaxconn=16384
net.core.netdev_max_backlog=32768
net.ipv4.tcp_max_syn_backlog=8192
net.ipv4.ip_local_port_range=10240 60999

vm.swappiness=10
EOF

  sysctl --system >>"$ERR_LOG" 2>&1 || true
  ok "sysctl tuning applied: $f"
}

tuning_apply() {
  hdr "🛠️ System tuning"
  apply_sysctl_file
}

###############################################################################
# UFW firewall (AT THE VERY END)
###############################################################################
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
    warn "tailscale0 not found. (Authorize Tailscale first.)"
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
apply_cmd() {
  need_root "$@"
  mkbackup

  hostname_apply_interactive

  if [[ -z "${ARG_USER}" ]]; then
    read_tty ARG_USER "User to create/ensure (leave empty to skip): "
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

  if [[ -z "${ARG_SSH_HARDEN}" ]]; then
    local a="n"
    read_tty a "Apply SSH hardening? [y/N]: "
    [[ "${a,,}" == "y" || "${a,,}" == "yes" ]] && ARG_SSH_HARDEN="1" || ARG_SSH_HARDEN="0"
  fi

  if [[ -z "${ARG_OPEN_WAN_443}" ]]; then
    local a="y"
    read_tty a "Open WAN only 443 via UFW (at the end)? [Y/n]: "
    [[ -z "$a" || "${a,,}" == "y" || "${a,,}" == "yes" ]] && ARG_OPEN_WAN_443="1" || ARG_OPEN_WAN_443="0"
  fi

  if [[ -z "${ARG_DNS_SWITCHER}" ]]; then
    local a="n"
    read_tty a "Run DNS switcher (near end)? [y/N]: "
    [[ "${a,,}" == "y" || "${a,,}" == "yes" ]] && ARG_DNS_SWITCHER="1" || ARG_DNS_SWITCHER="0"
  fi

  if [[ -z "${ARG_ZSH_ALL_USERS}" ]]; then
    local a="y"
    read_tty a "Setup zsh stack for all users? [Y/n]: "
    [[ -z "$a" || "${a,,}" == "y" || "${a,,}" == "yes" ]] && ARG_ZSH_ALL_USERS="1" || ARG_ZSH_ALL_USERS="0"
  fi

  ensure_packages "📦 Packages" \
    curl wget ca-certificates gnupg lsb-release apt-transport-https \
    jq iproute2 ethtool openssl logrotate cron ufw iperf3 git zsh mc

  timezone_apply

  if [[ "${ARG_TAILSCALE}" == "1" ]]; then
    tailscale_apply
  fi

  if [[ "${ARG_NODE_EXPORTER}" == "1" ]]; then
    node_exporter_apply
  fi

  if [[ -n "${ARG_USER}" ]]; then
    create_or_ensure_user "${ARG_USER}"
  fi

  if [[ "${ARG_ZSH_ALL_USERS}" == "1" ]]; then
    zsh_apply_all_users
  fi

  if [[ "${ARG_SSH_HARDEN}" == "1" ]]; then
    ssh_harden_apply
  fi

  # moved toward end
  tuning_apply

  # moved toward end
  if [[ "${ARG_DNS_SWITCHER}" == "1" ]]; then
    dns_apply
  fi

  # UFW at the end
  ufw_apply

  hdr "🧹 Autoremove"
  aptq "Autoremove" autoremove --purge

  hdr "✅ Done"
  if command -v tailscale >/dev/null 2>&1; then
    echo "Tailscale IP: $(tailscale ip -4 2>/dev/null || echo '-')"
  fi
  if [[ "${USER_CREATED}" == "1" ]]; then
    echo "User: ${ARG_USER}"
    echo "Password: ${USER_PASS}"
  fi
  echo "Backup dir: ${backup_dir}"

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
  restore_manifest "$backup"
  sysctl --system >/dev/null 2>&1 || true
  systemctl daemon-reexec >/dev/null 2>&1 || true
  ok "Rolled back. Backup used: $backup"
}

status_cmd() {
  hdr "📊 Status"
  echo "Host: $(host_short)"
  echo "BBR:  $(sysctl -n net.ipv4.tcp_congestion_control 2>/dev/null || echo '-')"
  echo "Qdisc:$(sysctl -n net.core.default_qdisc 2>/dev/null || echo '-')"
  echo "FWD:  $(sysctl -n net.ipv4.ip_forward 2>/dev/null || echo '-')"
  echo "TS IP:$(tailscale ip -4 2>/dev/null || echo '-')"
  echo "UFW:  $(ufw status 2>/dev/null | head -n1 || echo '-')"
}

case "$CMD" in
  apply)    apply_cmd ;;
  rollback) rollback_cmd "$@" ;;
  status)   status_cmd ;;
  ""|help|-h|--help) usage; exit 0 ;;
  *) usage; exit 1 ;;
esac
