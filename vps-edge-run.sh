#!/usr/bin/env bash
set -euo pipefail

# ==============================================================================
## vps-edge-run.sh — VPS bootstrap & hardening for Remnanode behind Tailscale
#
# ABSOLUTELY NO WARRANTY. USE AT YOUR OWN RISK.
# This script may change networking/SSH/firewall settings and can lock you out.
# Always test on a fresh VM first and keep provider console access available.
# ==============================================================================

# ---------------------- GLOBALS ----------------------
SCRIPT_NAME="$(basename "$0")"
STATE_DIR="/var/lib/vps-edge-run"
BACKUP_DIR="${STATE_DIR}/backups"
STAMP_FILE="${STATE_DIR}/last_apply.json"

SSHD_CONFIG="/etc/ssh/sshd_config"

export DEBIAN_FRONTEND=noninteractive
export NEEDRESTART_MODE=a

# ---------------------- DEFAULTS / FLAGS ----------------------
CMD="${1:-apply}"
shift || true

USER_NAME=""
TIMEZONE="Europe/Moscow"
REBOOT_DELAY="skip"      # 30s | 5m | 300 | 0|none|skip
SSH_PORT="${SSH_PORT:-22}"

REMNANODE="0"            # 0/1
NETTEST="0"              # 0/1
TAILSCALE="1"            # 0/1
TAILSCALE_ONLY="1"       # 1 = assume admin via tailscale; if WAN_SSH=0, require TS before enabling UFW
WAN_SSH="1"              # 1 = failsafe open 22/tcp on WAN
TS_EXIT_NODE="0"         # 1 = advertise-exit-node
TS_WAIT_SEC="60"         # wait tailscale IPv4 before enabling ufw in tailscale-only mode
SSH_HARDEN="0"           # 0/1 — PasswordAuthentication no + PermitRootLogin no
OPEN_WAN_443="1"         # 0/1 — allow 443 on WAN (tcp+udp)
OPEN_WAN_80="0"          # 0/1 — allow 80/tcp on WAN (rare)
DNS_SWITCHER="0"         # 0/1 — install dns-switcher and apply profile
DNS_PROFILE="1"          # 1..N — profile number for dns-switcher
INSTALL_NODE_EXPORTER="1"  # 0/1 — install node exporter via hteppl script
INSTALL_BBR_SCRIPT="0"     # 0/1 — run hteppl bbr_install.sh (you already set BBR in sysctl, so default 0)
IPERF_SERVICE="0"          # 0/1 — enable iperf3 systemd server
BESZEL_AGENT="0"           # 0/1 — run beszel-agent container (off by default for public script)

# Remnanode params (asked early if REMNANODE=1 and compose missing)
NODE_PORT=""
SECRET_KEY=""

# ---------------------- UTILS ----------------------
log()  { echo -e "\033[1;36m[$(date '+%F %T')] ℹ️ \033[0m $*"; }
ok()   { echo -e "\033[1;32m[$(date '+%F %T')] ✅ OK\033[0m $*"; }
warn() { echo -e "\033[1;33m[$(date '+%F %T')] ⚠️  WARN\033[0m $*"; }
err()  { echo -e "\033[1;31m[$(date '+%F %T')] ❌ ERR\033[0m $*"; }

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

require_root(){ [[ $EUID -eq 0 ]] || { err "Run as root (sudo -i)"; exit 1; }; }

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

have_cmd(){ command -v "$1" >/dev/null 2>&1; }

json_escape(){ python3 - <<'PY' "$1"
import json,sys
print(json.dumps(sys.argv[1]))
PY
}

mkdir_state(){
  mkdir -p "$STATE_DIR" "$BACKUP_DIR"
  chmod 700 "$STATE_DIR" || true
}

now_ts(){ date -u '+%Y%m%dT%H%M%SZ'; }

# ---------------------- ARG PARSING ----------------------
usage(){
  cat <<EOF
Usage:
  $SCRIPT_NAME apply [options]
  $SCRIPT_NAME rollback [--backup=<id>]
  $SCRIPT_NAME status

Common options (apply):
  --user=<name>                 Create/use admin user (required if no prompt)
  --timezone=<TZ>               Default: Europe/Moscow
  --reboot=<skip|0|30s|5m|...>   Default: skip
  --tailscale=0|1               Default: 1
  --tailscale-only=0|1          Default: 1
  --wan-ssh=0|1                 Default: 1 (failsafe keep 22/tcp on WAN)
  --ts-exit-node=0|1            Default: 0
  --ts-wait=<sec>               Default: 60
  --ssh-harden=0|1              Default: 0
  --open-wan-443=0|1            Default: 1
  --open-wan-80=0|1             Default: 0
  --dns-switcher=0|1            Default: 0
  --dns-profile=<n>             Default: 1
  --remnanode=0|1               Default: 0
  --nettest=0|1                 Default: 0
  --node-exporter=0|1           Default: 1
  --iperf-service=0|1           Default: 0
  --beszel-agent=0|1            Default: 0

Rollback:
  --backup=<id>                 Backup ID to rollback (default: latest)

EOF
}

parse_args(){
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --user=*) USER_NAME="${1#*=}"; shift ;;
      --timezone=*) TIMEZONE="${1#*=}"; shift ;;
      --reboot=*) REBOOT_DELAY="${1#*=}"; shift ;;

      --tailscale=*) TAILSCALE="${1#*=}"; shift ;;
      --tailscale-only=*) TAILSCALE_ONLY="${1#*=}"; shift ;;
      --wan-ssh=*) WAN_SSH="${1#*=}"; shift ;;
      --ts-exit-node=*) TS_EXIT_NODE="${1#*=}"; shift ;;
      --ts-wait=*) TS_WAIT_SEC="${1#*=}"; shift ;;

      --ssh-harden=*) SSH_HARDEN="${1#*=}"; shift ;;
      --open-wan-443=*) OPEN_WAN_443="${1#*=}"; shift ;;
      --open-wan-80=*) OPEN_WAN_80="${1#*=}"; shift ;;

      --dns-switcher=*) DNS_SWITCHER="${1#*=}"; shift ;;
      --dns-profile=*) DNS_PROFILE="${1#*=}"; shift ;;

      --remnanode=*) REMNANODE="${1#*=}"; shift ;;
      --nettest=*) NETTEST="${1#*=}"; shift ;;
      --node-exporter=*) INSTALL_NODE_EXPORTER="${1#*=}"; shift ;;
      --iperf-service=*) IPERF_SERVICE="${1#*=}"; shift ;;
      --beszel-agent=*) BESZEL_AGENT="${1#*=}"; shift ;;

      --backup=*) ROLLBACK_BACKUP_ID="${1#*=}"; shift ;;

      -h|--help) usage; exit 0 ;;
      *) err "Unknown arg: $1"; usage; exit 1 ;;
    esac
  done
}

# ---------------------- BACKUPS / ROLLBACK ----------------------
backup_id=""
backup_path=""

make_backup(){
  mkdir_state
  backup_id="$(now_ts)"
  backup_path="${BACKUP_DIR}/${backup_id}"
  mkdir -p "$backup_path"

  # Collect config backups (best-effort)
  cp -a /etc/sysctl.d "$backup_path/sysctl.d" 2>/dev/null || true
  cp -a /etc/systemd/system.conf.d "$backup_path/systemd.system.conf.d" 2>/dev/null || true
  cp -a /etc/security/limits.d "$backup_path/security.limits.d" 2>/dev/null || true
  cp -a /etc/ssh/sshd_config "$backup_path/sshd_config" 2>/dev/null || true
  cp -a /etc/default/ufw "$backup_path/ufw.default" 2>/dev/null || true
  ufw status verbose >"$backup_path/ufw.status.txt" 2>/dev/null || true
  ip -br a >"$backup_path/ip.br.a.txt" 2>/dev/null || true

  # Save a minimal stamp (JSON) for status
  cat >"$STAMP_FILE" <<EOF
{"backup_id":$(json_escape "$backup_id"),"created_utc":$(json_escape "$(date -u '+%F %T')")}
EOF

  ok "Backup created: $backup_id (${backup_path})"
}

list_backups(){
  mkdir_state
  ls -1 "$BACKUP_DIR" 2>/dev/null | sort -r || true
}

rollback(){
  require_root
  mkdir_state
  local id="${ROLLBACK_BACKUP_ID:-}"
  if [[ -z "$id" ]]; then
    id="$(list_backups | head -n1 || true)"
  fi
  [[ -n "$id" ]] || { err "No backups found in $BACKUP_DIR"; exit 1; }

  local bp="${BACKUP_DIR}/${id}"
  [[ -d "$bp" ]] || { err "Backup not found: $id"; exit 1; }

  warn "Rolling back using backup: $id"
  # Restore best-effort
  if [[ -d "$bp/sysctl.d" ]]; then
    rm -rf /etc/sysctl.d
    cp -a "$bp/sysctl.d" /etc/sysctl.d
  fi
  if [[ -d "$bp/systemd.system.conf.d" ]]; then
    rm -rf /etc/systemd/system.conf.d
    cp -a "$bp/systemd.system.conf.d" /etc/systemd/system.conf.d
  fi
  if [[ -d "$bp/security.limits.d" ]]; then
    rm -rf /etc/security/limits.d
    cp -a "$bp/security.limits.d" /etc/security/limits.d
  fi
  if [[ -f "$bp/sshd_config" ]]; then
    cp -a "$bp/sshd_config" /etc/ssh/sshd_config
  fi
  if [[ -f "$bp/ufw.default" ]]; then
    cp -a "$bp/ufw.default" /etc/default/ufw
  fi

  runq "sysctl --system" sysctl --system || true
  runq "systemd daemon-reexec" systemctl daemon-reexec || true
  runq "restart ssh/sshd" (systemctl restart ssh 2>/dev/null || systemctl restart sshd 2>/dev/null || true) || true

  # UFW: disable then enable to refresh rules (best-effort)
  if have_cmd ufw; then
    runq "ufw disable" ufw --force disable || true
    runq "ufw enable" ufw --force enable || true
  fi

  ok "Rollback done. Consider reboot if networking looks inconsistent."
}

status(){
  echo "=== vps-edge-run status ==="
  if [[ -f "$STAMP_FILE" ]]; then
    echo "Last apply:"
    cat "$STAMP_FILE" || true
  else
    echo "No apply stamp found: $STAMP_FILE"
  fi
  echo
  echo "Backups (latest first):"
  list_backups | sed 's/^/  - /' || true
  echo
  echo "Networking:"
  ip -br a || true
  echo
  echo "UFW:"
  if have_cmd ufw; then ufw status verbose || true; else echo "  ufw not installed"; fi
  echo
  echo "Tailscale:"
  if have_cmd tailscale; then (tailscale status || true); else echo "  tailscale not installed"; fi
}

# ---------------------- SYSTEM TUNING ----------------------
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

apply_perf_profile() {
  log "Network perf profile: BBR + fq (safe defaults)"
  install -m 0644 /dev/stdin /etc/sysctl.d/99-net-perf.conf <<'EOF_NETPERF'
net.core.default_qdisc = fq
net.ipv4.tcp_congestion_control = bbr

net.core.somaxconn = 8192
net.ipv4.tcp_max_syn_backlog = 8192
net.core.netdev_max_backlog = 16384

net.core.rmem_max = 134217728
net.core.wmem_max = 134217728
net.core.rmem_default = 262144
net.core.wmem_default = 262144
net.ipv4.tcp_rmem = 4096 262144 134217728
net.ipv4.tcp_wmem = 4096 262144 134217728
net.ipv4.udp_rmem_min = 8192
net.ipv4.udp_wmem_min = 8192
net.core.optmem_max = 65536

net.ipv4.tcp_mtu_probing = 1

net.ipv4.tcp_keepalive_time = 60
net.ipv4.tcp_keepalive_intvl = 10
net.ipv4.tcp_keepalive_probes = 6

net.ipv4.tcp_fin_timeout = 15
net.ipv4.tcp_tw_reuse = 1

net.ipv4.ip_local_port_range = 10240 65535

net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_rfc1337 = 1

net.ipv4.tcp_fastopen = 3
EOF_NETPERF

  runq "sysctl --system" sysctl --system || true

  # Apply fq qdisc immediately on main iface (best-effort)
  local IFACE=""
  IFACE="$(ip route get 1.1.1.1 2>/dev/null | awk '/dev/ {for(i=1;i<=NF;i++) if($i=="dev"){print $(i+1); exit}}' || true)"
  if [[ -n "${IFACE}" ]] && have_cmd tc; then
    runq "tc qdisc root fq on ${IFACE}" tc qdisc replace dev "${IFACE}" root fq || true
  fi

  ok "Perf profile applied"
}

apply_tailscale_sysctl() {
  log "Tailscale sysctl (forwarding + rp_filter relaxed)"
  install -m 0644 /dev/stdin /etc/sysctl.d/99-tailscale-forwarding.conf <<'EOF_SYSCTL'
net.ipv4.ip_forward=1
net.ipv6.conf.all.forwarding=1
net.ipv4.conf.all.rp_filter=0
net.ipv4.conf.default.rp_filter=0
EOF_SYSCTL
  runq "sysctl --system" sysctl --system || true

  local INTERNET_IFACE=""
  INTERNET_IFACE="$(ip route show default | awk '/default/ {print $5; exit}' || true)"
  if [[ -n "${INTERNET_IFACE:-}" ]] && have_cmd ethtool; then
    runq "ethtool gro on (${INTERNET_IFACE})" ethtool -K "${INTERNET_IFACE}" gro on || true
    runq "ethtool rx-udp-gro-forwarding on (${INTERNET_IFACE})" ethtool -K "${INTERNET_IFACE}" rx-udp-gro-forwarding on || true
  fi
  ok "Tailscale sysctl applied"
}

# ---------------------- APT HELPERS ----------------------
APT_LOG="/var/log/vps-edge-run-apt.log"
:> "$APT_LOG" || true

aptq() {
  local what="$1"; shift
  log "$what"
  if apt-get -y -qq -o Dpkg::Use-Pty=0 \
       -o Dpkg::Options::='--force-confdef' \
       -o Dpkg::Options::='--force-confold' \
       "$@" >>"$APT_LOG" 2>&1; then
    ok "$what"
  else
    err "$what failed. Tail:"
    tail -n 80 "$APT_LOG" || true
    echo "Full log: $APT_LOG"
    exit 1
  fi
}

# ---------------------- SSH HELPERS ----------------------
get_sshd_effective(){
  local key="$1"
  if [[ -f "$SSHD_CONFIG" ]]; then
    awk -v k="$key" '
      BEGIN{IGNORECASE=1; v=""}
      /^[[:space:]]*#/ {next}
      /^[[:space:]]*$/ {next}
      { if (tolower($1)==tolower(k) && NF>=2) v=$2 }
      END{ if (v=="") print "(unset)"; else print v }' "$SSHD_CONFIG"
  else
    echo "(no_config)"
  fi
}

restart_sshd(){
  systemctl restart ssh 2>/dev/null || systemctl restart sshd 2>/dev/null || true
}

apply_ssh_hardening(){
  log "SSH hardening: PasswordAuthentication no + PermitRootLogin no"
  if [[ ! -f "$SSHD_CONFIG" ]]; then
    warn "sshd_config not found — skip"
    return 0
  fi

  # Replace if exists (commented/uncommented), else append
  sed -i 's/^[[:space:]]*#\?[[:space:]]*PasswordAuthentication[[:space:]].*/PasswordAuthentication no/I' "$SSHD_CONFIG" || true
  sed -i 's/^[[:space:]]*#\?[[:space:]]*PermitRootLogin[[:space:]].*/PermitRootLogin no/I' "$SSHD_CONFIG" || true

  grep -qi '^[[:space:]]*PasswordAuthentication[[:space:]]' "$SSHD_CONFIG" || echo 'PasswordAuthentication no' >> "$SSHD_CONFIG"
  grep -qi '^[[:space:]]*PermitRootLogin[[:space:]]' "$SSHD_CONFIG" || echo 'PermitRootLogin no' >> "$SSHD_CONFIG"

  restart_sshd
  ok "SSH hardening applied"
}

# ---------------------- TAILSCALE HELPERS ----------------------
wait_tailscale_ipv4() {
  local timeout="${1:-60}"
  local t=0
  while (( t < timeout )); do
    local ip
    ip="$(tailscale ip -4 2>/dev/null | head -n1 || true)"
    if [[ -n "$ip" ]]; then
      echo "$ip"
      return 0
    fi
    sleep 2
    t=$((t+2))
  done
  return 1
}

install_or_fix_tailscale(){
  local TS_LOG="/var/log/install-tailscale.log"
  :> "$TS_LOG" || true

  if have_cmd tailscale; then
    ok "tailscale already installed"
  else
    log "Installing tailscale"
    runq "install tailscale" bash -lc "curl -fsSL https://tailscale.com/install.sh | sh >>'$TS_LOG' 2>&1"
  fi

  # Ensure service is enabled and running
  runq "enable tailscaled" systemctl enable --now tailscaled || true

  # Quick health check: tailscale0 should appear and ideally have IPv4 after auth
  if ip -4 addr show tailscale0 >/dev/null 2>&1; then
    ok "tailscale0 present"
  else
    warn "tailscale0 not present (tailscaled might be down) — restarting"
    runq "restart tailscaled" systemctl restart tailscaled || true
  fi
}

tailscale_up_interactive(){
  local TS_ARGS=(--ssh)
  if [[ "${TS_EXIT_NODE}" == "1" ]]; then
    TS_ARGS+=(--advertise-exit-node)
  fi

  log "Running: tailscale up ${TS_ARGS[*]}"
  set +e
  tailscale up "${TS_ARGS[@]}" | tee /tmp/tailscale-up.log
  local rc="${PIPESTATUS[0]}"
  set -e

  # Extract auth URL
  local url=""
  url="$(grep -Eo 'https://login\.tailscale\.com/[a-zA-Z0-9/_-]+' /tmp/tailscale-up.log | head -n1 || true)"
  if [[ -n "$url" ]]; then
    echo
    echo "To authenticate, visit:"
    echo
    echo "        $url"
    echo
    read_tty _ "Press Enter after authorizing this device in Tailscale… "
  else
    # If already authenticated, url may be absent
    warn "AuthURL not found in tailscale output (maybe already authorized)"
  fi

  # Wait for IPv4
  if TS_IP="$(wait_tailscale_ipv4 "${TS_WAIT_SEC}")"; then
    ok "Tailscale IPv4: ${TS_IP}"
  else
    warn "Tailscale IPv4 did not appear within ${TS_WAIT_SEC}s"
    TS_IP=""
  fi

  return "$rc"
}

# ---------------------- DNS SWITCHER ----------------------
install_dns_switcher(){
  # We keep it optional; repo script style can change, so best-effort.
  log "Installing dns-switcher (optional)"
  if [[ -d /opt/dns-switcher ]]; then
    ok "dns-switcher already present at /opt/dns-switcher"
  else
    runq "clone dns-switcher" git clone --depth 1 https://github.com/AndreyTimoschuk/dns-switcher /opt/dns-switcher || true
  fi

  if [[ -x /opt/dns-switcher/install.sh ]]; then
    runq "dns-switcher install" bash -lc "/opt/dns-switcher/install.sh --yes" || true
  else
    warn "dns-switcher install.sh not found — skip install step"
  fi

  # Try apply profile if helper exists
  if have_cmd dns-switcher; then
    runq "dns-switcher profile ${DNS_PROFILE}" bash -lc "dns-switcher -y profile ${DNS_PROFILE}" || true
  else
    warn "dns-switcher command not found — skip apply profile"
  fi
}

# ---------------------- DOCKER ----------------------
install_docker(){
  log "Docker"
  local DOCKER_LOG="/var/log/install-docker.log"
  :> "$DOCKER_LOG" || true

  if have_cmd docker; then
    ok "Docker already installed"
    runq "enable docker" systemctl enable --now docker || true
    return 0
  fi

  runq "rm old docker keyring" rm -f /usr/share/keyrings/docker-archive-keyring.gpg || true
  runq "install docker gpg key" bash -lc "curl -fsSL https://download.docker.com/linux/ubuntu/gpg | gpg --batch --yes --dearmor -o /usr/share/keyrings/docker-archive-keyring.gpg >>'$DOCKER_LOG' 2>&1"
  echo "deb [arch=$(dpkg --print-architecture) signed-by=/usr/share/keyrings/docker-archive-keyring.gpg] https://download.docker.com/linux/ubuntu $(lsb_release -cs) stable" \
    > /etc/apt/sources.list.d/docker.list

  aptq "APT update (docker)" update
  aptq "Install Docker CE" install docker-ce docker-ce-cli containerd.io docker-compose-plugin
  runq "enable docker" systemctl enable --now docker
  ok "Docker installed"
}

# ---------------------- USER + SHELL ----------------------
ensure_user(){
  log "User setup"
  if [[ -z "${USER_NAME}" ]]; then
    read_tty USER_NAME "Enter admin username to create/use (e.g. akadorkin): "
  fi
  [[ -n "${USER_NAME}" ]] || { err "user is empty"; exit 1; }

  local HOME_DIR="/home/${USER_NAME}"
  if id -u "${USER_NAME}" >/dev/null 2>&1; then
    ok "User ${USER_NAME} exists"
  else
    runq "useradd ${USER_NAME}" useradd -m -s /usr/bin/zsh "${USER_NAME}"
    ok "User ${USER_NAME} created"
  fi

  runq "add ${USER_NAME} to sudo,docker" usermod -aG sudo,docker "${USER_NAME}" || true
  install -m 0440 /dev/stdin "/etc/sudoers.d/${USER_NAME}" <<EOF_SUDO
${USER_NAME} ALL=(ALL) NOPASSWD:ALL
EOF_SUDO

  # Ensure zsh in /etc/shells
  grep -q '^/usr/bin/zsh$' /etc/shells || echo '/usr/bin/zsh' >> /etc/shells

  # Copy authorized_keys from root/ubuntu if present
  mkdir -p "${HOME_DIR}/.ssh"
  chmod 700 "${HOME_DIR}/.ssh"
  local AUTH_SRC=""
  if [[ -f /root/.ssh/authorized_keys && -s /root/.ssh/authorized_keys ]]; then
    AUTH_SRC="/root/.ssh/authorized_keys"
  elif [[ -f /home/ubuntu/.ssh/authorized_keys && -s /home/ubuntu/.ssh/authorized_keys ]]; then
    AUTH_SRC="/home/ubuntu/.ssh/authorized_keys"
  fi
  if [[ -n "$AUTH_SRC" ]]; then
    install -m 0600 "$AUTH_SRC" "${HOME_DIR}/.ssh/authorized_keys"
    chown -R "${USER_NAME}:${USER_NAME}" "${HOME_DIR}/.ssh"
    ok "authorized_keys copied from ${AUTH_SRC}"
  else
    warn "authorized_keys not found for root/ubuntu — ${USER_NAME} may be unreachable via SSH until you add keys"
  fi
}

# ---------------------- ZSH (best-effort) ----------------------
setup_zsh_stack(){
  local U="$1"
  local HOME_DIR="/home/${U}"
  [[ "$U" == "root" ]] && HOME_DIR="/root"

  log "Zsh stack for ${U} (best-effort)"
  if [[ "$U" != "root" ]]; then
    runq "chsh zsh (${U})" chsh -s /usr/bin/zsh "${U}" || true
  else
    chsh -s /usr/bin/zsh root || true
  fi

  # oh-my-zsh
  if [[ ! -d "${HOME_DIR}/.oh-my-zsh" ]]; then
    if [[ "$U" == "root" ]]; then
      RUNZSH=no KEEP_ZSHRC=yes CHSH=no sh -c "$(curl -fsSL https://raw.githubusercontent.com/ohmyzsh/ohmyzsh/master/tools/install.sh)" >/dev/null 2>&1 || true
    else
      su - "$U" -c 'RUNZSH=no KEEP_ZSHRC=yes CHSH=no sh -c "$(curl -fsSL https://raw.githubusercontent.com/ohmyzsh/ohmyzsh/master/tools/install.sh)"' >/dev/null 2>&1 || true
    fi
  fi

  # Fetch .zshrc and .p10k if you host them; skip on failure
  if [[ "$U" == "root" ]]; then
    curl -fsSL "https://kadorkin.io/zshrc" -o "${HOME_DIR}/.zshrc" >/dev/null 2>&1 || true
    curl -fsSL "https://kadorkin.io/p10k"  -o "${HOME_DIR}/.p10k.zsh" >/dev/null 2>&1 || true
    chown root:root "${HOME_DIR}/.zshrc" "${HOME_DIR}/.p10k.zsh" 2>/dev/null || true
  else
    curl -fsSL "https://kadorkin.io/zshrc" -o "${HOME_DIR}/.zshrc" >/dev/null 2>&1 || true
    curl -fsSL "https://kadorkin.io/p10k"  -o "${HOME_DIR}/.p10k.zsh" >/dev/null 2>&1 || true
    chown "${U}:${U}" "${HOME_DIR}/.zshrc" "${HOME_DIR}/.p10k.zsh" 2>/dev/null || true
  fi

  # Disable OMZ update prompts if zshrc exists
  for zrc in "${HOME_DIR}/.zshrc"; do
    [[ -f "$zrc" ]] || continue
    grep -q 'DISABLE_AUTO_UPDATE' "$zrc" 2>/dev/null || echo 'DISABLE_AUTO_UPDATE="true"' >> "$zrc"
    grep -q 'DISABLE_UPDATE_PROMPT' "$zrc" 2>/dev/null || echo 'DISABLE_UPDATE_PROMPT=true' >> "$zrc"
    grep -q ":omz:update" "$zrc" 2>/dev/null || echo "zstyle ':omz:update' mode disabled" >> "$zrc"
  done

  ok "Zsh stack done for ${U}"
}

# ---------------------- NODE EXPORTER (optional) ----------------------
install_node_exporter(){
  log "Node exporter (hteppl/sh) — optional"
  runq "node_install.sh" bash -lc 'curl -fsSL https://raw.githubusercontent.com/hteppl/sh/master/node_install.sh | bash' || true
  ok "Node exporter step done (best-effort)"
}

# ---------------------- IPERF3 SERVICE (optional) ----------------------
enable_iperf_service(){
  log "iperf3 systemd service"
  if ! have_cmd iperf3; then
    warn "iperf3 not installed — skipping service"
    return 0
  fi
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
  ok "iperf3 service enabled"
}

# ---------------------- BESZEL AGENT (optional) ----------------------
run_beszel_agent(){
  log "beszel-agent (docker) — optional"
  if ! have_cmd docker; then
    warn "docker not available — skip beszel-agent"
    return 0
  fi
  docker rm -f beszel-agent >/dev/null 2>&1 || true
  docker run -d --name beszel-agent --network host --restart unless-stopped \
    -v /var/run/docker.sock:/var/run/docker.sock:ro \
    -e KEY="ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOPI8y7VUFSVVRBd4/zfcZF2G9m/Gn3fwDGlB5i/g4Pb" \
    -e LISTEN=45876 henrygd/beszel-agent:latest >/dev/null 2>&1 || true
  ok "beszel-agent started (best-effort)"
}

# ---------------------- REMNANODE ----------------------
ensure_remnanode_compose(){
  local REMNA_DIR="/opt/remnanode"
  local REMNA_COMPOSE="${REMNA_DIR}/docker-compose.yml"

  if [[ -f "${REMNA_COMPOSE}" ]]; then
    ok "Remnanode compose exists: ${REMNA_COMPOSE} (will reuse)"
    return 0
  fi

  if [[ "${REMNANODE}" != "1" ]]; then
    warn "Remnanode compose missing but --remnanode=0 — skipping"
    return 0
  fi

  log "Remnanode compose missing → asking parameters"
  read_tty NODE_PORT "Enter NODE_PORT for remnanode (default 2222): "
  [[ -n "${NODE_PORT}" ]] || NODE_PORT="2222"
  read_tty_silent SECRET_KEY "Paste SECRET_KEY (hidden): "
  if [[ -z "${SECRET_KEY}" ]]; then
    err "SECRET_KEY empty — cannot create compose"
    return 1
  fi

  mkdir -p "${REMNA_DIR}"
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
      - NODE_PORT=${NODE_PORT}
      - SECRET_KEY=${SECRET_KEY}
EOF_DC
  ok "Created: ${REMNA_COMPOSE}"
}

start_remnanode(){
  local REMNA_DIR="/opt/remnanode"
  local REMNA_COMPOSE="${REMNA_DIR}/docker-compose.yml"
  if [[ -f "${REMNA_COMPOSE}" ]]; then
    log "Starting remnanode (docker compose up -d)"
    runq "remnanode up" bash -lc "cd '${REMNA_DIR}' && docker compose up -d"
    ok "Remnanode started"
  else
    warn "Remnanode compose not found — skip start"
  fi
}

# ---------------------- FIREWALL (UFW) ----------------------
detect_internet_iface(){
  local iface=""
  iface="$(ip route get 8.8.8.8 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="dev") print $(i+1)}' | head -n1 || true)"
  [[ -n "$iface" ]] || iface="$(ip route | awk '/default/ {for(i=1;i<=NF;i++) if($i=="dev") print $(i+1)}' | head -n1 || true)"
  echo "$iface"
}

apply_ufw(){
  log "Configuring UFW (safe mode)"
  if ! have_cmd ufw; then
    aptq "Install UFW" install ufw
  fi

  # Ensure forward policy ACCEPT for docker/tailscale routing
  if [[ -f /etc/default/ufw ]]; then
    if grep -q '^DEFAULT_FORWARD_POLICY=' /etc/default/ufw; then
      sed -i 's/^DEFAULT_FORWARD_POLICY=.*/DEFAULT_FORWARD_POLICY="ACCEPT"/' /etc/default/ufw || true
    else
      echo 'DEFAULT_FORWARD_POLICY="ACCEPT"' >> /etc/default/ufw
    fi
  fi

  local INTERNET_IFACE
  INTERNET_IFACE="$(detect_internet_iface)"
  if [[ -z "${INTERNET_IFACE}" ]]; then
    err "Failed to detect INTERNET_IFACE — aborting UFW setup"
    return 1
  fi
  ok "WAN interface: ${INTERNET_IFACE}"

  # If we plan to live with WAN SSH closed, require tailscale IPv4 first
  if [[ "${TAILSCALE_ONLY}" == "1" && "${WAN_SSH}" != "1" ]]; then
    if [[ -z "${TS_IP:-}" ]]; then
      err "TAILSCALE_ONLY=1 and WAN_SSH=0 but Tailscale IPv4 is empty."
      err "Refusing to enable UFW to avoid lockout. Fix tailscale and rerun."
      return 1
    fi
  fi

  ufw --force reset >/dev/null 2>&1 || true
  ufw default deny incoming >/dev/null 2>&1 || true
  ufw default allow outgoing >/dev/null 2>&1 || true

  # Failsafe WAN SSH
  if [[ "${WAN_SSH}" == "1" ]]; then
    log "FAILSAFE: allow WAN SSH 22/tcp on ${INTERNET_IFACE}"
    ufw allow in on "${INTERNET_IFACE}" to any port 22 proto tcp >/dev/null 2>&1 || true
  fi

  # WAN ports
  if [[ "${OPEN_WAN_443}" == "1" ]]; then
    log "Allow WAN 443/tcp+udp"
    ufw allow in on "${INTERNET_IFACE}" to any port 443 proto tcp >/dev/null 2>&1 || true
    ufw allow in on "${INTERNET_IFACE}" to any port 443 proto udp >/dev/null 2>&1 || true
  fi
  if [[ "${OPEN_WAN_80}" == "1" ]]; then
    log "Allow WAN 80/tcp"
    ufw allow in on "${INTERNET_IFACE}" to any port 80 proto tcp >/dev/null 2>&1 || true
  fi

  # Tailscale interface allow all
  ufw allow in on tailscale0 >/dev/null 2>&1 || true
  ufw allow out on tailscale0 >/dev/null 2>&1 || true

  # Docker bridges allow all
  local DOCKER_IFACES
  DOCKER_IFACES="$(ip -o link show | awk -F': ' '$2 ~ /^(docker0|br-)/ {print $2}' || true)"
  if [[ -n "${DOCKER_IFACES}" ]]; then
    for IFACE in ${DOCKER_IFACES}; do
      ufw allow in on "${IFACE}" >/dev/null 2>&1 || true
      ufw allow out on "${IFACE}" >/dev/null 2>&1 || true
    done
  fi

  # Make sure UFW is enabled on reboot
  install -m 0644 /dev/stdin /etc/cron.d/enable-ufw <<'EOF'
@reboot root ufw --force enable && ufw reload
EOF

  ufw --force enable >/dev/null 2>&1 || true
  ok "UFW enabled"
}

# ---------------------- NETTEST (optional) ----------------------
run_nettest(){
  log "NETTEST: iperf3_tesla.sh"
  local NETTEST_LOG="/var/log/nettest.pw.log"
  :> "$NETTEST_LOG" || true
  if wget -qO- http://nettest.pw/iperf3_tesla.sh | bash >>"$NETTEST_LOG" 2>&1; then
    ok "NETTEST ok (log: $NETTEST_LOG)"
  else
    warn "NETTEST failed (log: $NETTEST_LOG)"
    tail -n 80 "$NETTEST_LOG" || true
  fi
}

# ---------------------- APPLY ----------------------
apply(){
  require_root
  mkdir_state
  parse_args "$@"

  log "Params: user='${USER_NAME:-<ask>}' tz='${TIMEZONE}' reboot='${REBOOT_DELAY}' tailscale='${TAILSCALE}' tailscale_only='${TAILSCALE_ONLY}' wan_ssh='${WAN_SSH}' ssh_harden='${SSH_HARDEN}' remnanode='${REMNANODE}'"
  make_backup

  # Timezone
  log "Timezone → ${TIMEZONE}"
  runq "timedatectl set-timezone" timedatectl set-timezone "${TIMEZONE}" || true
  ok "Timezone set"

  # Base packages
  aptq "APT update" update
  aptq "APT upgrade" upgrade
  aptq "Install base packages" install \
    zsh git curl wget ca-certificates gnupg lsb-release apt-transport-https \
    iproute2 ufw htop mc cron ed openssl logrotate jq iperf3 ethtool tc

  runq "enable cron" systemctl enable --now cron >/dev/null 2>&1 || true

  # Tuning
  apply_fd_limits
  apply_perf_profile

  # Docker
  install_docker

  # User
  ensure_user
  setup_zsh_stack "${USER_NAME}"
  setup_zsh_stack "root"

  # Optional exporters
  if [[ "${INSTALL_NODE_EXPORTER}" == "1" ]]; then
    install_node_exporter
  fi
  if [[ "${IPERF_SERVICE}" == "1" ]]; then
    enable_iperf_service
  fi
  if [[ "${BESZEL_AGENT}" == "1" ]]; then
    run_beszel_agent
  fi

  # DNS switcher optional
  if [[ "${DNS_SWITCHER}" == "1" ]]; then
    install_dns_switcher
  fi

  # Remnanode
  if [[ "${REMNANODE}" == "1" ]]; then
    ensure_remnanode_compose
  fi

  # Tailscale early-ish
  TS_IP=""
  if [[ "${TAILSCALE}" == "1" ]]; then
    log "🧠 Tailscale (early)"
    apply_tailscale_sysctl
    install_or_fix_tailscale
    tailscale_up_interactive || true
  else
    warn "tailscale=0 — skipping"
  fi

  # SSH harden
  if [[ "${SSH_HARDEN}" == "1" ]]; then
    apply_ssh_hardening
  else
    warn "ssh_harden=0 — skipping"
  fi

  # UFW last: avoid lockout
  apply_ufw

  # Start remnanode after firewall (safe if using host network and 443 is open as needed)
  start_remnanode

  # NETTEST at end if requested
  if [[ "${NETTEST}" == "1" ]]; then
    run_nettest
  else
    ok "NETTEST=0 — skip"
  fi

  aptq "Autoremove" autoremove --purge

  # Safety before reboot: if WAN_SSH=0 and tailscale missing, cancel reboot
  if [[ "${WAN_SSH}" != "1" ]]; then
    if ! have_cmd tailscale; then
      warn "WAN_SSH=0 but tailscale not installed — forcing reboot=skip"
      REBOOT_DELAY="skip"
    elif [[ -z "${TS_IP:-}" ]]; then
      warn "WAN_SSH=0 but Tailscale IP empty — forcing reboot=skip"
      REBOOT_DELAY="skip"
    fi
  fi

  # Final summary
  echo
  echo "==================== SUMMARY ===================="
  echo "Backup ID:           ${backup_id}"
  echo "APT log:             ${APT_LOG}"
  echo "Docker log:          /var/log/install-docker.log"
  echo "Tailscale log:       /var/log/install-tailscale.log"
  echo "Timezone:            ${TIMEZONE}"
  echo "User:                ${USER_NAME}"
  echo "UFW:                 $(have_cmd ufw && ufw status | head -n1 || echo 'not installed')"
  echo "Tailscale IPv4:      ${TS_IP:-<none>}"
  echo "SSH effective:"
  echo "  - Port:            ${SSH_PORT}"
  echo "  - PasswordAuth:    $(get_sshd_effective PasswordAuthentication)"
  echo "  - PermitRootLogin: $(get_sshd_effective PermitRootLogin)"
  echo "FD/perf:"
  echo "  - fs.file-max:     $(cat /proc/sys/fs/file-max 2>/dev/null || echo 'n/a')"
  echo "  - fs.nr_open:      $(cat /proc/sys/fs/nr_open 2>/dev/null || echo 'n/a')"
  echo "  - systemd NOFILE:  $(systemctl show --property=DefaultLimitNOFILE 2>/dev/null | cut -d= -f2 || echo 'n/a')"
  echo "================================================="
  echo

  # Reboot
  case "${REBOOT_DELAY}" in
    0|no|none|skip|"")
      warn "Reboot skipped (--reboot=${REBOOT_DELAY})"
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
      warn "Reboot in ${REBOOT_DELAY}"
      shutdown -r +"${REBOOT_DELAY}" >/dev/null 2>&1 || shutdown -r now
      ;;
  esac
}

# ---------------------- MAIN ----------------------
case "${CMD}" in
  apply) apply "$@" ;;
  rollback) rollback ;;
  status) status ;;
  *) usage; exit 1 ;;
esac
