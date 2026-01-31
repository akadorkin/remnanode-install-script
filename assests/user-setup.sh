#!/usr/bin/env bash
set -euo pipefail

# -----------------------------------------------------------------------------
# assets/user-setup.sh
#
# Purpose:
#   - Create/ensure a user
#   - Generate password ONLY for new user (print once)
#   - Grant sudo NOPASSWD (optional)
#   - Add to docker group (optional)
#   - Copy authorized_keys from root or ubuntu
#   - Grant rw access to /opt via ACL
#
# NOTE: Provided "AS IS", without any warranties. Use at your own risk.
# -----------------------------------------------------------------------------

LOG_FILE="${LOG_FILE:-/var/log/edge-user-setup.log}"

USER_NAME="${USER_NAME:-}"
ADD_NOPASSWD="${ADD_NOPASSWD:-1}"
ADD_DOCKER_GROUP="${ADD_DOCKER_GROUP:-1}"
COPY_SSH_KEYS="${COPY_SSH_KEYS:-1}"

# Output helpers
ts() { date '+%F %T'; }
log() { echo "$(ts) $*" | tee -a "$LOG_FILE"; }
die() { log "ERROR: $*"; exit 1; }

require_root() { [[ ${EUID:-$(id -u)} -eq 0 ]] || die "Run as root"; }

read_tty() {
  local __var="$1" __prompt="$2" __v=""
  if [[ -t 0 ]]; then
    read -rp "$__prompt" __v </dev/tty || true
  fi
  printf -v "$__var" '%s' "$__v"
}

usage() {
  cat <<'EOF'
Usage:
  sudo bash user-setup.sh --user <name> [flags]

Flags:
  --user <name>         Username to create/ensure
  --no-nopasswd         Do not grant passwordless sudo
  --no-docker-group     Do not add user to docker group
  --no-copy-ssh         Do not copy authorized_keys from root/ubuntu

Env overrides:
  USER_NAME=<name>
  ADD_NOPASSWD=1|0
  ADD_DOCKER_GROUP=1|0
  COPY_SSH_KEYS=1|0
EOF
}

# Parse args
while [[ $# -gt 0 ]]; do
  case "$1" in
    --user=*) USER_NAME="${1#*=}"; shift ;;
    --user) USER_NAME="${2:-}"; shift 2 ;;
    --no-nopasswd) ADD_NOPASSWD="0"; shift ;;
    --no-docker-group) ADD_DOCKER_GROUP="0"; shift ;;
    --no-copy-ssh) COPY_SSH_KEYS="0"; shift ;;
    -h|--help|help) usage; exit 0 ;;
    *) die "Unknown arg: $1" ;;
  esac
done

USER_CREATED="0"
USER_PASSWORD="(unchanged)"

ensure_user() {
  local uname="$1"
  [[ -n "$uname" ]] || die "USER_NAME is empty"

  if [[ -x /usr/bin/zsh ]]; then
    grep -q '^/usr/bin/zsh$' /etc/shells 2>/dev/null || echo '/usr/bin/zsh' >> /etc/shells
  fi

  if id -u "$uname" >/dev/null 2>&1; then
    log "User exists: ${uname}"
    USER_CREATED="0"
    USER_PASSWORD="(unchanged)"
    return 0
  fi

  log "Creating user: ${uname}"
  useradd -m -s /usr/bin/zsh "$uname" >>"$LOG_FILE" 2>&1 || die "useradd failed"

  USER_PASSWORD="$(openssl rand -base64 16 | tr -d '\n' | head -c 20)"
  [[ -n "$USER_PASSWORD" ]] || USER_PASSWORD="ChangeMe-$(date +%s)"

  echo "${uname}:${USER_PASSWORD}" | chpasswd >>"$LOG_FILE" 2>&1 || die "chpasswd failed"

  USER_CREATED="1"
  log "User created: ${uname}"
}

ensure_groups() {
  local uname="$1"

  if [[ "${ADD_DOCKER_GROUP}" == "1" ]]; then
    getent group docker >/dev/null 2>&1 || groupadd docker || true
    usermod -aG docker "$uname" >>"$LOG_FILE" 2>&1 || true
    log "Added ${uname} to docker group"
  fi

  if getent group sudo >/dev/null 2>&1; then
    usermod -aG sudo "$uname" >>"$LOG_FILE" 2>&1 || true
    log "Added ${uname} to sudo group"
  fi
}

ensure_nopasswd_sudo() {
  local uname="$1"
  [[ "${ADD_NOPASSWD}" == "1" ]] || { log "NOPASSWD sudo disabled"; return 0; }

  install -m 0440 /dev/stdin "/etc/sudoers.d/${uname}" <<EOF
${uname} ALL=(ALL) NOPASSWD:ALL
EOF
  log "Granted NOPASSWD sudo"
}

copy_authorized_keys() {
  local uname="$1"
  local home="/home/${uname}"
  [[ "${COPY_SSH_KEYS}" == "1" ]] || { log "SSH key copy disabled"; return 0; }

  local src=""
  [[ -s /root/.ssh/authorized_keys ]] && src="/root/.ssh/authorized_keys"
  [[ -z "$src" && -s /home/ubuntu/.ssh/authorized_keys ]] && src="/home/ubuntu/.ssh/authorized_keys"

  mkdir -p "${home}/.ssh"
  chmod 700 "${home}/.ssh"

  if [[ -n "$src" ]]; then
    install -m 0600 "$src" "${home}/.ssh/authorized_keys"
    chown -R "${uname}:${uname}" "${home}/.ssh"
    log "Copied SSH keys from ${src}"
  else
    log "No SSH keys found to copy"
  fi
}

grant_opt_access() {
  local uname="$1"

  if ! command -v setfacl >/dev/null 2>&1; then
    log "Installing acl package"
    apt-get -y -qq install acl >>"$LOG_FILE" 2>&1 || true
  fi

  log "Granting rw access to /opt for ${uname} via ACL"

  # existing files
  setfacl -R -m "u:${uname}:rwX" /opt 2>>"$LOG_FILE" || true
  # default ACL for new files/dirs
  setfacl -R -d -m "u:${uname}:rwX" /opt 2>>"$LOG_FILE" || true
}

main() {
  require_root
  : >"$LOG_FILE"

  log "Starting user setup"

  [[ -n "$USER_NAME" ]] || read_tty USER_NAME "Enter username: "
  [[ -n "$USER_NAME" ]] || die "USER_NAME is empty"

  ensure_user "$USER_NAME"
  ensure_groups "$USER_NAME"
  ensure_nopasswd_sudo "$USER_NAME"
  copy_authorized_keys "$USER_NAME"
  grant_opt_access "$USER_NAME"

  echo
  echo "================ USER SUMMARY ================"
  echo "User:     ${USER_NAME}"
  if [[ "${USER_CREATED}" == "1" ]]; then
    echo "Password: ${USER_PASSWORD}"
  else
    echo "Password: (unchanged)"
  fi
  echo "Sudo:     $([[ "${ADD_NOPASSWD}" == "1" ]] && echo "NOPASSWD" || echo "standard")"
  echo "Docker:   $([[ "${ADD_DOCKER_GROUP}" == "1" ]] && echo "added" || echo "skip")"
  echo "SSH keys: $([[ "${COPY_SSH_KEYS}" == "1" ]] && echo "copied if present" || echo "skip")"
  echo "/opt:     rw access via ACL"
  echo "Log:      ${LOG_FILE}"
  echo "=============================================="
  echo

  log "Done."
}

main "$@"
