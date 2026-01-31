#!/usr/bin/env bash
set -euo pipefail

# remnanode-install.sh
# Iteration #3 (updated):
# - NO Docker installation here (assumes Docker + compose plugin already present)
# - Create /opt/remnanode/docker-compose.yml if missing
# - Ask NODE_PORT (default 2222) + SECRET_KEY (silent)
# - docker compose up -d
# - Setup logrotate for /var/log/remnanode/*.log
#
# Idempotent:
# - If compose exists → not overwritten
# - logrotate config safely overwritten

# ------------- OUTPUT HELPERS -------------
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

require_root(){ [[ ${EUID:-$(id -u)} -eq 0 ]] || { err "Run as root"; exit 1; }; }
read_tty(){ local __var="$1" __prompt="$2" __v=""; read -rp "$__prompt" __v </dev/tty || true; printf -v "$__var" '%s' "$__v"; }
read_tty_silent(){
  local __var="$1" __prompt="$2" __v=""
  read -rsp "$__prompt" __v </dev/tty || true
  echo >/dev/tty || true
  printf -v "$__var" '%s' "$__v"
}

require_root
export DEBIAN_FRONTEND=noninteractive

REMNA_DIR="/opt/remnanode"
REMNA_COMPOSE="${REMNA_DIR}/docker-compose.yml"
LOG_DIR="/var/log/remnanode"
LOGROTATE_CFG="/etc/logrotate.d/remnanode"

# ------------- Preconditions -------------
check_prereqs() {
  log "Checking prerequisites (docker + compose plugin)"

  if ! command -v docker >/dev/null 2>&1; then
    err "docker not found. Install Docker first (use apt-bootstrap.sh)."
    exit 1
  fi

  # Accept both `docker compose` (plugin) and legacy `docker-compose` if you ever need it
  if docker compose version >/dev/null 2>&1; then
    ok "docker compose plugin available"
  elif command -v docker-compose >/dev/null 2>&1; then
    warn "docker compose plugin not found, but docker-compose exists. Script uses: docker compose"
    err "Please install docker-compose-plugin (recommended) or adapt the script."
    exit 1
  else
    err "docker compose not available. Install docker-compose-plugin."
    exit 1
  fi
}

# ------------- Remnanode compose -------------
create_compose_if_missing() {
  if [[ -f "$REMNA_COMPOSE" ]]; then
    ok "remnanode compose exists — ${REMNA_COMPOSE}"
    return 0
  fi

  log "Creating remnanode compose"

  local NODE_PORT SECRET_KEY
  read_tty NODE_PORT "Enter NODE_PORT (default 2222): "
  [[ -n "$NODE_PORT" ]] || NODE_PORT="2222"

  read_tty_silent SECRET_KEY "Paste SECRET_KEY (input hidden): "
  [[ -n "$SECRET_KEY" ]] || { err "SECRET_KEY is empty"; exit 1; }

  runq "mkdir ${REMNA_DIR}" mkdir -p "$REMNA_DIR"

  install -m 0644 /dev/stdin "$REMNA_COMPOSE" <<EOF
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
EOF

  ok "Created ${REMNA_COMPOSE}"
}

# ------------- Logrotate -------------
setup_logrotate() {
  log "Setting up logrotate for remnanode"

  if ! command -v logrotate >/dev/null 2>&1; then
    err "logrotate not found. Install it via apt-bootstrap.sh (or: apt install logrotate)."
    exit 1
  fi

  runq "mkdir ${LOG_DIR}" mkdir -p "$LOG_DIR"
  chmod 755 "$LOG_DIR"

  install -m 0644 /dev/stdin "$LOGROTATE_CFG" <<'EOF'
/var/log/remnanode/*.log {
    size 50M
    rotate 5
    compress
    missingok
    notifempty
    copytruncate
}
EOF

  # Dry-run + force run for validation (safe)
  runq "logrotate test" logrotate -vf "$LOGROTATE_CFG"

  ok "logrotate configured (${LOGROTATE_CFG})"
}

# ------------- Bring up container -------------
bring_up() {
  log "Starting remnanode (docker compose up -d)"
  runq "docker compose up -d" bash -lc "cd '$REMNA_DIR' && docker compose up -d"

  echo
  docker ps --filter "name=remnanode" --format "table {{.Names}}\t{{.Image}}\t{{.Status}}" || true
}

# ------------- MAIN -------------
log "Iteration #3: remnanode install (no docker install)"

check_prereqs
create_compose_if_missing
setup_logrotate
bring_up

echo
ok "Done."
echo "Artifacts:"
echo "  • Compose:    $REMNA_COMPOSE"
echo "  • Logrotate:  $LOGROTATE_CFG"
