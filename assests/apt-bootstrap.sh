#!/usr/bin/env bash
set -euo pipefail

# -----------------------------------------------------------------------------
# assets/apt-bootstrap.sh
#
# Purpose:
#   - Update/upgrade packages (non-interactive)
#   - Install a baseline package set (must-have on any server)
#   - Install Docker CE + docker compose plugin (Ubuntu, official repo)
#   - Autoremove/purge unused deps
#   - Remove old kernel packages (keeping the currently running kernel)
#
# NOTE: Provided "AS IS", without any warranties. Use at your own risk.
# -----------------------------------------------------------------------------

LOG_FILE="${LOG_FILE:-/var/log/edge-apt-bootstrap.log}"

# Baseline packages (adjust as you like)
PKGS=(
  zsh git curl wget ca-certificates gnupg lsb-release apt-transport-https
  iproute2 ufw htop mc cron ed openssl logrotate jq iperf3 ethtool
)

ts() { date '+%F %T'; }
log() { echo "$(ts) $*" | tee -a "$LOG_FILE"; }
die() { log "ERROR: $*"; exit 1; }

require_root() { [[ ${EUID:-$(id -u)} -eq 0 ]] || die "Run as root"; }

apt_quiet() {
  # Usage: apt_quiet "Human readable title" <apt-get args...>
  local title="$1"; shift
  log "==> ${title}"
  if apt-get -y -qq -o Dpkg::Use-Pty=0 \
       -o Dpkg::Options::='--force-confdef' \
       -o Dpkg::Options::='--force-confold' \
       "$@" >>"$LOG_FILE" 2>&1; then
    log "OK  ${title}"
  else
    log "FAIL ${title}"
    log "---- last 120 lines of log ----"
    tail -n 120 "$LOG_FILE" | sed 's/^/    /' || true
    exit 1
  fi
}

remove_old_kernels() {
  # Remove linux-image-* / linux-headers-* packages that are NOT for the running kernel.
  # Conservative: keeps current kernel and does not touch meta packages (linux-generic, etc.).
  log "==> Removing old kernels (keeping current running kernel)"

  local current_ver current_rel
  current_ver="$(uname -r)"             # e.g. 6.5.0-26-generic
  current_rel="${current_ver%-generic}" # e.g. 6.5.0-26 (best-effort)
  log "Running kernel: ${current_ver}"

  mapfile -t candidates < <(
    dpkg-query -W -f='${Package}\n' 2>/dev/null \
      | grep -E '^(linux-image|linux-headers)-[0-9].*-(generic|lowlatency)$' || true
  )

  if [[ ${#candidates[@]} -eq 0 ]]; then
    log "No kernel image/header packages found matching expected patterns — skipping."
    return 0
  fi

  local to_purge=()
  local p
  for p in "${candidates[@]}"; do
    # Keep anything that contains the running release string
    if grep -qF -- "${current_rel}" <<<"$p"; then
      continue
    fi
    # Extra safety: never purge meta packages
    if [[ "$p" == "linux-image-generic" || "$p" == "linux-headers-generic" ]]; then
      continue
    fi
    to_purge+=("$p")
  done

  if [[ ${#to_purge[@]} -eq 0 ]]; then
    log "No old kernel packages to remove (only current kernel present)."
    return 0
  fi

  log "Kernel packages to purge (${#to_purge[@]}):"
  printf '%s\n' "${to_purge[@]}" | sed 's/^/  - /' | tee -a "$LOG_FILE"

  apt_quiet "Purge old kernel packages" purge --autoremove "${to_purge[@]}"

  if command -v update-grub >/dev/null 2>&1; then
    log "==> update-grub"
    update-grub >>"$LOG_FILE" 2>&1 || true
  fi

  log "OK  Old kernels removed"
}

detect_ubuntu_codename() {
  local codename=""
  if [[ -r /etc/os-release ]]; then
    # shellcheck disable=SC1091
    . /etc/os-release
    codename="${VERSION_CODENAME:-}"
  fi
  echo "$codename"
}

install_docker_ubuntu() {
  # Installs Docker CE + compose plugin from official Docker repo (Ubuntu).
  # If docker already exists → skip.
  if command -v docker >/dev/null 2>&1; then
    log "OK  Docker already installed — skipping"
    return 0
  fi

  local codename arch
  codename="$(detect_ubuntu_codename)"
  arch="$(dpkg --print-architecture 2>/dev/null || true)"

  if [[ -z "$codename" ]]; then
    die "Cannot detect Ubuntu codename (VERSION_CODENAME). Docker install expects Ubuntu."
  fi
  if [[ -z "$arch" ]]; then
    die "Cannot detect dpkg architecture. Docker install aborted."
  fi

  log "==> Installing Docker CE (official repo): ubuntu ${codename}, arch ${arch}"

  apt_quiet "Install Docker repo deps" install ca-certificates curl gnupg

  mkdir -p /etc/apt/keyrings
  if [[ ! -f /etc/apt/keyrings/docker.gpg ]]; then
    log "==> Adding Docker GPG key"
    curl -fsSL https://download.docker.com/linux/ubuntu/gpg \
      | gpg --batch --yes --dearmor -o /etc/apt/keyrings/docker.gpg >>"$LOG_FILE" 2>&1
    chmod a+r /etc/apt/keyrings/docker.gpg || true
    log "OK  Docker GPG key added"
  else
    log "OK  Docker GPG key already present — skipping"
  fi

  cat >/etc/apt/sources.list.d/docker.list <<EOF
deb [arch=${arch} signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/ubuntu ${codename} stable
EOF

  apt_quiet "APT update (docker repo)" update
  apt_quiet "Install Docker CE + compose plugin" install docker-ce docker-ce-cli containerd.io docker-compose-plugin

  if command -v systemctl >/dev/null 2>&1; then
    log "==> Enable docker"
    systemctl enable --now docker >>"$LOG_FILE" 2>&1 || true
  fi

  log "OK  Docker installed"
}

main() {
  require_root
  : >"$LOG_FILE"

  export DEBIAN_FRONTEND=noninteractive
  export NEEDRESTART_MODE=a

  log "Starting apt bootstrap"
  log "Log file: ${LOG_FILE}"

  apt_quiet "APT update" update
  apt_quiet "APT upgrade" upgrade
  apt_quiet "Install baseline packages" install "${PKGS[@]}"

  # Enable cron if present
  if command -v systemctl >/dev/null 2>&1; then
    if systemctl list-unit-files 2>/dev/null | grep -qE '^cron\.service'; then
      log "==> Enable cron"
      systemctl enable --now cron >>"$LOG_FILE" 2>&1 || true
    fi
  fi

  # Ensure zsh is in /etc/shells for chsh usability
  if [[ -x /usr/bin/zsh ]]; then
    grep -q '^/usr/bin/zsh$' /etc/shells || echo '/usr/bin/zsh' >> /etc/shells
  fi

  # Docker (Ubuntu-only approach)
  # If you want Debian too later — we’ll extend this function.
  install_docker_ubuntu

  # Remove old kernels BEFORE final autoremove (so leftovers are cleaned)
  remove_old_kernels

  apt_quiet "Autoremove (purge)" autoremove --purge
  apt_quiet "Autoclean" autoclean

  log "Done."
  log "Tip: you can check what changed via: tail -n 200 ${LOG_FILE}"
}

main "$@"
