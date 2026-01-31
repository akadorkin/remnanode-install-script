#!/usr/bin/env bash
set -euo pipefail

# -----------------------------------------------------------------------------
# assets/ssh-fail2ban-harden.sh
#
# Purpose:
#   - Install & enable fail2ban
#   - Configure sshd jail + recidive
#   - Exponential bantime (incremental)
#   - SSH hardening:
#       * disable password auth for everyone
#       * disable root login entirely
#
# NOTE: Provided "AS IS", without any warranties. Use at your own risk.
# -----------------------------------------------------------------------------

LOG_FILE="${LOG_FILE:-/var/log/edge-ssh-fail2ban-harden.log}"

# Fail2ban settings (reasonable defaults)
SSH_MAXRETRY="${SSH_MAXRETRY:-5}"
SSH_FINDTIME="${SSH_FINDTIME:-10m}"
SSH_BANTIME="${SSH_BANTIME:-30m}"

RECIDIVE_FINDTIME="${RECIDIVE_FINDTIME:-7d}"
RECIDIVE_BANTIME="${RECIDIVE_BANTIME:-14d}"
RECIDIVE_MAXRETRY="${RECIDIVE_MAXRETRY:-5}"

# Exponential bantime (fail2ban >= 0.11 supports these options)
BANTIME_INCREMENT="${BANTIME_INCREMENT:-true}"
BANTIME_FACTOR="${BANTIME_FACTOR:-2}"
BANTIME_FORMULA="${BANTIME_FORMULA:-ban.Time * 2}"

ts()  { date '+%F %T'; }
log() { echo "$(ts) $*" | tee -a "$LOG_FILE"; }
die() { log "ERROR: $*"; exit 1; }

require_root() {
  [[ ${EUID:-$(id -u)} -eq 0 ]] || die "Run as root"
}

apt_install() {
  export DEBIAN_FRONTEND=noninteractive
  log "APT update"
  apt-get -y -qq update >>"$LOG_FILE" 2>&1 || true
  log "Installing packages: $*"
  apt-get -y -qq install "$@" >>"$LOG_FILE" 2>&1 || die "apt install failed"
}

restart_sshd() {
  systemctl restart ssh 2>/dev/null || systemctl restart sshd 2>/dev/null || true
}

main() {
  require_root
  : >"$LOG_FILE"

  log "Start: ssh hardening + fail2ban + recidive"

  # Packages
  apt_install fail2ban openssh-server

  # -------------------- SSH HARDENING --------------------
  local cfg="/etc/ssh/sshd_config"
  [[ -f "$cfg" ]] || die "sshd_config not found: $cfg"

  # Backup once per run (simple)
  local bk="/root/sshd_config.backup.$(date +%Y%m%d_%H%M%S)"
  cp -a "$cfg" "$bk"
  log "Backup: $bk"

  # Force desired directives (replace if exists, else append)
  set_sshd_kv() {
    local key="$1" val="$2"
    if grep -qiE "^[[:space:]]*#?[[:space:]]*${key}[[:space:]]+" "$cfg"; then
      sed -i -E "s|^[[:space:]]*#?[[:space:]]*${key}[[:space:]]+.*|${key} ${val}|I" "$cfg"
    else
      echo "${key} ${val}" >>"$cfg"
    fi
  }

  # Disable password logins entirely
  set_sshd_kv "PasswordAuthentication" "no"
  set_sshd_kv "KbdInteractiveAuthentication" "no"
  set_sshd_kv "ChallengeResponseAuthentication" "no"

  # Root login disabled completely
  set_sshd_kv "PermitRootLogin" "no"

  # Keep PAM enabled (safer default on Ubuntu)
  set_sshd_kv "UsePAM" "yes"

  # Optional: reduce attack surface (safe defaults)
  set_sshd_kv "X11Forwarding" "no"
  set_sshd_kv "PermitEmptyPasswords" "no"

  # Validate config before restart
  if sshd -t >>"$LOG_FILE" 2>&1; then
    log "sshd config OK (sshd -t)"
  else
    log "sshd config validation failed; restoring backup"
    cp -a "$bk" "$cfg"
    die "sshd -t failed. Restored backup."
  fi

  restart_sshd
  log "SSH hardening applied (password login disabled, root login disabled)"

  # -------------------- FAIL2BAN --------------------
  log "Configuring fail2ban"

  mkdir -p /etc/fail2ban

  # jail.d is preferred over editing jail.conf
  local jail="/etc/fail2ban/jail.d/edge-ssh.conf"
  cat >"$jail" <<EOF
[DEFAULT]
# Ban time growth (incremental / "exponential-like")
bantime.increment = ${BANTIME_INCREMENT}
bantime.factor = ${BANTIME_FACTOR}
bantime.formula = ${BANTIME_FORMULA}

# Reasonable defaults
backend = systemd
ignoreip = 127.0.0.1/8 ::1

[sshd]
enabled = true
mode = aggressive
port = ssh
maxretry = ${SSH_MAXRETRY}
findtime = ${SSH_FINDTIME}
bantime = ${SSH_BANTIME}

[recidive]
enabled = true
logpath = /var/log/fail2ban.log
maxretry = ${RECIDIVE_MAXRETRY}
findtime = ${RECIDIVE_FINDTIME}
bantime = ${RECIDIVE_BANTIME}
EOF

  # Ensure fail2ban log exists (recidive uses it)
  touch /var/log/fail2ban.log
  chmod 640 /var/log/fail2ban.log || true

  systemctl enable --now fail2ban >>"$LOG_FILE" 2>&1 || true
  systemctl restart fail2ban >>"$LOG_FILE" 2>&1 || true

  # Show status summary
  log "Fail2ban status:"
  fail2ban-client status >>"$LOG_FILE" 2>&1 || true
  fail2ban-client status sshd  >>"$LOG_FILE" 2>&1 || true
  fail2ban-client status recidive >>"$LOG_FILE" 2>&1 || true

  echo
  echo "================ SUMMARY ================"
  echo "SSH:"
  echo "  - PasswordAuthentication: disabled"
  echo "  - Root login: disabled (PermitRootLogin no)"
  echo
  echo "Fail2ban:"
  echo "  - sshd: enabled (mode=aggressive, maxretry=${SSH_MAXRETRY}, findtime=${SSH_FINDTIME}, bantime=${SSH_BANTIME})"
  echo "  - recidive: enabled (findtime=${RECIDIVE_FINDTIME}, bantime=${RECIDIVE_BANTIME})"
  echo "  - bantime.increment=${BANTIME_INCREMENT}, factor=${BANTIME_FACTOR}, formula='${BANTIME_FORMULA}'"
  echo
  echo "Files:"
  echo "  - SSH backup:  ${bk}"
  echo "  - jail config: ${jail}"
  echo "Log: ${LOG_FILE}"
  echo "========================================"
  echo

  log "Done."
}

main "$@"
