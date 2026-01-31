#!/usr/bin/env bash
set -euo pipefail

# -----------------------------------------------------------------------------
# assets/zsh-setup.sh
#
# Purpose:
#   - Install & configure Zsh stack for:
#       * all users in /home/*
#       * root
#   - oh-my-zsh + plugins + powerlevel10k + fzf
#   - Pull .zshrc and .p10k.zsh from your GitHub raw links
#
# Idempotent:
#   - Won't reinstall if already present
#   - Plugins/themes cloned only if missing
#
# NOTE: Provided "AS IS", without any warranties. Use at your own risk.
# -----------------------------------------------------------------------------

LOG_FILE="${LOG_FILE:-/var/log/edge-zsh-setup.log}"

# Your new URLs (can be overridden via env)
ZSHRC_URL="${ZSHRC_URL:-https://raw.githubusercontent.com/akadorkin/remnanode-install-script/refs/heads/main/zsh/zshrc}"
P10K_URL="${P10K_URL:-https://raw.githubusercontent.com/akadorkin/remnanode-install-script/refs/heads/main/zsh/p10k}"

ts() { date '+%F %T'; }
log() { echo "$(ts) $*" | tee -a "$LOG_FILE"; }
die() { log "ERROR: $*"; exit 1; }
require_root() { [[ ${EUID:-$(id -u)} -eq 0 ]] || die "Run as root"; }

apt_quiet() {
  local title="$1"; shift
  log "==> ${title}"
  if apt-get -y -qq -o Dpkg::Use-Pty=0 \
       -o Dpkg::Options::='--force-confdef' \
       -o Dpkg::Options::='--force-confold' \
       "$@" >>"$LOG_FILE" 2>&1; then
    log "OK  ${title}"
  else
    log "FAIL ${title}"
    tail -n 120 "$LOG_FILE" | sed 's/^/    /' || true
    exit 1
  fi
}

ensure_prereqs() {
  export DEBIAN_FRONTEND=noninteractive
  export NEEDRESTART_MODE=a

  apt_quiet "APT update" update
  apt_quiet "Install Zsh prereqs" install zsh git curl ca-certificates
  # make chsh happy
  if [[ -x /usr/bin/zsh ]]; then
    grep -q '^/usr/bin/zsh$' /etc/shells || echo '/usr/bin/zsh' >> /etc/shells
  fi
}

zsh_disable_update_prompts() {
  local zrc="$1"
  [[ -f "$zrc" ]] || return 0

  grep -q 'DISABLE_AUTO_UPDATE' "$zrc" 2>/dev/null || echo 'DISABLE_AUTO_UPDATE="true"' >> "$zrc"
  grep -q 'DISABLE_UPDATE_PROMPT' "$zrc" 2>/dev/null || echo 'DISABLE_UPDATE_PROMPT=true' >> "$zrc"
  grep -q ":omz:update" "$zrc" 2>/dev/null || echo "zstyle ':omz:update' mode disabled" >> "$zrc"
}

run_as_user() {
  local uname="$1"; shift
  # shellcheck disable=SC2024
  su - "$uname" -c "$*" >>"$LOG_FILE" 2>&1 || return 1
}

ensure_ohmyzsh_for_user() {
  local uname="$1"
  local home="$2"

  [[ -d "$home" ]] || return 0

  log "---- user: ${uname} (home: ${home}) ----"

  # oh-my-zsh install
  if [[ ! -d "${home}/.oh-my-zsh" ]]; then
    log "Install oh-my-zsh for ${uname}"
    if [[ "$uname" == "root" ]]; then
      RUNZSH=no KEEP_ZSHRC=yes CHSH=no \
        sh -c "$(curl -fsSL https://raw.githubusercontent.com/ohmyzsh/ohmyzsh/master/tools/install.sh)" \
        >>"$LOG_FILE" 2>&1 || true
    else
      run_as_user "$uname" 'RUNZSH=no KEEP_ZSHRC=yes CHSH=no sh -c "$(curl -fsSL https://raw.githubusercontent.com/ohmyzsh/ohmyzsh/master/tools/install.sh)"' || true
    fi
  else
    log "oh-my-zsh already present for ${uname}"
  fi

  local zsh_path="${home}/.oh-my-zsh"
  local zsh_custom="${zsh_path}/custom"
  mkdir -p "${zsh_custom}/plugins" "${zsh_custom}/themes" >>"$LOG_FILE" 2>&1 || true

  # plugins/themes
  if [[ ! -d "${zsh_custom}/plugins/zsh-autosuggestions" ]]; then
    log "Clone zsh-autosuggestions for ${uname}"
    if [[ "$uname" == "root" ]]; then
      git clone --depth=1 https://github.com/zsh-users/zsh-autosuggestions "${zsh_custom}/plugins/zsh-autosuggestions" >>"$LOG_FILE" 2>&1 || true
    else
      run_as_user "$uname" "git clone --depth=1 https://github.com/zsh-users/zsh-autosuggestions ${zsh_custom}/plugins/zsh-autosuggestions" || true
    fi
  fi

  if [[ ! -d "${zsh_custom}/plugins/zsh-completions" ]]; then
    log "Clone zsh-completions for ${uname}"
    if [[ "$uname" == "root" ]]; then
      git clone --depth=1 https://github.com/zsh-users/zsh-completions "${zsh_custom}/plugins/zsh-completions" >>"$LOG_FILE" 2>&1 || true
    else
      run_as_user "$uname" "git clone --depth=1 https://github.com/zsh-users/zsh-completions ${zsh_custom}/plugins/zsh-completions" || true
    fi
  fi

  if [[ ! -d "${zsh_custom}/plugins/zsh-syntax-highlighting" ]]; then
    log "Clone zsh-syntax-highlighting for ${uname}"
    if [[ "$uname" == "root" ]]; then
      git clone --depth=1 https://github.com/zsh-users/zsh-syntax-highlighting "${zsh_custom}/plugins/zsh-syntax-highlighting" >>"$LOG_FILE" 2>&1 || true
    else
      run_as_user "$uname" "git clone --depth=1 https://github.com/zsh-users/zsh-syntax-highlighting ${zsh_custom}/plugins/zsh-syntax-highlighting" || true
    fi
  fi

  if [[ ! -d "${zsh_custom}/themes/powerlevel10k" ]]; then
    log "Clone powerlevel10k for ${uname}"
    if [[ "$uname" == "root" ]]; then
      git clone --depth=1 https://github.com/romkatv/powerlevel10k.git "${zsh_custom}/themes/powerlevel10k" >>"$LOG_FILE" 2>&1 || true
    else
      run_as_user "$uname" "git clone --depth=1 https://github.com/romkatv/powerlevel10k.git ${zsh_custom}/themes/powerlevel10k" || true
    fi
  fi

  # fzf
  if [[ ! -d "${home}/.fzf" ]]; then
    log "Install fzf for ${uname}"
    if [[ "$uname" == "root" ]]; then
      git clone --depth 1 https://github.com/junegunn/fzf.git "${home}/.fzf" >>"$LOG_FILE" 2>&1 || true
      bash -lc 'yes | ~/.fzf/install --key-bindings --completion --no-bash --no-fish --no-update-rc' >>"$LOG_FILE" 2>&1 || true
    else
      run_as_user "$uname" 'git clone --depth 1 https://github.com/junegunn/fzf.git ~/.fzf' || true
      run_as_user "$uname" 'yes | ~/.fzf/install --key-bindings --completion --no-bash --no-fish --no-update-rc' || true
    fi
  else
    log "fzf already present for ${uname}"
  fi

  # Pull configs
  log "Download .zshrc + .p10k.zsh for ${uname}"
  curl -fsSL "$ZSHRC_URL" -o "${home}/.zshrc" >>"$LOG_FILE" 2>&1 || die "failed to download zshrc from ${ZSHRC_URL}"
  curl -fsSL "$P10K_URL"  -o "${home}/.p10k.zsh" >>"$LOG_FILE" 2>&1 || die "failed to download p10k from ${P10K_URL}"

  # FZF_BASE fallback (only if not already there)
  if [[ -f "${home}/.zshrc" ]] && ! grep -q 'FZF_BASE=' "${home}/.zshrc" 2>/dev/null; then
    cat >> "${home}/.zshrc" <<'EOF_FZF'
# Linux fallback for oh-my-zsh fzf plugin
if command -v fzf >/dev/null 2>&1; then
  export FZF_BASE="${FZF_BASE:-$HOME/.fzf}"
fi
EOF_FZF
  fi

  zsh_disable_update_prompts "${home}/.zshrc"

  # Ownership + default shell
  if [[ "$uname" == "root" ]]; then
    chown root:root "${home}/.zshrc" "${home}/.p10k.zsh" 2>/dev/null || true
    chsh -s /usr/bin/zsh root >/dev/null 2>&1 || true
  else
    chown "$uname:$uname" "${home}/.zshrc" "${home}/.p10k.zsh" 2>/dev/null || true
    chsh -s /usr/bin/zsh "$uname" >/dev/null 2>&1 || true
  fi

  log "OK zsh stack ensured for ${uname}"
}

main() {
  require_root
  : >"$LOG_FILE"
  log "Starting zsh setup"
  log "ZSHRC_URL=${ZSHRC_URL}"
  log "P10K_URL=${P10K_URL}"
  ensure_prereqs

  # /home/* users
  local d u
  while IFS= read -r -d '' d; do
    u="$(basename "$d")"
    ensure_ohmyzsh_for_user "$u" "$d"
  done < <(find /home -mindepth 1 -maxdepth 1 -type d -print0 2>/dev/null || true)

  # root
  ensure_ohmyzsh_for_user "root" "/root"

  log "Done."
  log "Log: ${LOG_FILE}"
}

main "$@"
