ASSETS_TMP="/tmp/vps-edge-assets"
mkdir -p "$ASSETS_TMP"

run_asset() {
  local name="$1" url="$2" log_file="$3"
  local tmp="${ASSETS_TMP}/${name}.sh"

  echo "==> Running asset: ${name}"
  mkdir -p "$(dirname "$log_file")"
  : >"$log_file" || true

  # 1) Если ассет уже лежит локально — используем его
  if [[ ! -s "$tmp" ]]; then
    echo "    download: $url"
    curl -fsSL "$url" -o "$tmp"
    chmod +x "$tmp"
  else
    echo "    local: $tmp"
  fi

  # 2) Запуск: всё в консоль + в лог
  # 3) Если интерактивный ассет — цепляем /dev/tty
  if [[ -e /dev/tty ]]; then
    bash "$tmp" </dev/tty 2>&1 | tee -a "$log_file"
  else
    # без tty — просто как есть
    bash "$tmp" 2>&1 | tee -a "$log_file"
  fi
}