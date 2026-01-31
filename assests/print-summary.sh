#!/usr/bin/env bash
set -Eeuo pipefail

# ---------------------------------------------------------------------------
# assests/print-summary.sh
#
# Expects these vars to be set by the main script (best-effort):
#
# Host/Geo:
#   HOST_SHORT, WAN_IP, GEO_CITY, GEO_REGION, GEO_CC, GEO_PROVIDER, GEO_FLAG
#   TS_IP, TS_NAME
#
# User/Services:
#   ARG_USER, USER_CREATED, USER_PASS
#   REMNA_STATUS_LINE, REMNA_COMPOSE_PATH
#
# Backup + logs:
#   BACKUP_DIR
#   APT_LOG, DNS_LOG, TS_LOG, DOCKER_LOG, TUNE_LOG, ERR_LOG
#
# Before/After snapshot values (strings):
#   B_TCP, A_TCP
#   B_QDISC, A_QDISC
#   B_FORWARD, A_FORWARD
#   B_CONNTRACK, A_CONNTRACK
#   B_TW, A_TW
#   B_SWAPPINESS, A_SWAPPINESS
#   B_SWAP, A_SWAP
#   B_NOFILE, A_NOFILE
#   B_JOURNALD, A_JOURNALD
#   B_LOGROTATE, A_LOGROTATE
#   B_AUTOREBOOT, A_AUTOREBOOT
#   B_REBOOT_TIME, A_REBOOT_TIME
#
# Manifest counts:
#   MANIFEST_PATH
#
# Reboot:
#   REBOOT_LINE   (e.g. "2026-01-31 14:03:04 WARN Reboot disabled (--reboot=skip)")
# ---------------------------------------------------------------------------

_ts() { date '+%F %T'; }

# Colors are intentionally minimal: screenshot shows mostly plain text.
_hdr() {
  local t="$1"
  echo
  echo "$t"
  echo
}

_row2() { # key value
  printf "%-12s | %s\n" "$1" "$2"
}

_row3() { # key before after
  printf "%-11s | %-28s | %s\n" "$1" "$2" "$3"
}

_manifest_counts() {
  local man="${1:-}"
  [[ -n "$man" && -f "$man" ]] || { echo "0 0"; return 0; }

  local copies moves
  copies="$(awk -F'\t' '$1=="COPY"{c++} END{print c+0}' "$man" 2>/dev/null || echo 0)"
  moves="$(awk -F'\t' '$1=="MOVE"{c++} END{print c+0}' "$man" 2>/dev/null || echo 0)"
  echo "$copies $moves"
}

# Helper: show user line exactly like screenshot
_user_summary_line() {
  local uname="${ARG_USER:-}"
  [[ -n "$uname" ]] || { echo "-"; return 0; }

  if [[ "${USER_CREATED:-0}" == "1" ]]; then
    echo "$uname"
  else
    echo "$uname (already existed)"
  fi
}

_pass_summary_line() {
  local uname="${ARG_USER:-}"
  [[ -n "$uname" ]] || { echo "-"; return 0; }

  if [[ "${USER_CREATED:-0}" == "1" ]]; then
    echo "${USER_PASS:-"(generated)"}"
  else
    echo "(unchanged)"
  fi
}

# Helper: best-effort remnanode line
_remna_line() {
  if [[ -n "${REMNA_STATUS_LINE:-}" ]]; then
    echo "${REMNA_STATUS_LINE}"
    return 0
  fi
  # fallback: if docker exists, try to infer
  if command -v docker >/dev/null 2>&1; then
    local s
    s="$(docker ps --format '{{.Names}} {{.Status}}' 2>/dev/null | awk '$1=="remnanode"{ $1=""; sub(/^ /,""); print "Up " $0 }' | head -n1 || true)"
    [[ -n "$s" ]] && { echo "remnanode ${s}"; return 0; }
  fi
  echo "-"
}

print_end_report() {
  # END header line (geo)
  echo
  echo "End"
  echo "  ${GEO_FLAG:-🏳️} ${WAN_IP:-?} — ${GEO_CITY:-?}, ${GEO_REGION:-?}, ${GEO_CC:-?} — ${GEO_PROVIDER:-?}"

  # Before -> After (all)
  _hdr "Before → After (all)"
  echo "------------+-----------------------------+-----------------------------"

  # Only print rows you have. (If var missing, print "-" so layout stays stable.)
  _row3 "TCP"         "${B_TCP:--}"        "${A_TCP:--}"
  _row3 "Qdisc"       "${B_QDISC:--}"      "${A_QDISC:--}"
  _row3 "Forward"     "${B_FORWARD:--}"    "${A_FORWARD:--}"
  _row3 "Conntrack"   "${B_CONNTRACK:--}"  "${A_CONNTRACK:--}"
  _row3 "TW buckets"  "${B_TW:--}"         "${A_TW:--}"
  _row3 "Swappiness"  "${B_SWAPPINESS:--}" "${A_SWAPPINESS:--}"
  _row3 "Swap"        "${B_SWAP:--}"       "${A_SWAP:--}"
  _row3 "Nofile"      "${B_NOFILE:--}"     "${A_NOFILE:--}"
  _row3 "Journald"    "${B_JOURNALD:--}"   "${A_JOURNALD:--}"
  _row3 "Logrotate"   "${B_LOGROTATE:--}"  "${A_LOGROTATE:--}"
  _row3 "AutoReboot"  "${B_AUTOREBOOT:--}" "${A_AUTOREBOOT:--}"
  _row3 "Reboot time" "${B_REBOOT_TIME:--}" "${A_REBOOT_TIME:--}"

  # Files
  _hdr "Files"
  read -r _copies _moves < <(_manifest_counts "${MANIFEST_PATH:-}")
  echo "  backed up (COPY): ${_copies}"
  echo "  moved aside:      ${_moves}"

  # Summary
  _hdr "Summary"
  _row2 "Host"        "${HOST_SHORT:-$(hostname -s 2>/dev/null || hostname)}"
  _row2 "FQDN"        "${TS_NAME:-"-"}"
  _row2 "WAN"         "${GEO_FLAG:-🏳️} ${WAN_IP:-?}"
  _row2 "Geo"         "${GEO_CITY:-?}, ${GEO_REGION:-?}, ${GEO_CC:-?}"
  _row2 "Provider"    "${GEO_PROVIDER:-?}"
  _row2 "Tailscale IP" "${TS_IP:-"-"}"
  _row2 "MagicDNS"    "${TS_NAME:-"-"}"
  _row2 "User"        "$(_user_summary_line)"
  _row2 "Password"    "$(_pass_summary_line)"
  _row2 "remnanode"   "$(_remna_line)"
  _row2 "compose"     "${REMNA_COMPOSE_PATH:-/opt/remnanode/docker-compose.yml}"

  # Backup + logs
  _hdr "Backup + logs"
  echo "Backup: ${BACKUP_DIR:-"-"}"
  echo "Logs:"
  echo "  - APT:      ${APT_LOG:-"-"}"
  echo "  - DNS:      ${DNS_LOG:-"-"}"
  echo "  - Tailscale:${TS_LOG:-"-"}"
  echo "  - Docker:   ${DOCKER_LOG:-"-"}"
  echo "  - Error:    ${ERR_LOG:-"-"}"
  echo "BACKUP_DIR=${BACKUP_DIR:-"-"}"

  # Reboot line (optional)
  if [[ -n "${REBOOT_LINE:-}" ]]; then
    echo
    echo "${REBOOT_LINE}"
  fi
}
