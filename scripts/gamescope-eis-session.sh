#!/usr/bin/env bash
# Run *inside* gamescope, which exports LIBEI_SOCKET to its children.
# Writes only a private path pointer; never creates/injects a host input device.
set -euo pipefail
if [[ -z "${LIBEI_SOCKET:-}" || -z "${XDG_RUNTIME_DIR:-}" ]]; then
  echo "[gamescope-eis] requires LIBEI_SOCKET and XDG_RUNTIME_DIR from gamescope" >&2
  exit 2
fi
if [[ $# -eq 0 ]]; then
  echo "usage: gamescope-eis-session.sh COMMAND [ARG...]" >&2
  exit 2
fi
socket="${LIBEI_SOCKET}"
if [[ "$socket" != /* ]]; then
  socket="${XDG_RUNTIME_DIR}/$socket"
fi
if [[ ! -S "$socket" ]]; then
  echo "[gamescope-eis] not a socket: $socket" >&2
  exit 3
fi
path_file="${RO_RELAY_EIS_FILE:-${XDG_RUNTIME_DIR}/ro-relay-gamescope-eis.path}"
umask 077
tmp="$(mktemp "${path_file}.XXXXXX")"
printf '%s\n' "$socket" > "$tmp"
mv -f -- "$tmp" "$path_file"
echo "[gamescope-eis] socket path file: $path_file" >&2
cleanup() {
  if [[ -f "$path_file" ]] && [[ "$(cat "$path_file")" == "$socket" ]]; then
    rm -f -- "$path_file"
  fi
}
trap cleanup EXIT
"$@"
