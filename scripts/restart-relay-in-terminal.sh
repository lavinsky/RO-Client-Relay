#!/usr/bin/env bash
# Restart ./run.sh without closing the current terminal or touching OpenKore.
# If invoked non-interactively, reuse the previous private TTY hint or derive
# the TTY from the active relay launcher. No session-specific PID is embedded.
set -euo pipefail

repo="$(cd "$(dirname "$0")/.." && pwd)"
runtime="${XDG_RUNTIME_DIR:-/run/user/$(id -u)}/visualbt-relay"
socket="$runtime/feed.sock"
log="$runtime/relay-console.log"
tty_file="$runtime/relay-tty"
mkdir -p -m 700 "$runtime"
chmod 700 "$runtime"

matching_relays=()
while read -r candidate; do
  [[ -n "$candidate" && -r "/proc/$candidate/cwd" ]] || continue
  if [[ "$(readlink -f "/proc/$candidate/cwd")" == "$repo" ]]; then
    matching_relays+=("$candidate")
  fi
done < <(pgrep -f '/relay_capture_linux.py$' || true)
[[ "${#matching_relays[@]}" -eq 1 ]] || {
  echo "Expected exactly one active relay from this checkout; found ${#matching_relays[@]}" >&2
  exit 2
}
python_pid="${matching_relays[0]}"
run_pid="$(ps -p "$python_pid" -o ppid= | tr -d ' ')"
[[ -n "$run_pid" ]] || { echo 'Relay launcher parent not found' >&2; exit 2; }
[[ "$(readlink -f /proc/$python_pid/cwd)" == "$repo" ]] || {
  echo 'Active relay belongs to a different checkout' >&2; exit 2;
}
[[ "$(ps -p "$run_pid" -o args=)" == 'bash ./run.sh' ]] || {
  echo 'Unexpected relay launcher command' >&2; exit 2;
}
group="$(ps -p "$run_pid" -o pgid= | tr -d ' ')"
[[ "$run_pid" == "$group" ]] || {
  echo 'Unexpected relay process group; refusing broad signal' >&2; exit 2;
}

resolve_tty() {
  local candidate="${RO_RELAY_LOG_TTY:-}"
  if [[ -z "$candidate" && -t 1 ]]; then
    candidate="$(tty 2>/dev/null || true)"
  fi
  if [[ -z "$candidate" || "$candidate" == "not a tty" ]]; then
    local short
    short="$(ps -p "$run_pid" -o tty= | tr -d ' ')"
    if [[ -n "$short" && "$short" != "?" ]]; then
      candidate="/dev/$short"
    fi
  fi
  if [[ (-z "$candidate" || "$candidate" == "not a tty") && -r "$tty_file" ]]; then
    candidate="$(cat "$tty_file")"
  fi
  [[ "$candidate" == /dev/pts/* ]] || return 1
  [[ -w "$candidate" ]] || return 1
  [[ "$(stat -c %u "$candidate")" == "$(id -u)" ]] || return 1
  printf '%s\n' "$candidate"
}

tty="$(resolve_tty)" || {
  echo 'No safe writable user-owned /dev/pts TTY found; set RO_RELAY_LOG_TTY explicitly' >&2
  exit 2
}
printf '%s\n' "$tty" >"$tty_file"
chmod 600 "$tty_file"

if [[ "${1:-}" == --dry-run ]]; then
  echo "Validated relay=$python_pid launcher=$run_pid tty=$tty observer=$socket"
  exit 0
fi
[[ "$#" -eq 0 ]] || { echo 'usage: restart-relay-in-terminal.sh [--dry-run]' >&2; exit 2; }

# Stop old process and allow Frida Gadget hooks to unload before reattach.
kill -INT -- "-$group"
for _ in $(seq 1 160); do
  if ! kill -0 "$python_pid" 2>/dev/null && ! kill -0 "$run_pid" 2>/dev/null; then
    break
  fi
  sleep .025
done
if kill -0 "$python_pid" 2>/dev/null || kill -0 "$run_pid" 2>/dev/null; then
  echo 'Old Frida relay not closed; avoiding concurrent attach' >&2
  exit 3
fi

# Private file, no implicit nohup.out in the repository.
touch "$log"
chmod 600 "$log"
rm -f "$socket"
cd "$repo"
setsid -f env RO_RELAY_OBSERVER_SOCKET="$socket" bash ./run.sh </dev/null >>"$log" 2>&1
if ! pgrep -af "^tail -n 0 -F $log$" >/dev/null; then
  setsid -f tail -n 0 -F "$log" </dev/null >"$tty" 2>/dev/null
fi
for _ in $(seq 1 160); do
  candidate=""
  while read -r maybe; do
    [[ -n "$maybe" && "$maybe" != "$python_pid" && -r "/proc/$maybe/cwd" ]] || continue
    if [[ "$(readlink -f "/proc/$maybe/cwd")" == "$repo" ]]; then
      candidate="$maybe"
      break
    fi
  done < <(pgrep -f '/relay_capture_linux.py$' || true)
  if [[ -n "$candidate" && -S "$socket" ]]; then
    echo "Restarted relay PID=$candidate; logs=$tty, observer=$socket"
    exit 0
  fi
  sleep .05
done
echo 'New relay did not become ready; inspect private log' >&2
exit 4
