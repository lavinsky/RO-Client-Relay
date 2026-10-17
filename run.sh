#!/usr/bin/env bash
# Operational launcher. relay_capture.conf owns defaults; CLI arguments override them.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PY="${FRIDA_PY:-${VENV:-$HOME/.venv-frida}/bin/python}"
[ -x "$PY" ] || PY=python3
exec "$PY" -u "$ROOT/relay_capture_linux.py" --wait "$@"
