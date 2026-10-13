#!/usr/bin/env bash
# run.sh - roda o relay de captura com o venv do frida, segurando o stdin aberto.
#
# O driver encerra quando o stdin fecha (EOF); `tail -f /dev/null` o mantém aberto, então você não
# precisa digitar aquele prefixo toda vez. Pare com Ctrl-C.
#
# Uso:   ./run.sh [--flags-do-capturador...]     (sem flags usa relay_capture.conf)
#        VENV=/caminho/venv ./run.sh ...          (venv alternativo; padrão ~/.venv-frida)
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
VENV="${VENV:-$HOME/.venv-frida}"
PY="$VENV/bin/python"

[ -x "$PY" ] || { echo "[run] venv não encontrado em $VENV - rode ./setup.sh primeiro" >&2; exit 1; }

tail -f /dev/null | "$PY" "$HERE/relay_capture_linux.py" "$@"
