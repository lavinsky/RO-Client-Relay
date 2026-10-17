#!/usr/bin/env bash
# run.sh - sobe a cadeia COMPLETA que faz o OpenKore andar E atacar/lançar no cliente uaRO.
#
# Bare `./run.sh` já faz tudo funcionar (configuração padrão = a que validamos ao vivo):
#   - relay com --move-dispatch (ANDAR) + --action-merge (ATACAR/LANÇAR) + fila FIFO de egresso
#     (--egress-queue, 400ms) + faixa obsoleta desligada (--scramble-range ''); resto vem da conf
#     (inject, inject-call, scramble-bp=18eff2, consumidor 127.0.0.1:2350). Roda com `python -u`.
#   - action_trigger.py: ao ver a linha de arme no stdout do relay, dispara a tecla sintética
#     (ydotool/uinput, passa no Gepard): 0437→INSERT, 0438→9 (fileira de cima), 0af4→F2.
#
# O consumidor (control/config.txt) já está configurado para LANÇAR Soul Strike lvl 10 à distância
# em vez de melee (attackUseWeapon 0, attackSkillSlot Soul Strike, attackDistance 9). Isso contorna
# a causa-raiz: ação só commita com o char EM ALCANCE e ASSENTADO — ataque melee falha porque roteia
# corpo-a-corpo e ataca na transição de chegada; ataque/perícia à distância assentam em alcance.
#
# ORDEM ao vivo (servidor próprio autorizado): suba isto, depois ANDE UMA VEZ no cliente para o
# move-dispatch capturar o `this` (DR2). Pós relogin, ande de novo (recaptura passiva). Pré-req:
# gadget na porta (default 27053), ydotoold rodando, janela do cliente focável.
#
# Uso:
#   ./run.sh [--port 27053] [--wid 0x05200001] [--dry]   # cadeia completa (padrão)
#   ./run.sh --raw [--flags-do-capturador...]            # só o relay cru (conf/defaults), sem trigger
# Pare com Ctrl-C.
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"

# Escape hatch: `--raw` = relay cru com a conf/defaults e flags arbitrárias (comportamento antigo).
if [ "${1:-}" = "--raw" ]; then
  shift
  VENV="${VENV:-$HOME/.venv-frida}"
  PY="$VENV/bin/python"
  [ -x "$PY" ] || { echo "[run] venv não encontrado em $VENV - rode ./setup.sh primeiro" >&2; exit 1; }
  echo "[run] modo --raw: relay cru (conf/defaults), sem action-merge/trigger"
  tail -f /dev/null | "$PY" "$HERE/relay_capture_linux.py" "$@"
  exit $?
fi

# Padrão: a cadeia completa validada ao vivo.
exec "$HERE/research/action_0437_0438/run_action_merge.sh" "$@"
