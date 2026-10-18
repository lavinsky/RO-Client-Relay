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
# ORDEM ao vivo (servidor próprio autorizado): a porta do Frida Gadget é detectada
# automaticamente (config inicia em 27052, pick-next em conflito); suba isto,
# depois ANDE UMA VEZ no cliente para o move-dispatch capturar o `this` (DR2).
# Pós relogin, ande de novo (recaptura passiva). Pré-req: Gadget carregado,
# ydotoold rodando, janela do cliente focável.
#
# Uso:
#   ./run.sh [--port PORT] [--wid 0x05200001] [--dry]   # porta auto-detectada no padrão
#   ./run.sh --raw [--flags-do-capturador...]            # só o relay cru (conf/defaults), sem trigger
# Pare com Ctrl-C.
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"

# Único launcher operacional. Todos os padrões ficam em relay_capture.conf.
# Compatibilidade: --raw aceita diretamente todas as flags de relay_capture_linux.py.
RAW=0
if [ "${1:-}" = "--raw" ]; then RAW=1; shift; fi
PY="${FRIDA_PY:-$HOME/.venv-frida/bin/python}"
[ -x "$PY" ] || PY="python3"

if [ "$RAW" -eq 1 ]; then
    echo "[run] modo raw: argumentos repassados diretamente; defaults em relay_capture.conf"
    tail -f /dev/null | "$PY" -u "$HERE/relay_capture_linux.py" "$@"
    exit $?
fi

ARGS=()
while [ "$#" -gt 0 ]; do
    case "$1" in
        --port|--wid)
            [ "$#" -ge 2 ] || { echo "[run] falta valor para $1" >&2; exit 2; }
            if [ "$1" = "--wid" ]; then ARGS+=(--synth-wid "$2"); else ARGS+=(--port "$2"); fi
            shift 2;;
        --dry) ARGS+=(--synth-dry); shift;;
        --target-select|--no-target-select|--sendcall-demand|--no-sendcall-demand)
            ARGS+=("$1"); shift;;
        *) echo "[run] opção desconhecida: $1 (use --raw para opções avançadas)" >&2; exit 2;;
    esac
done

echo "[run] iniciando relay usando relay_capture.conf como configuração principal"
# Mantém stdin aberto para o capturador, sem processo auxiliar de ações.
tail -f /dev/null | "$PY" -u "$HERE/relay_capture_linux.py" "${ARGS[@]}"
