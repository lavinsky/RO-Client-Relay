#!/usr/bin/env bash
# run_action_merge.sh — opção 1 ponta-a-ponta: OpenKore → ANDAR + ATACAR no cliente, via merge.
#
# UM processo só (o arming/roteamento E o disparo da tecla vivem no relay):
#   - relay com --move-dispatch (ANDAR: o 035f do OpenKore vira dispatch nativo; sem isso o char NÃO
#     anda), --action-merge (ATACAR), --synth-input (dispara a tecla do carrier) e a faixa OBSOLETA
#     desligada (--scramble-range ''); o resto (inject, inject-call, scramble-bp=18eff2, reg=auto,
#     consumidor 127.0.0.1:2350, dispatcher 0xd473b0/site 0x4dcba0, sendpacket 816640) vem da conf.
#     -> 035f do OpenKore -> dispatcher nativo (cliente monta/cifra o próprio); 0437/0438/0af4 ->
#        relay arma o CORPO DO CONSUMIDOR (<GID><ação>) no body-map E, no mesmo ponto de arme, o
#        módulo relay/synth_input.py injeta a tecla (ydotool/uinput, passa no Gepard) que faz o
#        CLIENTE montar o carrier; o store reescreve o corpo pelo do consumidor e a ação executa.
#        0437→INSERT, 0438→9 (fileira de cima), 0af4→F2. (Antes isso era o sidecar action_trigger.py
#        tailando o stdout; agora é integrado — sem 2º processo nem log intermediário.)
#
# ORDEM ao vivo: suba isto, depois ANDE UMA VEZ no cliente (OpenKore ou manual) para o move-dispatch
# capturar o `this` passivamente (DR2). Pós relogin (mapa→login→mapa) o relay recaptura sozinho
# (on_connect -> recapture); basta andar uma vez de novo. DRs: DR0=scramble, DR1=sendcall,
# DR2+DR3=move-dispatch (orçamento cheio — esperado).
#
# LIVE, no servidor próprio autorizado. Detecta automaticamente a porta do Gadget
# (config inicial 27052, seleciona próxima livre). --port permite override explícito.
# Requer ydotoold rodando e janela do cliente focável. NÃO edita a conf (inject/inject-call/faixa).
#
# Uso:
#   research/action_0437_0438/run_action_merge.sh [--port PORT] [--wid 0x05200001] [--dry] [--target-select]
#   --target-select: EXPERIMENTO — emite um 0368 (seleção por GID) ANTES do 0437/0438. OFF por padrão
#   (não altera a configuração atual); ligue só para testar a hipótese do pré-select.
# Pare com Ctrl-C.
set -euo pipefail

# Without --port, let relay/agent.py find the uaRO Gadget's actual listen port
# (frida-gadget-32.config starts at 27052 and picks the next free port).
PORT=""
WID=""
DRY=""
TSEL=""
DEMAND=""
while [ $# -gt 0 ]; do
  case "$1" in
    --port) PORT="$2"; shift 2;;
    --wid)  WID="$2";  shift 2;;
    --dry)  DRY="--dry"; shift;;
    --target-select) TSEL="--target-select"; shift;;
    --sendcall-demand) DEMAND="--sendcall-demand"; shift;;
    --no-sendcall-demand) DEMAND="--no-sendcall-demand"; shift;;
    *) echo "arg desconhecido: $1" >&2; exit 2;;
  esac
done

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
PY="${FRIDA_PY:-$HOME/.venv-frida/bin/python}"
[ -x "$PY" ] || PY="python3"            # fallback: o import do frida precisa estar nesse interpretador

SYNTH_DRY=""
[ -n "$DRY" ] && SYNTH_DRY="--synth-dry"
PORT_ARGS=()
[ -n "$PORT" ] && PORT_ARGS+=(--port "$PORT")
[ -n "$WID" ] && PORT_ARGS+=(--synth-wid "$WID")

echo "[run] relay: configuracao padrao via relay_capture.conf, port=${PORT:-auto}, wid=${WID:-config}"
echo "[run] teclas e modos de acao lidos de relay_capture.conf"
[ -n "$TSEL" ] && echo "[run] EXPERIMENTO --target-select: 0368 (seleção por GID) emitido antes de 0437/0438"
# UM processo só: o atuador de tecla agora é um módulo do relay (--synth-input), disparado direto no
# ponto de arme (relay/synth_input.py). Não há mais sidecar nem log intermediário tail-ado.
# stdin aberto (senão o driver recebe EOF via `tail -f /dev/null`). -u: stdout UNBUFFERED p/ ver ao vivo.
# --egress-queue: serializa o despacho (FIFO, 400ms entre pacotes, +400ms após ação) p/ o 035f do
# move-dispatch não atropelar o 0437/0438 — no cliente real/xKore o fluxo ordenado já faz isso.
tail -f /dev/null | "$PY" -u "$ROOT/relay_capture_linux.py" "${PORT_ARGS[@]}" \
    $SYNTH_DRY $TSEL $DEMAND
