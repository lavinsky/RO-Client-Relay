#!/usr/bin/env bash
# run_action_merge.sh — opção 1 ponta-a-ponta: OpenKore → ANDAR + ATACAR no cliente, via merge.
#
# Fia os DOIS processos que a opção 1 precisa (o arming/roteamento já vive em relay/writeback.py):
#   1) o relay com --move-dispatch (ANDAR: o 035f do OpenKore vira dispatch nativo; sem isso o char
#      NÃO anda), --action-merge (ATACAR) e a faixa OBSOLETA desligada (--scramble-range ''); o resto
#      (inject, inject-call, scramble-bp=18eff2, reg=auto, consumidor 127.0.0.1:2350, dispatcher
#      0xd473b0/site 0x4dcba0, sendpacket 816640) vem da conf/defaults.
#      -> 035f do OpenKore -> dispatcher nativo (cliente monta/cifra o próprio); 0437/0438/0af4 ->
#         relay arma o CORPO DO CONSUMIDOR (<GID><ação>) no body-map e loga "[inject] inbound id=0x…
#         scramble body map".
#   2) action_trigger.py tailando o stdout do relay: ao ver essa linha, dispara a tecla sintética
#      (ydotool/uinput, passa no Gepard) que faz o CLIENTE montar o carrier; o store reescreve o
#      corpo pelo do consumidor e a ação executa. 0437→INSERT, 0438→F1, 0af4→F2.
#
# ORDEM ao vivo: suba isto, depois ANDE UMA VEZ no cliente (OpenKore ou manual) para o move-dispatch
# capturar o `this` passivamente (DR2). Pós relogin (mapa→login→mapa) o relay recaptura sozinho
# (on_connect -> recapture); basta andar uma vez de novo. DRs: DR0=scramble, DR1=sendcall,
# DR2+DR3=move-dispatch (orçamento cheio — esperado).
#
# LIVE, no servidor próprio autorizado. Requer: gadget na porta (default 27053), ydotoold rodando
# (ver synth_input.py), janela do cliente focável. NÃO edita a conf (inject/inject-call/faixa).
#
# Uso:
#   research/action_0437_0438/run_action_merge.sh [--port 27053] [--wid 0x05200001] [--dry]
# Pare com Ctrl-C (encerra relay + trigger).
set -euo pipefail

PORT=27053
WID=0x05200001
DRY=""
while [ $# -gt 0 ]; do
  case "$1" in
    --port) PORT="$2"; shift 2;;
    --wid)  WID="$2";  shift 2;;
    --dry)  DRY="--dry"; shift;;
    *) echo "arg desconhecido: $1" >&2; exit 2;;
  esac
done

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
PY="${FRIDA_PY:-$HOME/.venv-frida/bin/python}"
[ -x "$PY" ] || PY="python3"            # fallback: o import do frida precisa estar nesse interpretador
LOG="$(mktemp -t action_merge_relay.XXXXXX.log)"

cleanup() {
  [ -n "${TRIG_PID:-}" ] && kill "$TRIG_PID" 2>/dev/null || true
  [ -n "${RELAY_PID:-}" ] && kill "$RELAY_PID" 2>/dev/null || true
  echo "[run] encerrado; log em $LOG"
}
trap cleanup EXIT INT TERM

echo "[run] relay: --move-dispatch --action-merge --scramble-range '' (resto da conf), port=$PORT, log=$LOG"
# stdin aberto (senão o driver recebe EOF); stdout -> log (que o trigger tail-a) e também na tela.
# -u: stdout UNBUFFERED. Sem isso o python bufferiza por bloco através do pipe, o $LOG fica vazio e
# o action_trigger (que tail-a o $LOG) não vê as linhas de arme -> não dispara o INSERT sozinho.
# --egress-queue: serializa o despacho (FIFO, 100ms entre pacotes, +400ms após ação) p/ o 035f do
# move-dispatch não atropelar o 0437/0438 — no cliente real/xKore o fluxo ordenado já faz isso.
tail -f /dev/null | "$PY" -u "$ROOT/relay_capture_linux.py" --port "$PORT" \
    --move-dispatch --action-merge --egress-queue --egress-interval-ms 400 --scramble-range '' 2>&1 | tee "$LOG" &
RELAY_PID=$!

# Espera o relay conectar no consumidor OU armar o scrambler antes de ligar o trigger.
for _ in $(seq 1 100); do
  grep -qE 'connected to|scrambler|scramble-bp' "$LOG" 2>/dev/null && break
  sleep 0.1
done

echo "[run] trigger: 0437→INSERT 0438→F1 0af4→F2, wid=$WID $DRY"
"$PY" "$ROOT/research/action_0437_0438/action_trigger.py" \
    --log "$LOG" --wid "$WID" $DRY &
TRIG_PID=$!

wait "$RELAY_PID"
