#!/usr/bin/env bash
# run.sh - sobe a cadeia COMPLETA que faz o OpenKore andar E atacar/lançar no cliente uaRO.
#
# Bare `./run.sh` já faz tudo funcionar (configuração padrão = a que validamos ao vivo):
#   - relay com --move-dispatch (ANDAR) + --action-merge (ATACAR/LANÇAR) + fila FIFO de egresso
#     (--egress-queue, 400ms) + faixa obsoleta desligada (--scramble-range ''); resto vem da conf
#     (inject, inject-call, offsets nativos vindos do client profile, consumidor 127.0.0.1:2350).
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

# VisualBehaviorTrees / roBrowser: mirror read-only of the exact plaintext
# stream already delivered to OpenKore. The UNIX socket is user-private and
# carries only observer R frames; browser output never reaches the game.
if [[ "${RO_RELAY_OBSERVER_SOCKET:-}" != "off" ]]; then
    OBSERVER_DIR="${XDG_RUNTIME_DIR:-/run/user/$(id -u)}/visualbt-relay"
    install -d -m 700 "$OBSERVER_DIR"
    export RO_RELAY_OBSERVER_SOCKET="${RO_RELAY_OBSERVER_SOCKET:-$OBSERVER_DIR/feed.sock}"
    # A previous unclean exit can leave the pathname behind. Never unlink a
    # socket owned by a live relay: a second launcher must fail harmlessly.
    if [[ -S "$RO_RELAY_OBSERVER_SOCKET" ]]; then
        if ss -xl 2>/dev/null | grep -Fq "$RO_RELAY_OBSERVER_SOCKET"; then
            echo "[run] observer socket already active: $RO_RELAY_OBSERVER_SOCKET" >&2
        else
            rm -f "$RO_RELAY_OBSERVER_SOCKET"
        fi
    fi
fi

# Único launcher operacional. Todos os padrões ficam em relay_capture.conf.
# Compatibilidade: --raw aceita diretamente todas as flags de relay_capture_linux.py.
RAW=0
if [ "${1:-}" = "--raw" ]; then RAW=1; shift; fi
PY="${FRIDA_PY:-$HOME/.venv-frida/bin/python}"
[ -x "$PY" ] || PY="python3"

# Auditoria opcional: nunca solicitar senha interativamente ou impedir o jogo.
# Para ativar: sudo -v antes de ./run.sh; caso contrário seguimos sem auditoria.
# O monitor acompanha reinícios do uaRO e remove somente regras que conseguiu instalar.
AUDIT_SCRIPT="$HERE/scripts/audit-game-stop-signals.sh"
AUDIT_MONITOR_PID=''
audit_monitor() {
    local pid='' newpid='' audit_ready=0
    audit_monitor_cleanup() {
        if [[ -n "$pid" && "$audit_ready" -eq 1 ]]; then
            sudo -n "$AUDIT_SCRIPT" report "$pid" 2>&1 || true
            sudo -n "$AUDIT_SCRIPT" stop "$pid" 2>&1 || true
        fi
    }
    trap audit_monitor_cleanup EXIT
    trap 'exit 0' TERM INT
    while :; do
        newpid="$(pgrep -u "$(id -u)" -x 'uaRO.exe' | tail -n 1 || true)"
        if [[ "$newpid" != "$pid" ]]; then
            if [[ -n "$pid" && "$audit_ready" -eq 1 ]]; then
                sudo -n "$AUDIT_SCRIPT" report "$pid" 2>&1 || true
                sudo -n "$AUDIT_SCRIPT" stop "$pid" 2>&1 || true
            fi
            audit_ready=0; pid="$newpid"
            if [[ -n "$pid" ]]; then
                if sudo -n "$AUDIT_SCRIPT" start "$pid"; then
                    audit_ready=1
                    echo "[audit] monitorando sinais enviados ao uaRO PID=$pid"
                else
                    echo '[audit] sem privilégios não interativos; auditoria desativada (execute sudo -v antes de ./run.sh)' >&2
                    return 0
                fi
            fi
        fi
        sleep 1
    done
}
audit_cleanup() {
    if [[ -n "$AUDIT_MONITOR_PID" ]]; then
        kill "$AUDIT_MONITOR_PID" 2>/dev/null || true
        wait "$AUDIT_MONITOR_PID" 2>/dev/null || true
    fi
}
# A execução com sudo -n não altera a exigência de senha do sistema e não trava o launcher.
if [[ -x "$AUDIT_SCRIPT" ]] && sudo -n true 2>/dev/null; then
    audit_monitor & AUDIT_MONITOR_PID=$!
    trap audit_cleanup EXIT
else
    echo '[audit] inativa; para habilitar auditoria de sinais, execute sudo -v antes de ./run.sh'
fi

# Prevent a Wine process-wide SIGSTOP from becoming an indefinite freeze.
# Separate process, independent of relay/Frida message flow; one SIGCONT per stop episode.
WATCHDOG_PID=''
"$PY" -u "$HERE/scripts/watch-uaro-stop.py" --threshold 3 --interval 0.25 &
WATCHDOG_PID=$!
run_cleanup() {
    if [[ -n "$WATCHDOG_PID" ]]; then
        kill "$WATCHDOG_PID" 2>/dev/null || true
        wait "$WATCHDOG_PID" 2>/dev/null || true
    fi
    audit_cleanup
}
trap run_cleanup EXIT

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
