#!/usr/bin/env bash
# Diagnostico delimitado do uaRO: nao altera relay e nao instala watchpoints.
set -Eeuo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT"
umask 077
command -v cecli >/dev/null || { echo 'ERRO: cecli ausente' >&2; exit 2; }
command -v python3 >/dev/null || exit 2
if pgrep -f '[/]relay_capture_linux.py' >/dev/null; then
  echo 'ERRO: relay em execucao. Feche o relay antes da sondagem.' >&2; exit 3
fi
OUT="$ROOT/research/recv_cipher/artifacts/$(date +%Y%m%d-%H%M%S)"
mkdir -m 700 "$OUT"
python3 -m ro_ops discover > "$OUT/discover.json"
python3 - "$OUT/discover.json" > "$OUT/identity.env" <<'PY'
import json,sys
j=json.load(open(sys.argv[1])); d=j.get('data',{})
if j.get('status')!='verified' or len(d.get('candidates',[]))!=1:
    raise SystemExit('ERRO: identidade unica do cliente nao confirmada')
import re
c=d['candidates'][0]
name=c.get('argv0','').replace('\\','/').split('/')[-1]
if not re.fullmatch(r'uar[o]\.exe',name,re.I):
    raise SystemExit('ERRO: candidato nao e uaRO.exe: '+name)
if c.get('pid') != d.get('pid') or not isinstance(d.get('starttime_ticks'),int):
    raise SystemExit('ERRO: identidade inconsistente')
pid=int(d['pid'])
print('PID='+str(pid));print('STARTTIME='+str(d['starttime_ticks']))
PY
# identity.env is locally generated with validated numeric values only.
source "$OUT/identity.env"
echo "Cliente uaRO.exe (Wine/Proton) identificado dinamicamente: PID=$PID; resultados: $OUT"
# Prevent PID reuse or a relaunch between discovery and debugger attach.
check_identity() {
  python3 - "$PID" "$STARTTIME" <<'PYID'
import sys
pid=int(sys.argv[1]); start=int(sys.argv[2])
try:
    fields=open(f'/proc/{pid}/stat').read().rsplit(')',1)[1].split()
    current=int(fields[19]); state=fields[0]
    cmd=open(f'/proc/{pid}/cmdline','rb').read().decode('utf-8','replace').lower()
except (OSError,ValueError,IndexError):
    raise SystemExit('ERRO: processo nao esta mais acessivel')
if current != start or state in ('Z','X') or 'uaro.exe' not in cmd:
    raise SystemExit('ERRO: uaRO.exe reiniciou, encerrou ou PID foi reutilizado')
PYID
}
check_identity
cecli server info > "$OUT/ceserver.json"
cecli process info --pid "$PID" > "$OUT/process.json"
# Cached ring addresses belong to a past process instance and cannot be
# independently validated as the current decrypt ring. Never probe a stale base.
echo 'Endereco de ring em cache ignorado: exige redescoberta por evidencia da sessao atual.' | tee "$OUT/ring_note.txt"
check_identity
# A trace is a bounded debugger attach/detach smoke-test; it does NOT reveal the writer PC.
check_identity
cecli --timeout 10s debug trace --pid "$PID" --events 5 --event-timeout 1s --continue auto --yes > "$OUT/debug_trace.json"
python3 - "$OUT/debug_trace.json" <<'PY'
import json,sys
j=json.load(open(sys.argv[1])); d=j.get('data',{})
print('Debug trace:', 'OK' if j.get('ok') else 'FALHOU', '| eventos:', d.get('event_count'), '| timeout:', d.get('timed_out'))
PY
echo "Coleta encerrada. Compartilhe apenas o resumo; revise os arquivos em: $OUT"
