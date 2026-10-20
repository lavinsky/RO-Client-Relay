#!/usr/bin/env bash
# Diagnostico delimitado do uaRO: nao altera relay e nao instala watchpoints.
set -Eeuo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT"
umask 077
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
# Nunca anexar depurador CEserver/ptrace: congela o uaRO sob Wine/Proton.
# Inventario e correlacao somente leitura via /proc; sem ptrace ou escrita de memoria.
check_identity
python3 - "$PID" > "$OUT/proc_status.json" <<'PYSTATUS'
import json,sys
pid=int(sys.argv[1]); result={'pid':pid}
for line in open(f'/proc/{pid}/status'):
    if line.startswith(('Name:', 'State:', 'Threads:', 'TracerPid:')):
        key,value=line.split(':',1)
        result[key]=value.strip()
print(json.dumps(result))
PYSTATUS
if python3 - "$OUT/proc_status.json" <<'PYTRACER'
import json,sys
j=json.load(open(sys.argv[1]))
raise SystemExit(0 if j.get('TracerPid') == '0' else 1)
PYTRACER
then
  echo 'Inventario concluido; nenhum depurador foi anexado.'
else
  echo 'ATENCAO: processo possui TracerPid nao-zero; nenhuma sonda executada.' >&2
  exit 4
fi
echo "Coleta encerrada. Compartilhe apenas o resumo; revise os arquivos em: $OUT"
# Passive libc/Wine recv callsite observation via Frida Gadget; no ptrace.
if [[ "${RECV_FRIDA_PROBE:-1}" == "1" ]]; then
  PORT="$(python3 - "$OUT/discover.json" <<'PYPORT'
import json,sys
j=json.load(open(sys.argv[1]));print(j['data']['port'])
PYPORT
)"
  check_identity
  python3 research/recv_cipher/recv_probe.py --pid "$PID" --port "$PORT" --out "$OUT/recv_callsites.jsonl" --seconds "${RECV_PROBE_SECONDS:-12}" --max-calls "${RECV_PROBE_MAX_CALLS:-160}"
fi
