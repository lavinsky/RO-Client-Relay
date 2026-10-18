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
pid=d['pid']; print('PID='+str(pid));print('STARTTIME='+str(d['starttime_ticks']))
PY
# identity.env is locally generated with validated numeric values only.
source "$OUT/identity.env"
echo "Cliente identificado: PID=$PID; resultados privados: $OUT"
cecli server info > "$OUT/ceserver.json"
cecli process info --pid "$PID" > "$OUT/process.json"
# Region is read from the cache, but verified in the CURRENT process; not trusted as a decrypt boundary.
CACHE="$ROOT/.relay_actor_ring"
if [[ -r "$CACHE" ]] && [[ $(cat "$CACHE") =~ ^[0-9a-fA-F]{6,16}$ ]]; then
  ADDR="0x$(cat "$CACHE")"
  cecli memory region --pid "$PID" --address "$ADDR" > "$OUT/ring_region.json"
  python3 - "$PID" "$ADDR" > "$OUT/ring_check.json" <<'PY'
import json,sys
from relay.memory import ProcessMemory,region_at
pid=int(sys.argv[1]);base=int(sys.argv[2],16);region=region_at(pid,base)
read=ProcessMemory(pid).read(base+0x40,32) if region else b''
print(json.dumps({'pid':pid,'ring_base':hex(base),'mapped':bool(region),'sample_size':len(read),'sample_nonzero':sum(bool(b) for b in read)}))
PY
else
  echo 'Cache da ring ausente/invalido; a etapa de ring foi omitida.' | tee "$OUT/ring_note.txt"
fi
# A trace is a bounded debugger attach/detach smoke-test; it does NOT reveal the writer PC.
cecli --timeout 10s debug trace --pid "$PID" --events 5 --event-timeout 1s --continue auto --yes > "$OUT/debug_trace.json"
python3 - "$OUT/debug_trace.json" <<'PY'
import json,sys
j=json.load(open(sys.argv[1])); d=j.get('data',{})
print('Debug trace:', 'OK' if j.get('ok') else 'FALHOU', '| eventos:', d.get('event_count'), '| timeout:', d.get('timed_out'))
PY
echo "Coleta encerrada. Compartilhe apenas o resumo; revise os arquivos em: $OUT"
