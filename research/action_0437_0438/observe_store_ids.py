#!/usr/bin/env python3
"""OBSERVADOR SOMENTE-LEITURA do store do scrambler (gepard+0x18eff2): QUAIS ids passam por ele?

Pergunta: o store pinado `gepard+0x18eff2` (que reescreve o `035F` do movimento) também processa o
envio natural de `0x0437`/`0x0438`/`0x0AF4`? O relay nunca registrou `hit:'wrote'` para ação, mesmo
com corpo armado e carriers naturais — hipótese: ação usa OUTRO sítio de store, não o 0x18eff2.

Método (sem patch/escrita): HW exec BP DR0 em gepard+0x18eff2. O store é byte-a-byte (ecx = byte do
corpo sendo XORado; o id fica em ecx-2 para pacotes 5f03/3704/... com header de 2 bytes). A cada hit,
lê u16 em ecx-2 (e varre eax/ebx/edx/esi/edi/ebp-2 como fallback) e acumula um histograma de ids. Só
emite o histograma a cada N hits e ao ver um id novo (o BP dispara milhares de vezes/seg — nunca
floodar). Read-only; não arma corpo nenhum. Pare se o cliente travar.

O responsável/este agente gera `0x0437` naturais apertando INSERT (sentar) algumas vezes durante a
janela. Requer que NENHUM relay esteja usando DR0 (pare o relay antes).

Uso: observe_store_ids.py --pid PID --out ARQ [--port 27053] [--timeout-ms 25000] [--store-off 0x18eff2]
"""
import argparse
import json
import time
from pathlib import Path

import frida

JS = r"""
'use strict';
if (Process.arch !== 'ia32') throw new Error('Expected ia32');
var mainTid = Process.id;
var gb = null;
Process.enumerateRanges({protection: '---', coalesce: false}).forEach(function (r) {
  if (r.file && /\/gepard\.dll$/i.test(r.file.path) && (gb === null || r.base.compare(gb) < 0)) gb = r.base;
});
if (!gb) throw new Error('Gepard mapping absent');
var store = gb.add(STORE_OFF);
var th = Process.enumerateThreads().filter(function (t) { return t.id === mainTid; })[0];
if (!th) throw new Error('main thread absent');

var hist = {};          // id(hex) -> count (id lido em ecx-2)
var histScan = {};      // id(hex) -> count (qualquer registrador -2, fallback)
var hits = 0, done = false, lastEmit = 0;
var REGS = ['eax','ebx','ecx','edx','esi','edi','ebp'];

function bump(o, id) { var k = '0x' + (id >>> 0).toString(16); var isNew = o[k] === undefined; o[k] = (o[k] || 0) + 1; return isNew; }
function plausible(v) { return v >= 0x0001 && v <= 0x0fff; }

Process.setExceptionHandler(function (d) {
  if (d.type !== 'breakpoint' || done) return false;
  var c = d.context;
  if (!c.pc.equals(store)) return false;
  if (Process.getCurrentThreadId() !== mainTid) return true;
  hits++;
  var newId = false;
  // primário: id em ecx-2 (layout observado p/ 035f)
  try { var idc = c.ecx.sub(2).readU16(); if (plausible(idc)) newId = bump(hist, idc) || newId; } catch (e) {}
  // fallback: varre registradores, id em reg-2
  for (var i = 0; i < REGS.length; i++) {
    try { var r = c[REGS[i]]; if (!(r instanceof NativePointer) || r.isNull()) continue;
      var idv = r.sub(2).readU16(); if (plausible(idv)) bump(histScan, idv); } catch (e) {}
  }
  if (newId || (hits - lastEmit) >= 4000) { lastEmit = hits; send({site: 'hist', hits: hits, ecx_minus2: hist, scan_minus2: histScan}); }
  return true;
});

try { th.setHardwareBreakpoint(0, store); } catch (e) { throw new Error('HW BP failed: ' + e.message); }
send({site: 'READY', read_only: true, main_tid: mainTid, gepard_base: gb.toString(), store: store.toString()});
setTimeout(function () { done = true; try { th.unsetHardwareBreakpoint(0); } catch (e) {}
  send({site: 'DONE', hits: hits, ecx_minus2: hist, scan_minus2: histScan}); }, TIMEOUT_MS);
rpc.exports = { stop: function () { done = true; try { th.unsetHardwareBreakpoint(0); } catch (e) {} return {hits: hits, ecx_minus2: hist, scan_minus2: histScan}; } };
"""


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--pid', type=int, required=True)
    ap.add_argument('--out', required=True)
    ap.add_argument('--port', type=int, default=27053)
    ap.add_argument('--timeout-ms', type=int, default=25000)
    ap.add_argument('--store-off', default='0x18eff2')
    a = ap.parse_args(argv)
    assert 5000 <= a.timeout_ms <= 120000
    assert Path('/proc', str(a.pid), 'comm').read_text().strip().lower() == 'uaro.exe', 'pid nao e uaRO.exe'

    source = JS.replace('STORE_OFF', str(int(a.store_off, 16))).replace('TIMEOUT_MS', str(a.timeout_ms))
    result = {'meta': {'pid': a.pid, 'store_off': a.store_off, 'generated': time.strftime('%Y-%m-%dT%H:%M:%S')}, 'events': []}

    def flush():
        try: Path(a.out).write_text(json.dumps(result, indent=2) + '\n')
        except OSError: pass

    done = {'v': False}

    def on_message(msg, data):
        if msg['type'] == 'send':
            v = msg['payload']; result['events'].append(v); tag = v.get('site')
            if tag == 'READY':
                print('READY store=%s main_tid=%s' % (v.get('store'), v.get('main_tid')), flush=True)
            elif tag == 'hist':
                print('hits=%d ecx-2=%s' % (v['hits'], v['ecx_minus2']), flush=True)
            elif tag == 'DONE':
                print('DONE hits=%d\n  ecx-2 ids=%s\n  scan-2 ids=%s' % (v['hits'], v['ecx_minus2'], v['scan_minus2']), flush=True)
                done['v'] = True
            flush()
        elif msg['type'] == 'error':
            result['events'].append({'site': 'ERROR', 'message': msg.get('description')})
            print('ERROR', msg.get('description'), flush=True); flush()

    dev = frida.get_device_manager().add_remote_device('127.0.0.1:' + str(a.port))
    session = dev.attach('Gadget'); script = None
    try:
        script = session.create_script(source); script.on('message', on_message); script.load()
        deadline = time.time() + a.timeout_ms / 1000.0 + 3
        while time.time() < deadline and not done['v']:
            time.sleep(0.2)
    finally:
        if script is not None:
            try: script.exports_sync.stop()
            except Exception: pass
            try: script.unload()
            except Exception: pass
        try: session.detach()
        except Exception: pass
    flush()
    print(json.dumps({'out': str(Path(a.out).resolve())}, indent=2), flush=True)


if __name__ == '__main__':
    main()
