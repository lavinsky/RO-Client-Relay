#!/usr/bin/env python3
"""CAPTURA READ-ONLY dos CHAMADORES do dispatcher 0xd473b0 para as codes de interesse.

Objetivo: descobrir DE ONDE a conjuracao natural dispara a cadeia de pericia (`0x29` set-skill+GID,
`0x5a` set-nivel, `0x2a` dispara) — i.e., o sitio de dispatch do handler de input — e comparar com o
movimento (`0x11`), que funciona disparado do fire-site de main-loop 0x4dcba0. Hipotese a testar depois:
a skill so comete quando disparada do contexto/ sitio do input (que seta um flag/alvo que o `0x2a` le e,
fora dele, devolve 0). NENHUM disparo/escrita aqui — so HW exec BP (DR0) lendo retorno + backtrace.

Metodo: DR0 no dispatcher; em cada hit na main, le code=[esp+8]; se for code de interesse e != idle,
grava retaddr=[esp] e um backtrace (FUZZY) resolvido para uaRO+off / gepard+off. Amostra limitada por code.

O responsavel: fica parado ~3s, entao conjura Soul Strike algumas vezes num monstro; opcional atacar/mover
para comparacao. Read-only: se travar/alertar, pare.

Uso: capture_skill_callers.py --pid PID --out ARQ [--port 27053] [--timeout-ms 60000]
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
var UA_BASE = ptr('0x400000'), UA_LO = ptr('0x401000'), UA_HI = ptr('0x1717000');
var GHI = gb ? gb.add(0x2000000) : null;
function region(p) {
  if (p === null) return null;
  if (p.compare(UA_LO) >= 0 && p.compare(UA_HI) < 0) return 'uaRO+' + p.sub(UA_BASE).toString();
  if (gb && p.compare(gb) >= 0 && p.compare(GHI) < 0) return 'gepard+' + p.sub(gb).toString();
  return p.toString();
}

var dispatcher = ptr('0xd473b0');
if (!Process.findRangeByAddress(dispatcher)) throw new Error('dispatcher unmapped');
var th = Process.enumerateThreads().filter(function (t) { return t.id === mainTid; })[0];
if (!th) throw new Error('main thread absent');

var IDLE = 0x78;
var WANT = {0x11: 'move', 0x28: 'attack', 0x1f: 'sit/stand', 0x0a: 'select',
            0x29: 'skill-set', 0x5a: 'skill-level', 0x2a: 'skill-fire'};
var capCount = {};
var MAXPER = 5;
var done = false;

var t0 = Date.now();
function ms() { return Date.now() - t0; }

Process.setExceptionHandler(function (d) {
  if (d.type !== 'breakpoint' || done) return false;
  var c = d.context;
  if (!c.pc.equals(dispatcher)) return false;
  if (Process.getCurrentThreadId() !== mainTid) return true;
  var lo, hi;
  try { lo = c.esp.add(8).readU32() >>> 0; hi = c.esp.add(12).readU32() >>> 0; } catch (e) { return true; }
  if (!(hi === 0 && lo <= 0x95) || lo === IDLE) return true;
  if (!WANT[lo]) return true;
  if ((capCount[lo] || 0) >= MAXPER) return true;
  capCount[lo] = (capCount[lo] || 0) + 1;

  var ret = null; try { ret = c.esp.readPointer(); } catch (e) {}
  var frame = [];
  for (var k = 0; k < 6; k++) { try { frame.push(c.esp.add(4 + k * 4).readU32() >>> 0); } catch (e) { frame.push(null); } }
  var bt = [];
  try {
    Thread.backtrace(c, Backtracer.FUZZY).slice(0, 10).forEach(function (a) { bt.push(region(a)); });
  } catch (e) {}
  send({site: 'caller', ms: ms(), code: lo, code_hex: '0x' + lo.toString(16), name: WANT[lo],
        retaddr: ret ? ret.toString() : null, retaddr_region: region(ret),
        frame: frame, backtrace: bt});
  return true;
});

try { th.setHardwareBreakpoint(0, dispatcher); } catch (e) { throw new Error('HW BP failed: ' + e.message); }
send({site: 'READY', ms: ms(), main_tid: mainTid, gepard_base: gb ? gb.toString() : null,
      dispatcher: dispatcher.toString(), want: Object.keys(WANT)});
setTimeout(function () { done = true; try { th.unsetHardwareBreakpoint(0); } catch (e) {}
  send({site: 'DONE', ms: ms(), capCount: capCount}); }, TIMEOUT_MS);
rpc.exports = { stop: function () { done = true; try { th.unsetHardwareBreakpoint(0); } catch (e) {} return capCount; } };
"""


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--pid', type=int, required=True)
    ap.add_argument('--out', required=True)
    ap.add_argument('--port', type=int, default=27053)
    ap.add_argument('--timeout-ms', type=int, default=60000)
    a = ap.parse_args(argv)
    assert 5000 <= a.timeout_ms <= 180000, 'timeout fora de faixa'
    assert Path('/proc', str(a.pid), 'comm').read_text().strip().lower() == 'uaro.exe', 'pid nao e uaRO.exe'

    source = JS.replace('TIMEOUT_MS', str(a.timeout_ms))
    result = {'meta': {'pid': a.pid, 'generated': time.strftime('%Y-%m-%dT%H:%M:%S'),
                       'task': 'read-only capture of dispatcher callers for skill/move codes'}, 'events': []}

    def flush():
        try:
            Path(a.out).write_text(json.dumps(result, indent=2) + '\n')
        except OSError:
            pass

    done = {'v': False}

    def on_message(msg, data):
        if msg['type'] == 'send':
            v = msg['payload']
            result['events'].append(v)
            tag = v.get('site')
            if tag == 'READY':
                print('READY main_tid=%s gepard=%s' % (v.get('main_tid'), v.get('gepard_base')), flush=True)
            elif tag == 'caller':
                print('CALLER %s %s ret=%s bt=%s' % (v['code_hex'], v['name'], v.get('retaddr_region'),
                                                     v.get('backtrace')), flush=True)
            elif tag == 'DONE':
                print('DONE capCount=%s' % v.get('capCount'), flush=True)
                done['v'] = True
            flush()
        elif msg['type'] == 'error':
            result['events'].append({'site': 'ERROR', 'message': msg.get('description')})
            print('ERROR', msg.get('description'), flush=True)
            flush()

    dev = frida.get_device_manager().add_remote_device('127.0.0.1:' + str(a.port))
    session = dev.attach('Gadget')
    script = None
    try:
        script = session.create_script(source)
        script.on('message', on_message)
        script.load()
        deadline = time.time() + a.timeout_ms / 1000.0 + 3
        while time.time() < deadline and not done['v']:
            time.sleep(0.2)
    finally:
        if script is not None:
            try:
                script.exports_sync.stop()
            except Exception:
                pass
            try:
                script.unload()
            except Exception:
                pass
        try:
            session.detach()
        except Exception:
            pass
    flush()
    callers = {}
    for e in result['events']:
        if e.get('site') == 'caller':
            callers.setdefault(e['code_hex'] + ' ' + e['name'], set()).add(e.get('retaddr_region'))
    print(json.dumps({'out': str(Path(a.out).resolve()),
                      'retaddr_by_code': {k: sorted(v) for k, v in callers.items()}}, indent=2), flush=True)


if __name__ == '__main__':
    main()
