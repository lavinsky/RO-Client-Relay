#!/usr/bin/env python3
"""CAPTURA READ-ONLY da cadeia EXATA de chamadores do dispatcher 0xd473b0 via walk de EBP.

Substitui o backtrace FUZZY (heuristico, deu falsos positivos) por um walk da cadeia de frame pointers:
no HW exec BP de entrada do dispatcher (antes do prologo dele), ebp = frame do chamador que montou quadro;
[ebp+4] = return addr, ebp = [ebp]. As funcoes do uaRO usam frame pointer, entao isso da a cadeia real.
Objetivo: achar o sitio real de disparo do `0x2a` (skill-fire) vs `0x29`/`0x5a` (prepare) e `0x11` (move).
Valida cada frame (ebp crescente e legivel; retaddr em regiao de codigo). NENHUM disparo/escrita — so leitura.

O responsavel: parado ~3s, entao Soul Strike 3-4x num monstro; opcional atacar 1-2x (0x28). Read-only.
Uso: capture_skill_ebp.py --pid PID --out ARQ [--port 27053] [--timeout-ms 75000]
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
function inCode(p) {
  if (p === null) return false;
  if (p.compare(UA_LO) >= 0 && p.compare(UA_HI) < 0) return true;
  if (gb && p.compare(gb) >= 0 && p.compare(GHI) < 0) return true;
  return false;
}
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
var capCount = {}, MAXPER = 4;
var done = false;
var t0 = Date.now();
function ms() { return Date.now() - t0; }

function ebpWalk(ebp) {
  var out = [], guard = ebp;
  for (var i = 0; i < 14; i++) {
    if (ebp === null) break;
    var ra = null, nx = null;
    try { ra = ebp.add(4).readPointer(); nx = ebp.readPointer(); } catch (e) { break; }
    out.push({ebp: ebp.toString(), ret: region(ra), code: inCode(ra)});
    if (nx === null || nx.compare(ebp) <= 0) break;           // ebp deve crescer
    if (nx.sub(ebp).compare(ptr('0x100000')) > 0) break;      // salto absurdo => parar
    ebp = nx;
  }
  return out;
}

Process.setExceptionHandler(function (d) {
  if (d.type !== 'breakpoint' || done) return false;
  var c = d.context;
  if (!c.pc.equals(dispatcher)) return false;
  if (Process.getCurrentThreadId() !== mainTid) return true;
  var lo, hi;
  try { lo = c.esp.add(8).readU32() >>> 0; hi = c.esp.add(12).readU32() >>> 0; } catch (e) { return true; }
  if (!(hi === 0 && lo <= 0x95) || lo === IDLE || !WANT[lo]) return true;
  if ((capCount[lo] || 0) >= MAXPER) return true;
  capCount[lo] = (capCount[lo] || 0) + 1;

  var espRet = null; try { espRet = c.esp.readPointer(); } catch (e) {}
  var frame = [];
  for (var k = 0; k < 6; k++) { try { frame.push(c.esp.add(4 + k * 4).readU32() >>> 0); } catch (e) { frame.push(null); } }
  send({site: 'caller', ms: ms(), code: lo, code_hex: '0x' + lo.toString(16), name: WANT[lo],
        esp_ret: region(espRet), ebp: c.ebp.toString(), frame: frame, ebp_chain: ebpWalk(c.ebp)});
  return true;
});

try { th.setHardwareBreakpoint(0, dispatcher); } catch (e) { throw new Error('HW BP failed: ' + e.message); }
send({site: 'READY', ms: ms(), main_tid: mainTid, gepard_base: gb ? gb.toString() : null, dispatcher: dispatcher.toString()});
setTimeout(function () { done = true; try { th.unsetHardwareBreakpoint(0); } catch (e) {}
  send({site: 'DONE', ms: ms(), capCount: capCount}); }, TIMEOUT_MS);
rpc.exports = { stop: function () { done = true; try { th.unsetHardwareBreakpoint(0); } catch (e) {} return capCount; } };
"""


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--pid', type=int, required=True)
    ap.add_argument('--out', required=True)
    ap.add_argument('--port', type=int, default=27053)
    ap.add_argument('--timeout-ms', type=int, default=75000)
    a = ap.parse_args(argv)
    assert 5000 <= a.timeout_ms <= 180000, 'timeout fora de faixa'
    assert Path('/proc', str(a.pid), 'comm').read_text().strip().lower() == 'uaro.exe', 'pid nao e uaRO.exe'

    source = JS.replace('TIMEOUT_MS', str(a.timeout_ms))
    result = {'meta': {'pid': a.pid, 'generated': time.strftime('%Y-%m-%dT%H:%M:%S'),
                       'task': 'read-only EBP-chain caller capture for dispatcher skill/move codes'}, 'events': []}

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
                chain = ' <- '.join([f['ret'] for f in v.get('ebp_chain', []) if f.get('code')][:8])
                print('CALLER %s %-12s esp_ret=%s | ebp-chain(code): %s' % (
                    v['code_hex'], v['name'], v.get('esp_ret'), chain), flush=True)
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
    # resumo: por code, a cadeia de retornos em codigo (exata) mais frequente
    byc = {}
    for e in result['events']:
        if e.get('site') == 'caller':
            chain = tuple(f['ret'] for f in e.get('ebp_chain', []) if f.get('code'))
            byc.setdefault(e['code_hex'] + ' ' + e['name'], {})
            byc[e['code_hex'] + ' ' + e['name']][chain] = byc[e['code_hex'] + ' ' + e['name']].get(chain, 0) + 1
    summary = {k: [{'count': n, 'chain': list(ch)} for ch, n in sorted(v.items(), key=lambda x: -x[1])]
               for k, v in byc.items()}
    print(json.dumps({'out': str(Path(a.out).resolve()), 'exact_ebp_chains_by_code': summary}, indent=2), flush=True)


if __name__ == '__main__':
    main()
