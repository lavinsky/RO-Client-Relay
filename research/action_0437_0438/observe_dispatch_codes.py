#!/usr/bin/env python3
"""OBSERVADOR SOMENTE-LEITURA (método MOVER aplicado a 0x0437/0x0438).

Pergunta: qual `code` do dispatcher 0xd473b0 origina os pacotes CZ 0x0437 (ação/ataque),
0x0438 (perícia) e 0x0368 (select-by-GID) — análogo a `code 0x11 -> 035f`?

Método (sem chamada nativa, sem injeção, sem patch):
  - DR0 = HW exec BP no dispatcher 0xd473b0 (main): `code=[esp+8]` (válido se `[esp+12]==0 && code<=0x95`);
    registra codes != 0x78 (idle) com os 13 dwords do frame (args: GID do alvo, id/nível de perícia, etc.).
  - DR1 = HW exec BP na SendPacket(this,len,buf) do cliente em uaRO+0x816640 (VA 0xC16640), onde o pacote
    está EM CLARO antes do scrambler do Gepard. Varre os args de pilha [esp+4..esp+16] procurando o ponteiro
    `buf` cujo U16 inicial é um id CZ plausível; emite id + 16 bytes do corpo. (É o que o agente do relay faz:
    `agent/relay_hook_linux.js` sendcall; RVA 0x816640 = `relay/cli.py --sendpacket-rva`.) O scrambler
    gb+0x18eff2 NÃO serve aqui: só dispara no caminho síncrono da chamada direta (06b), não no envio natural.
  - Correlação: para cada SendPacket de id X, o hit de dispatcher imediatamente anterior na main dá o `code`
    que originou X. Ambos levam timestamp (ms).

Layouts (fonte: relay/writeback.py): 0x0437 ACT=[id][GID:4][ação:1] (ataque GID!=0, sentar GID=0);
0x0438 SKILL=[id][nível:2][skill:2][GID:4]; 0x0368 SELECT-by-GID; 0x035f WALK.

O responsável executa, numa janela única: (1) ~3s parado; (2) sentar algumas vezes; (3) atacar um monstro
algumas vezes; (4) usar a MESMA perícia algumas vezes. Read-only: se o cliente travar/alertar Gepard, pare.

Uso: observe_dispatch_codes.py --pid PID --out ARQ [--port 27053] [--timeout-ms 60000]
"""
import argparse
import json
import os
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
var UA_LO = ptr('0x401000'), UA_HI = ptr('0x1717000'), UA_BASE = ptr('0x400000');
var GHI = gb.add(0x2000000);
function region(p) {
  if (p === null) return null;
  if (p.compare(UA_LO) >= 0 && p.compare(UA_HI) < 0) return 'uaRO+' + p.sub(UA_BASE).toString();
  if (p.compare(gb) >= 0 && p.compare(GHI) < 0) return 'gepard+' + p.sub(gb).toString();
  return p.toString();
}

var dispatcher = ptr('DISP_ADDR');
var sendpacket = UA_BASE.add(SENDPKT_RVA);   // SendPacket(this,len,buf) no uaRO.exe (cleartext)
if (sendpacket.compare(UA_LO) < 0 || sendpacket.compare(UA_HI) >= 0)
  throw new Error('SendPacket fora da faixa uaRO: ' + sendpacket);

var th = Process.enumerateThreads().filter(function (t) { return t.id === mainTid; })[0];
if (!th) throw new Error('main thread absent');

var t0 = Date.now();
function ms() { return Date.now() - t0; }

var codeHist = {};
var lastDisp = null;        // {code, ms} último code != idle na main
var dispRecent = [];        // janela recente de codes p/ correlação (code, ms)
var frameSamples = {};
var IDLE = 0x78;
var done = false;

function sampleFrame(c) {
  var f = [];
  for (var k = 0; k < 13; k++) { try { f.push(c.esp.add(4 + k * 4).readU32() >>> 0); } catch (e) { f.push(null); } }
  return f;
}
function plausibleId(v) { return v >= 0x0001 && v <= 0x0fff; }

Process.setExceptionHandler(function (d) {
  if (d.type !== 'breakpoint' || done) return false;
  var c = d.context, pc = c.pc;
  if (pc.equals(dispatcher)) {
    if (Process.getCurrentThreadId() !== mainTid) return true;
    var lo, hi;
    try { lo = c.esp.add(8).readU32() >>> 0; hi = c.esp.add(12).readU32() >>> 0; } catch (e) { return true; }
    var code = (hi === 0 && lo <= 0x95) ? lo : null;
    if (code === null) return true;
    codeHist[code] = (codeHist[code] || 0) + 1;
    if (code !== IDLE) {
      lastDisp = {code: code, ms: ms()};
      dispRecent.push(lastDisp); if (dispRecent.length > 24) dispRecent.shift();
      var n = frameSamples[code] || 0;
      if (n < 3) { frameSamples[code] = n + 1; send({site: 'disp_code', code: code, ms: ms(), frame: sampleFrame(c)}); }
    }
    return true;
  }
  if (pc.equals(sendpacket)) {
    var tid = Process.getCurrentThreadId();
    var args = [], peeks = [], buf = null, id = null;
    for (var j = 1; j <= 4; j++) {
      var a = null; try { a = c.esp.add(j * 4).readPointer(); } catch (e) {}
      args.push(a ? a.toString() : null);
      var pk = null, idv = null;
      if (a !== null) { try { idv = a.readU16(); pk = a.readByteArray(16); } catch (e) {} }
      peeks.push(pk);
      if (buf === null && idv !== null && plausibleId(idv)) { buf = a; id = idv; }
    }
    var now = ms();
    send({site: 'sendpacket', ms: now, tid: tid, on_main: (tid === mainTid),
          id: id, id_hex: id === null ? null : '0x' + id.toString(16),
          args: args, this_ecx: c.ecx.toString(),
          prev_disp_code: lastDisp ? lastDisp.code : null,
          prev_disp_dt_ms: lastDisp ? (now - lastDisp.ms) : null,
          recent_codes: dispRecent.map(function (x) { return x.code; })},
         peeks[0] || peeks[1] || peeks[2] || peeks[3]);
    return true;
  }
  return false;
});

var sm = Module.findGlobalExportByName('sendmsg');
if (sm) {
  Interceptor.attach(sm, { onEnter: function (a) {
    try {
      var msg = a[1], iov = msg.add(8).readPointer(), n = msg.add(12).readU32(), tot = 0;
      for (var i = 0; i < Math.min(n, 32); i++) tot += iov.add(i * 8 + 4).readU32();
      if (tot > 0 && tot <= 64) send({site: 'sendmsg', bytes: tot, ms: ms()});
    } catch (e) {}
  }});
}

function armAll() { th.setHardwareBreakpoint(0, dispatcher); th.setHardwareBreakpoint(1, sendpacket); }
function disarmAll() { try { th.unsetHardwareBreakpoint(0); } catch (e) {} try { th.unsetHardwareBreakpoint(1); } catch (e) {} }
try { armAll(); } catch (e) { throw new Error('HW BP failed: ' + e.message); }
send({site: 'READY', read_only: true, main_tid: mainTid, gepard_base: gb.toString(),
      dispatcher: dispatcher.toString(), sendpacket: sendpacket.toString(), idle_code: IDLE});

setTimeout(function () { done = true; disarmAll(); send({site: 'DONE', elapsed_ms: ms(), code_histogram: codeHist}); }, TIMEOUT_MS);
rpc.exports = { stop: function () { done = true; disarmAll(); return {code_histogram: codeHist}; } };
"""


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--pid', type=int, required=True)
    ap.add_argument('--out', required=True)
    ap.add_argument('--port', type=int, default=27053)
    ap.add_argument('--timeout-ms', type=int, default=60000)
    ap.add_argument('--dispatcher', default='0xd473b0')
    ap.add_argument('--sendpacket-rva', default='0x816640')
    a = ap.parse_args(argv)
    assert 5000 <= a.timeout_ms <= 180000, 'timeout fora de faixa'
    assert Path('/proc', str(a.pid), 'comm').read_text().strip().lower() == 'uaro.exe', 'pid nao e uaRO.exe'

    source = (JS.replace('DISP_ADDR', a.dispatcher)
                .replace('SENDPKT_RVA', str(int(a.sendpacket_rva, 16)))
                .replace('TIMEOUT_MS', str(a.timeout_ms)))
    result = {'meta': {'pid': a.pid, 'dispatcher': a.dispatcher, 'sendpacket_rva': a.sendpacket_rva,
                       'generated': time.strftime('%Y-%m-%dT%H:%M:%S')}, 'events': []}

    def flush():
        try:
            Path(a.out).write_text(json.dumps(result, indent=2) + '\n')
        except OSError:
            pass

    done = {'v': False}

    def on_message(msg, data):
        if msg['type'] == 'send':
            v = msg['payload']
            if data is not None:
                try:
                    v = dict(v); v['body_hex'] = data.hex()
                except Exception:
                    pass
            result['events'].append(v)
            tag = v.get('site')
            if tag == 'READY':
                print('READY main_tid=%s sendpacket=%s' % (v.get('main_tid'), v.get('sendpacket')), flush=True)
            elif tag == 'disp_code':
                print('disp_code 0x%x ms=%s frame=%s' % (v['code'], v['ms'], v.get('frame')), flush=True)
            elif tag == 'sendpacket':
                print('SENDPKT id=%s ms=%s prev_code=%s dt=%s recent=%s body=%s' % (
                    v.get('id_hex'), v['ms'], v.get('prev_disp_code'), v.get('prev_disp_dt_ms'),
                    [hex(x) for x in (v.get('recent_codes') or [])], v.get('body_hex')), flush=True)
            elif tag == 'DONE':
                print('DONE elapsed=%s code_hist=%s' % (v.get('elapsed_ms'), v.get('code_histogram')), flush=True)
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
    sp = [e for e in result['events'] if e.get('site') == 'sendpacket']
    mapping = {}
    for e in sp:
        if e.get('id_hex'):
            mapping.setdefault(e['id_hex'], {'prev_codes': {}, 'count': 0})
            mapping[e['id_hex']]['count'] += 1
            pc = e.get('prev_disp_code')
            if pc is not None:
                mapping[e['id_hex']]['prev_codes'][hex(pc)] = mapping[e['id_hex']]['prev_codes'].get(hex(pc), 0) + 1
    print(json.dumps({'out': os.path.abspath(a.out), 'sendpacket_count': len(sp),
                      'id_to_prev_disp_code': mapping}, indent=2), flush=True)


if __name__ == '__main__':
    main()
