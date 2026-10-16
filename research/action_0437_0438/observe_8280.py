#!/usr/bin/env python3
"""OBSERVADOR SOMENTE-LEITURA do 0x8280 ao redor das ações (0x0437/0x0438/0x0AF4) — Fase 1.

Hipótese sob teste (ver docs/GEPARD_CONTROL_PACKETS.md e o plano da trilha): um 0x8280
(candidato a CS_GEPARD_SYNC do uaRO; análogo 2016 em
relay/resources/Gepard-SRC-LGP-master/src/common/socket.cpp:411 e .../map/clif.cpp:79)
sai IMEDIATAMENTE ANTES de todo 0x0437/0x0438/0x0AF4 e gateia a ação no servidor.

Perguntas que esta sonda responde (read-only, sem injeção/patch/chamada nativa):
  1. ORDEM: antes de cada ação (0437/0438/0AF4), sai um pacote pequeno (o 8280)?
  2. ORIGEM do 8280: ele passa pela SendPacket do CLIENTE (em claro, id 0x8280 visível)
     ou é emitido pelo GEPARD internamente (invisível na SendPacket; só aparece no
     sendmsg como uma escrita pequena, já cifrada)?
  3. FORMA: comprimento do 8280; o corpo (em claro, se client-origin) muda por ação?
  4. RANGE: em que faixa de memória vivem os buffers das ações (arg `buf` da SendPacket) —
     insumo para configurar scramble-range das ações no merge (relay_capture.conf).

Método:
  - DR0 = HW exec BP na SendPacket(this,len,buf) do cliente em uaRO+0x816640 (VA 0xC16640),
    onde o pacote está EM CLARO antes do scrambler (gb+0x18eff2). HW BP não é detectável
    pelo check de integridade byte-a-byte do Gepard (ao contrário de hook inline). Registra
    TODOS os ids de saída do cliente (não só ações), com id, 32 B de corpo, ms e ptr do buf.
  - Interceptor em libc `sendmsg` (fora do Gepard, seguro): registra o TAMANHO e ms de cada
    egress real. Uma escrita minúscula (~6-8 B) logo antes do egress da ação = o 8280
    (mesmo cifrado, distinguível por tamanho/tempo).
  - Correlação na saída: para cada ação, lista os ids de SendPacket imediatamente anteriores
    e os tamanhos de sendmsg imediatamente anteriores; e resume a faixa de `buf` por id.

Procedimento (responsável, janela única, read-only; pare se o cliente travar/alertar):
  (1) ~3 s parado; (2) atacar um monstro 3-4×; (3) usar a MESMA perícia em alvo 3-4×;
  (4) usar uma perícia de CHÃO 3-4×. Cada passo gera a ação e, se a hipótese valer, o 8280.

Uso: observe_8280.py --pid PID --out ARQ [--port 27053] [--timeout-ms 60000]
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

var sendpacket = UA_BASE.add(SENDPKT_RVA);   // SendPacket(this,len,buf) no uaRO.exe (cleartext)
if (sendpacket.compare(UA_LO) < 0 || sendpacket.compare(UA_HI) >= 0)
  throw new Error('SendPacket fora da faixa uaRO: ' + sendpacket);

var th = Process.enumerateThreads().filter(function (t) { return t.id === mainTid; })[0];
if (!th) throw new Error('main thread absent');

var t0 = Date.now();
function ms() { return Date.now() - t0; }

var ACTION_IDS = {0x0437: 1, 0x0438: 1, 0x0af4: 1};
var SYNC_ID = 0x8280;
var done = false;

var sendpktRecent = [];   // janela recente de ids vistos na SendPacket do cliente {id, ms}
var sendmsgRecent = [];   // janela recente de egress reais {bytes, ms}
function pushRecent(arr, v) { arr.push(v); if (arr.length > 16) arr.shift(); }
function plausibleId(v) { return v >= 0x0001 && v <= 0xffff; }

Process.setExceptionHandler(function (d) {
  if (d.type !== 'breakpoint' || done) return false;
  var c = d.context, pc = c.pc;
  if (pc.equals(sendpacket)) {
    if (Process.getCurrentThreadId() !== mainTid) return true;
    var buf = null, id = null, body = null, lenArg = null;
    // varre os args de pilha procurando o ponteiro buf cujo U16 inicial é um id plausível
    for (var j = 1; j <= 4; j++) {
      var a = null; try { a = c.esp.add(j * 4).readPointer(); } catch (e) {}
      if (a === null) continue;
      var idv = null;
      try { idv = a.readU16(); } catch (e) {}
      if (idv !== null && plausibleId(idv)) {
        buf = a; id = idv;
        try { body = a.readByteArray(32); } catch (e) { body = null; }
        break;
      }
    }
    try { lenArg = c.esp.add(8).readU32() >>> 0; } catch (e) {}
    if (id === null) return true;
    var now = ms();
    var isAction = !!ACTION_IDS[id];
    pushRecent(sendpktRecent, {id: id, ms: now});
    var out = {site: 'sendpacket', ms: now, id: id, id_hex: '0x' + id.toString(16),
               is_action: isAction, is_sync: (id === SYNC_ID),
               buf: buf ? buf.toString() : null, buf_region: region(buf), len_arg: lenArg,
               prev_sendpkt_ids: sendpktRecent.slice(0, -1).map(function (x) { return '0x' + x.id.toString(16); }),
               recent_sendmsg_bytes: sendmsgRecent.map(function (x) { return x.bytes; })};
    send(out, body);
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
      if (tot > 0 && tot <= 256) { var now = ms(); pushRecent(sendmsgRecent, {bytes: tot, ms: now});
        send({site: 'sendmsg', bytes: tot, ms: now, small: (tot <= 12)}); }
    } catch (e) {}
  }});
}

function arm() { th.setHardwareBreakpoint(0, sendpacket); }
function disarm() { try { th.unsetHardwareBreakpoint(0); } catch (e) {} }
try { arm(); } catch (e) { throw new Error('HW BP failed: ' + e.message); }
send({site: 'READY', read_only: true, main_tid: mainTid, gepard_base: gb.toString(),
      sendpacket: sendpacket.toString(), sync_id: '0x' + SYNC_ID.toString(16),
      action_ids: Object.keys(ACTION_IDS).map(function (k) { return '0x' + (k >>> 0).toString(16); })});

setTimeout(function () { done = true; disarm(); send({site: 'DONE', elapsed_ms: ms()}); }, TIMEOUT_MS);
rpc.exports = { stop: function () { done = true; disarm(); return {elapsed_ms: ms()}; } };
"""


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--pid', type=int, required=True)
    ap.add_argument('--out', required=True)
    ap.add_argument('--port', type=int, default=27053)
    ap.add_argument('--timeout-ms', type=int, default=60000)
    ap.add_argument('--sendpacket-rva', default='0x816640')
    a = ap.parse_args(argv)
    assert 5000 <= a.timeout_ms <= 180000, 'timeout fora de faixa'
    assert Path('/proc', str(a.pid), 'comm').read_text().strip().lower() == 'uaro.exe', 'pid nao e uaRO.exe'

    source = (JS.replace('SENDPKT_RVA', str(int(a.sendpacket_rva, 16)))
                .replace('TIMEOUT_MS', str(a.timeout_ms)))
    result = {'meta': {'pid': a.pid, 'sendpacket_rva': a.sendpacket_rva,
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
                print('READY main_tid=%s sendpacket=%s sync=%s' % (
                    v.get('main_tid'), v.get('sendpacket'), v.get('sync_id')), flush=True)
            elif tag == 'sendpacket':
                print('SENDPKT id=%s%s%s ms=%s buf=%s prev=%s recent_sendmsg=%s body=%s' % (
                    v.get('id_hex'), ' [ACTION]' if v.get('is_action') else '',
                    ' [SYNC]' if v.get('is_sync') else '', v['ms'], v.get('buf_region'),
                    v.get('prev_sendpkt_ids'), v.get('recent_sendmsg_bytes'), v.get('body_hex')), flush=True)
            elif tag == 'sendmsg' and v.get('small'):
                print('sendmsg SMALL bytes=%s ms=%s' % (v.get('bytes'), v['ms']), flush=True)
            elif tag == 'DONE':
                print('DONE elapsed=%s' % v.get('elapsed_ms'), flush=True)
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

    # --- resumo: ações, o que as precede, e faixas de buf por id ---
    ev = result['events']
    sp = [e for e in ev if e.get('site') == 'sendpacket']
    actions = [e for e in sp if e.get('is_action')]
    sync_seen_on_sendpacket = any(e.get('is_sync') for e in sp)
    # faixa de buf por id (insumo p/ scramble-range das ações)
    buf_by_id = {}
    for e in sp:
        if e.get('buf'):
            idh = e['id_hex']
            buf_by_id.setdefault(idh, {'min': None, 'max': None, 'region_example': e.get('buf_region'), 'count': 0})
            val = int(e['buf'], 16)
            b = buf_by_id[idh]
            b['count'] += 1
            b['min'] = val if b['min'] is None else min(b['min'], val)
            b['max'] = val if b['max'] is None else max(b['max'], val)
    for b in buf_by_id.values():
        if b['min'] is not None:
            b['min'] = hex(b['min']); b['max'] = hex(b['max'])
    action_preamble = [{
        'action': e['id_hex'], 'ms': e['ms'],
        'prev_sendpkt_ids': e.get('prev_sendpkt_ids'),
        'recent_sendmsg_bytes': e.get('recent_sendmsg_bytes'),
    } for e in actions]
    summary = {
        'out': os.path.abspath(a.out),
        'sendpacket_count': len(sp),
        'action_count': len(actions),
        'sync_0x8280_seen_on_client_sendpacket': sync_seen_on_sendpacket,
        'interpretation_hint': ('8280 is CLIENT-origin (visible in cleartext at SendPacket)'
                                if sync_seen_on_sendpacket
                                else '8280 NOT seen at SendPacket -> likely GEPARD-origin; '
                                     'look for a small (~6-8B) sendmsg right before each action'),
        'action_preamble': action_preamble,
        'buf_range_by_id': buf_by_id,
    }
    print(json.dumps(summary, indent=2), flush=True)


if __name__ == '__main__':
    main()
