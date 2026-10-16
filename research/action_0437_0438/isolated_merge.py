#!/usr/bin/env python3
"""TESTE ISOLADO da substituicao (merge) do 0x0437 — SEM relay e SEM consumidor (OpenKore).

Objetivo (pedido do responsavel): "replacing a single 0437 with attack by pressing insert". Arma UM
corpo 0x0437 e reescreve, no proprio scrambler do cliente (store gepard+0x18eff2, pre-XOR, in-place),
o carrier natural que o cliente constroi quando aperto INSERT (sentar). Isola o mecanismo do relay e
do OpenKore para responder a hipotese do responsavel: "a relay must have got on to the wrong address".

Diferencas vs o agente do relay (de proposito, para diagnosticar):
  - SEM filtro de faixa (scramble-range): registra o endereco do buffer do carrier e marca se cai na
    janela velha 0x2632000-0x2730000 (se cair FORA, a faixa fixa do relay era a causa).
  - Arma um unico corpo conhecido (marcador por padrao) e loga `was=<pre-XOR do cliente> -> <armado>`
    a cada escrita, com o registrador/offset usados e o endereco.

Logica de match igual a do agente (auto): a cada hit do store, varre eax/ebx/ecx/edx/esi/edi/ebp; se
[reg+off] (off em {-2,0}) == 0x0437, escreve os 5 bytes do corpo em reg+off+2. Read-only fora isso.

NAO autoriza nada: alvo e o cliente autorizado do responsavel (servidor proprio). Requer DR0 livre
(pare o relay). Pare se o cliente travar.

Uso:
    isolated_merge.py --pid PID [--port 27053] [--body <10 hex>] [--timeout-ms 60000]
      --body: 5 bytes do corpo 0x0437 = GID alvo (4, little-endian) + acao (1). Ex. ataque continuo
              em GID 0x068ec1ae: 'aec18e0607'. Padrao: 'efbeadde07' (GID 0xdeadbeef marcador, acao 07)
              — serve so para PROVAR o mecanismo/endereco (o servidor ignora GID inexistente).
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

var BODY = BODY_BYTES;                 // Array de 5 ints (corpo armado)
var WANT = 0x0437;
var OFFS = [-2, 0];
var REGS = ['eax','ebx','ecx','edx','esi','edi','ebp'];
var RLO = ptr('0x2632000'), RHI = ptr('0x2730000');  // janela velha do relay (so p/ marcar in/out)
var wrote = 0, hits = 0, done = false;

function toHex(p, n) { try { var u = new Uint8Array(p.readByteArray(n)); var s=''; for (var i=0;i<u.length;i++){var h=u[i].toString(16); s+=(h.length<2?'0':'')+h;} return s; } catch(e){ return null; } }

Process.setExceptionHandler(function (d) {
  if (d.type !== 'breakpoint' || done) return false;
  var c = d.context;
  if (!c.pc.equals(store)) return false;
  if (Process.getCurrentThreadId() !== mainTid) return true;
  hits++;
  var cand = {eax:c.eax, ebx:c.ebx, ecx:c.ecx, edx:c.edx, esi:c.esi, edi:c.edi, ebp:c.ebp};
  for (var rn in cand) {
    var r = cand[rn];
    if (!(r instanceof NativePointer) || r.isNull()) continue;
    for (var ci = 0; ci < OFFS.length; ci++) {
      var off = OFFS[ci], idv;
      try { idv = r.add(off).readU16(); } catch (e) { continue; }
      if (idv !== WANT) continue;
      var bodyp = r.add(off + 2);
      var was = toHex(bodyp, BODY.length);
      var inRange = (bodyp.compare(RLO) >= 0 && bodyp.compare(RHI) < 0);
      try {
        for (var i = 0; i < BODY.length; i++) bodyp.add(i).writeU8(BODY[i]);
        wrote++;
        send({tag:'WROTE', n:wrote, hits:hits, reg:rn, off:off, addr:bodyp.toString(),
              in_old_range:inRange, was:was, now:toHex(bodyp, BODY.length)});
      } catch (e) { send({tag:'ERR', e:'write: '+e.message}); }
      return true;   // escreveu neste hit; proximo hit
    }
  }
  return true;
});

try { th.setHardwareBreakpoint(0, store); } catch (e) { throw new Error('HW BP failed: ' + e.message); }
send({tag:'READY', main_tid:mainTid, gepard_base:gb.toString(), store:store.toString(), body:BODY});
setTimeout(function () { done = true; try { th.unsetHardwareBreakpoint(0); } catch (e) {}
  send({tag:'DONE', hits:hits, wrote:wrote}); }, TIMEOUT_MS);
rpc.exports = { stop: function () { done = true; try { th.unsetHardwareBreakpoint(0); } catch (e) {} return {hits:hits, wrote:wrote}; } };
"""


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('--pid', type=int, required=True)
    ap.add_argument('--port', type=int, default=27053)
    ap.add_argument('--body', default='efbeadde07', help='5 bytes hex: GID(4 LE)+acao(1)')
    ap.add_argument('--out', default=None)
    ap.add_argument('--timeout-ms', type=int, default=60000)
    ap.add_argument('--store-off', default='0x18eff2')
    a = ap.parse_args(argv)
    assert 5000 <= a.timeout_ms <= 300000
    assert Path('/proc', str(a.pid), 'comm').read_text().strip().lower() == 'uaro.exe', 'pid nao e uaRO.exe'
    body = bytes.fromhex(a.body)
    assert len(body) == 5, 'corpo 0x0437 tem 5 bytes (10 hex)'

    source = (JS.replace('STORE_OFF', str(int(a.store_off, 16)))
                .replace('BODY_BYTES', json.dumps(list(body)))
                .replace('TIMEOUT_MS', str(a.timeout_ms)))
    result = {'meta': {'pid': a.pid, 'body': a.body, 'generated': time.strftime('%Y-%m-%dT%H:%M:%S')}, 'events': []}

    def flush():
        if a.out:
            try: Path(a.out).write_text(json.dumps(result, indent=2) + '\n')
            except OSError: pass

    done = {'v': False}

    def on_message(msg, data):
        if msg['type'] == 'send':
            v = msg['payload']; result['events'].append(v); tag = v.get('tag')
            if tag == 'READY':
                print('READY store=%s body=%s' % (v.get('store'), v.get('body')), flush=True)
            elif tag == 'WROTE':
                print('WROTE #%d hits=%d reg=%s off=%d addr=%s in_old_range=%s  was=%s -> now=%s'
                      % (v['n'], v['hits'], v['reg'], v['off'], v['addr'], v['in_old_range'], v['was'], v['now']), flush=True)
            elif tag == 'DONE':
                print('DONE hits=%d wrote=%d' % (v['hits'], v['wrote']), flush=True); done['v'] = True
            elif tag == 'ERR':
                print('ERR', v.get('e'), flush=True)
            flush()
        elif msg['type'] == 'error':
            print('SCRIPT-ERROR', msg.get('description'), flush=True)
            result['events'].append({'tag': 'ERROR', 'message': msg.get('description')}); flush()

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


if __name__ == '__main__':
    main()
