#!/usr/bin/env python3
"""Rodada MOVER-...-05, ETAPA 2c (SOMENTE LEITURA): Frida não vê uaRO/gepard como módulos PE (Proton
new-WoW64; só .so unix são módulos), e o send da libc fica no lado unix da fronteira de syscall. Então
vou ao flush pelo lado PE SEM hookar ws2_32: capturo o endereço de retorno natural do dispatcher (o
sítio em gepard logo após a call ao dispatcher 0xd473b0) via HW exec BP, e DESMONTO em memória o código
a partir dali — é a continuação que, no fluxo natural, enfileira+flusha o 0x035F (a rodada 04 mostrou
que a chamada direta, que NÃO passa por aqui, monta mas não envia). Identifica o ponto de flush e as
`call` candidatas (função de envio do jogo) e sua ABI/contexto para a rodada 06.

HW exec BP (não detectável) + leitura/desmontagem de memória. Sem chamada nativa, sem hook em código.
Uso: disasm_postdispatch.py --pid PID --out ARQ [--port 27053] [--count 90] [--timeout-ms 40000]
"""
import argparse
import json
import os
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
var UA_IMAGEBASE = ptr('0x400000'), LO = ptr('0x401000'), HI = ptr('0x1717000');
var GHI = gb.add(0x2000000);
function region(p) {
  if (p === null) return null;
  if (p.compare(LO) >= 0 && p.compare(HI) < 0) return 'uaRO+' + p.sub(UA_IMAGEBASE).toString();
  if (p.compare(gb) >= 0 && p.compare(GHI) < 0) return 'gepard+' + p.sub(gb).toString();
  var m = Process.findModuleByAddress(p); if (m) return m.name + '+' + p.sub(m.base).toString();
  return p.toString();
}

var dispatcher = ptr('0xd473b0');
var th = Process.enumerateThreads().filter(function (t) { return t.id === mainTid; })[0];
if (!th) throw new Error('main thread absent');
var armed = false, done = false;

function disasmFrom(start, count) {
  var out = [], p = start;
  for (var i = 0; i < count; i++) {
    var ins;
    try { ins = Instruction.parse(p); } catch (e) { out.push({addr: region(p), raw: 'parse_error:' + e.message}); break; }
    var row = {addr: region(p), abs: p.toString(), mnemonic: ins.mnemonic, op: ins.opStr};
    if (/^(call|jmp)/.test(ins.mnemonic)) {
      // tentar resolver alvo direto
      var t = ins.opStr.trim();
      if (/^0x[0-9a-f]+$/i.test(t)) { try { row.target = region(ptr(t)); } catch (e) {} }
    }
    if (ins.mnemonic === 'ret' || ins.mnemonic === 'retn') { out.push(row); break; }
    out.push(row); p = ins.next;
  }
  return out;
}

Process.setExceptionHandler(function (d) {
  if (d.type !== 'breakpoint' || !armed || done) return false;
  var c = d.context; if (!c.pc.equals(dispatcher)) return false;
  // frame do dispatcher: code em [esp+8]? (igual aos probes anteriores: esp+8=lo, esp+12=hi)
  try {
    var lo = c.esp.add(8).readU32(), hi = c.esp.add(12).readU32();
    var code = (hi === 0 && lo <= 0x95) ? lo : null;
    if (code !== 0x11) return true;                      // só o caso de andar
    var retAddr = c.esp.readPointer();
    done = true;
    var win_before = [];
    // janela curta antes do retorno (contexto do chamador) — desmonta a partir de retAddr-0x20 best-effort
    var res = {site: 'post_dispatch_disasm', gepard_base: gb.toString(),
               dispatcher: dispatcher.toString(),
               natural_return_addr: retAddr.toString(), natural_return_region: region(retAddr),
               this_ecx: c.ecx.toString(),
               forward: disasmFrom(retAddr, COUNT)};
    send({tag: 'CAP', data: res});
    try { th.unsetHardwareBreakpoint(0); armed = false; } catch (e) {}
    return true;
  } catch (e) { send({tag: 'HERR', message: e.message}); return true; }
});
try { th.setHardwareBreakpoint(0, dispatcher); armed = true; } catch (e) { throw new Error('HW BP failed: ' + e.message); }
send({tag: 'READY', read_only: true, main_tid: mainTid, gepard_base: gb.toString(), dispatcher: dispatcher.toString()});
setTimeout(function () { try { if (armed) th.unsetHardwareBreakpoint(0); } catch (e) {} send({tag: 'DONE'}); }, TIMEOUT_MS);
rpc.exports = { stop: function () { try { if (armed) { th.unsetHardwareBreakpoint(0); armed = false; } } catch (e) {} return {armed: armed}; } };
"""


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--pid', type=int, required=True)
    ap.add_argument('--out', required=True)
    ap.add_argument('--port', type=int, default=27053)
    ap.add_argument('--count', type=int, default=90)
    ap.add_argument('--timeout-ms', type=int, default=40000)
    a = ap.parse_args(argv)
    assert Path('/proc', str(a.pid), 'comm').read_text().strip().lower() == 'uaro.exe'
    source = JS.replace('COUNT', str(a.count)).replace('TIMEOUT_MS', str(a.timeout_ms))
    result = {'events': []}

    def flush():
        try: Path(a.out).write_text(json.dumps(result, indent=2) + '\n')
        except OSError: pass

    done = {'v': False}

    def on_message(msg, data):
        if msg['type'] == 'send':
            v = msg['payload']; result['events'].append(v); flush()
            tag = v.get('tag')
            if tag == 'READY':
                print('READY main_tid=%s gepard=%s' % (v.get('main_tid'), v.get('gepard_base')), flush=True)
            elif tag == 'CAP':
                print('CAPTURED post_dispatch ret=%s' % v['data'].get('natural_return_region'), flush=True)
                done['v'] = True
            elif tag == 'DONE':
                done['v'] = True
            elif tag in ('HERR',):
                print('HANDLER_ERR', v.get('message'), flush=True)
        elif msg['type'] == 'error':
            result['events'].append({'tag': 'ERROR', 'message': msg.get('description')}); flush()
            print('ERROR', msg.get('description'), flush=True)

    dev = frida.get_device_manager().add_remote_device('127.0.0.1:' + str(a.port))
    session = dev.attach('Gadget'); script = None
    try:
        import time
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
    cap = next((e for e in result['events'] if e.get('tag') == 'CAP'), None)
    print(json.dumps({'captured': bool(cap), 'out': os.path.abspath(a.out)}, indent=2), flush=True)


if __name__ == '__main__':
    main()
