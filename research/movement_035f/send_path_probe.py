#!/usr/bin/env python3
"""Rodada MOVER-...-05, ETAPA 2 (SOMENTE LEITURA): identificar o ponto de ENFILEIRAMENTO/FLUSH
do caminho de envio natural do pacote 0x035F, para uma futura injeção pela via natural (em vez de
chamar o dispatcher direto, que montou 0x35F mas não transmitiu e travou o cliente — rodada 04).

Método: hooks APENAS em exports de envio da libc/wineserver (send/sendto/sendmsg/writev/write).
Quando um envio ao fd do servidor (porta 5121) carrega um payload cujo id == 0x035F, captura o
BACKTRACE (Thread.backtrace) e mapeia cada quadro para região+offset (uaRO base 0x400000 / gepard
base dinâmica). Sem chamada nativa, sem HW BP, sem hook em código do uaRO/gepard. 100% observação.

Uso: send_path_probe.py --pid PID --out ARQ [--port 27053] [--server-port 5121]
     [--max-captures 4] [--timeout-ms 40000]
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
function mapFrame(p) {
  if (p === null) return null;
  if (p.compare(LO) >= 0 && p.compare(HI) < 0) return 'uaRO+' + p.sub(UA_IMAGEBASE).toString();
  if (p.compare(gb) >= 0 && p.compare(GHI) < 0) return 'gepard+' + p.sub(gb).toString();
  var m = Process.findModuleByAddress(p);
  if (m) return m.name + '+' + p.sub(m.base).toString();
  return p.toString();
}

var peerFn = new NativeFunction(Module.getGlobalExportByName('getpeername'), 'int', ['int', 'pointer', 'pointer']);
var serverFd = {};
function isServerFd(fd) {
  if (fd in serverFd) return serverFd[fd];
  var sa = Memory.alloc(32), len = Memory.alloc(4); len.writeU32(32); var ok = false;
  if (peerFn(fd, sa, len) === 0 && sa.readU16() === 2) ok = (((sa.add(2).readU8() << 8) | sa.add(3).readU8()) === SERVER_PORT);
  serverFd[fd] = ok; return ok;
}

var t0 = Date.now(), captures = 0, events = [];
function emit(ev) { ev.ms = Date.now() - t0; events.push(ev); try { send({tag: 'EV', ev: ev}); } catch (e) {} }

// extrai os primeiros bytes do 1º iovec/buffer de cada api
function firstBytes(api, args, n) {
  try {
    if (api === 'sendmsg') { var iov = args[1].add(8).readPointer(); return iov.readPointer().readByteArray(n); }
    if (api === 'writev')  { var v = args[1]; return v.readPointer().readByteArray(n); }
    // send/sendto/write: buffer em args[1]
    return args[1].readByteArray(n);
  } catch (e) { return null; }
}
function payloadLen(api, args) {
  try {
    if (api === 'sendmsg') { var iov = args[1].add(8).readPointer(), c = args[1].add(12).readU32(), t = 0;
      for (var i = 0; i < Math.min(c, 32); i++) t += iov.add(i * 8 + 4).readU32(); return t; }
    if (api === 'writev')  { var v = args[1], c = args[2].toInt32(), t = 0;
      for (var j = 0; j < Math.min(c, 32); j++) t += v.add(j * 8 + 4).readU32(); return t; }
    if (api === 'send' || api === 'sendto' || api === 'write') return args[2].toInt32();
  } catch (e) {}
  return null;
}

var apis = ['sendmsg', 'sendto', 'send', 'writev', 'write', '__send', '__libc_send'];
var hooked = {};
apis.forEach(function (name) {
  var fn = Module.findGlobalExportByName(name); if (!fn || hooked[fn.toString()]) return; hooked[fn.toString()] = true;
  Interceptor.attach(fn, {
    onEnter: function (args) {
      if (captures >= MAX_CAP) return;
      var fd = args[0].toInt32(); if (fd < 0 || !isServerFd(fd)) return;
      var head = firstBytes(name, args, 8); if (!head) return;
      var b = new Uint8Array(head); if (b.length < 2) return;
      var id = b[0] | (b[1] << 8);
      if (id !== 0x035f) return;                         // só o pacote de movimento
      captures++;
      var tid = Process.getCurrentThreadId();
      var bt_acc = null, bt_fuzzy = null;
      try { bt_acc = Thread.backtrace(this.context, Backtracer.ACCURATE).map(mapFrame); } catch (e) {}
      try { bt_fuzzy = Thread.backtrace(this.context, Backtracer.FUZZY).map(mapFrame); } catch (e) {}
      emit({site: 'send_035f', api: name, fd: fd, on_main: (tid === mainTid), tid: tid,
            len: payloadLen(name, args),
            head: Array.prototype.slice.call(b),
            return_addr: mapFrame(this.returnAddress),
            bt_accurate: bt_acc, bt_fuzzy: bt_fuzzy});
      if (captures >= MAX_CAP) { try { send({tag: 'ENOUGH'}); } catch (e) {} }
    }
  });
});
if (Object.keys(hooked).length === 0) throw new Error('No send export hooked');
send({tag: 'READY', read_only: true, main_tid: mainTid, gepard_base: gb.toString(), hooked: Object.keys(hooked).length});
setTimeout(function () { try { send({tag: 'DONE', events: events, captures: captures}); } catch (e) {} }, TIMEOUT_MS);
rpc.exports = { dump: function () { return {events: events, captures: captures}; } };
"""


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--pid', type=int, required=True)
    ap.add_argument('--out', required=True)
    ap.add_argument('--port', type=int, default=27053)
    ap.add_argument('--server-port', type=int, default=5121)
    ap.add_argument('--max-captures', type=int, default=4)
    ap.add_argument('--timeout-ms', type=int, default=40000)
    a = ap.parse_args(argv)
    assert Path('/proc', str(a.pid), 'comm').read_text().strip().lower() == 'uaro.exe'
    source = (JS.replace('SERVER_PORT', str(a.server_port))
              .replace('MAX_CAP', str(a.max_captures))
              .replace('TIMEOUT_MS', str(a.timeout_ms)))
    result = {'events': []}

    def flush():
        try:
            Path(a.out).write_text(json.dumps(result, indent=2) + '\n')
        except OSError:
            pass

    done = {'v': False}

    def on_message(msg, data):
        if msg['type'] == 'send':
            v = msg['payload']; result['events'].append(v); flush()
            tag = v.get('tag')
            if tag == 'READY':
                print('READY main_tid=%s gepard=%s hooked=%s'
                      % (v.get('main_tid'), v.get('gepard_base'), v.get('hooked')), flush=True)
            elif tag == 'EV':
                print('CAPTURED send_035f (%s)' % (v.get('ev') or {}).get('api'), flush=True)
            elif tag in ('DONE', 'ENOUGH'):
                done['v'] = True
        elif msg['type'] == 'error':
            result['events'].append({'tag': 'ERROR', 'message': msg.get('description')}); flush()
            print('ERROR', msg.get('description'), flush=True)

    dev = frida.get_device_manager().add_remote_device('127.0.0.1:' + str(a.port))
    session = dev.attach('Gadget'); script = None
    try:
        script = session.create_script(source); script.on('message', on_message); script.load()
        import time
        deadline = time.time() + a.timeout_ms / 1000.0 + 3
        while time.time() < deadline and not done['v']:
            time.sleep(0.2)
        try:
            d = script.exports_sync.dump(); result['final'] = d; flush()
        except Exception:
            pass
    finally:
        if script is not None:
            try: script.unload()
            except Exception: pass
        try: session.detach()
        except Exception: pass
    flush()
    caps = [e for e in result['events'] if e.get('tag') == 'EV']
    print(json.dumps({'captures': len(caps),
                      'out': os.path.abspath(a.out)}, indent=2), flush=True)


if __name__ == '__main__':
    main()
