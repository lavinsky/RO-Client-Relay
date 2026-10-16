#!/usr/bin/env python3
"""Rodada MOVER-...-05, ETAPA 2b (SOMENTE LEITURA): o send da libc fica no lado UNIX da fronteira
de syscall do Wine (backtrace só ntdll/wine/libc, sem quadros PE). Para achar o FLUSH do lado PE,
hooka os exports de socket do ws2_32.dll (PE) — `send`/`sendto`/`WSASend`/`WSASendTo` — e captura o
backtrace quando o payload ao fd do servidor começa com id 0x035F. Isso revela a função de uaRO/gepard
que entrega o pacote ao socket (candidata para injeção pela via natural na rodada 06).

Sem chamada nativa, sem HW BP, sem hook em código do uaRO/gepard. Apenas exports de ws2_32.dll.
Uso: send_path_pe.py --pid PID --out ARQ [--port 27053] [--max-captures 4] [--timeout-ms 40000]
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
var UA_IMAGEBASE = ptr('0x400000'), LO = ptr('0x401000'), HI = ptr('0x1717000');
var GHI = gb ? gb.add(0x2000000) : null;
function mapFrame(p) {
  if (p === null) return null;
  if (p.compare(LO) >= 0 && p.compare(HI) < 0) return 'uaRO+' + p.sub(UA_IMAGEBASE).toString();
  if (gb && p.compare(gb) >= 0 && p.compare(GHI) < 0) return 'gepard+' + p.sub(gb).toString();
  var m = Process.findModuleByAddress(p);
  if (m) return m.name + '+' + p.sub(m.base).toString();
  return p.toString();
}

// localizar o módulo PE ws2_32 e seus exports de envio
var wsmods = Process.enumerateModules().filter(function (m) { return /ws2_32|wsock32|mswsock/i.test(m.name); });
var modReport = wsmods.map(function (m) { return {name: m.name, base: m.base.toString(), size: m.size}; });
var sendNames = ['send', 'sendto', 'WSASend', 'WSASendTo'];
var hooks = [];
wsmods.forEach(function (m) {
  var exps = m.enumerateExports();
  sendNames.forEach(function (nm) {
    var e = exps.filter(function (x) { return x.name === nm; })[0];
    if (e) hooks.push({mod: m.name, name: nm, addr: e.address});
  });
});

var t0 = Date.now(), captures = 0, events = [];
function emit(ev) { ev.ms = Date.now() - t0; events.push(ev); try { send({tag: 'EV', ev: ev}); } catch (e) {} }

// ws2_32 send(fd, buf, len, flags); WSASend(s, lpBuffers(WSABUF*), dwBufferCount, ...)
function headOf(name, args, n) {
  try {
    if (name === 'send' || name === 'sendto') return args[1].readByteArray(n);
    if (name === 'WSASend' || name === 'WSASendTo') { var wsabuf = args[1]; // WSABUF{u_long len; char* buf}
      return wsabuf.add(4).readPointer().readByteArray(n); }
  } catch (e) {}
  return null;
}
function lenOf(name, args) {
  try {
    if (name === 'send' || name === 'sendto') return args[2].toInt32();
    if (name === 'WSASend' || name === 'WSASendTo') { var wsabuf = args[1], c = args[2].toInt32(), t = 0;
      for (var i = 0; i < Math.min(c, 32); i++) t += wsabuf.add(i * 8).readU32(); return t; }
  } catch (e) {}
  return null;
}

hooks.forEach(function (h) {
  Interceptor.attach(h.addr, {
    onEnter: function (args) {
      if (captures >= MAX_CAP) return;
      var head = headOf(h.name, args, 8); if (!head) return;
      var b = new Uint8Array(head); if (b.length < 2) return;
      var id = b[0] | (b[1] << 8);
      if (id !== 0x035f) return;
      captures++;
      var tid = Process.getCurrentThreadId();
      var bt_acc = null, bt_fuzzy = null;
      try { bt_acc = Thread.backtrace(this.context, Backtracer.ACCURATE).map(mapFrame); } catch (e) {}
      try { bt_fuzzy = Thread.backtrace(this.context, Backtracer.FUZZY).map(mapFrame); } catch (e) {}
      emit({site: 'pe_send_035f', mod: h.mod, api: h.name, sock: args[0].toInt32(),
            on_main: (tid === mainTid), tid: tid, len: lenOf(h.name, args),
            head: Array.prototype.slice.call(b),
            return_addr: mapFrame(this.returnAddress), bt_accurate: bt_acc, bt_fuzzy: bt_fuzzy});
      if (captures >= MAX_CAP) { try { send({tag: 'ENOUGH'}); } catch (e) {} }
    }
  });
});

send({tag: 'READY', read_only: true, main_tid: mainTid, gepard_base: gb ? gb.toString() : null,
      ws_modules: modReport, send_hooks: hooks.map(function (h) { return {mod: h.mod, name: h.name, addr: h.addr.toString()}; })});
setTimeout(function () { try { send({tag: 'DONE', events: events, captures: captures}); } catch (e) {} }, TIMEOUT_MS);
rpc.exports = { dump: function () { return {events: events, captures: captures}; } };
"""


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--pid', type=int, required=True)
    ap.add_argument('--out', required=True)
    ap.add_argument('--port', type=int, default=27053)
    ap.add_argument('--max-captures', type=int, default=4)
    ap.add_argument('--timeout-ms', type=int, default=40000)
    a = ap.parse_args(argv)
    assert Path('/proc', str(a.pid), 'comm').read_text().strip().lower() == 'uaro.exe'
    source = JS.replace('MAX_CAP', str(a.max_captures)).replace('TIMEOUT_MS', str(a.timeout_ms))
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
                print('READY main_tid=%s ws_modules=%s send_hooks=%s'
                      % (v.get('main_tid'), json.dumps(v.get('ws_modules')), json.dumps(v.get('send_hooks'))), flush=True)
            elif tag == 'EV':
                print('CAPTURED pe_send_035f api=%s mod=%s' % ((v.get('ev') or {}).get('api'), (v.get('ev') or {}).get('mod')), flush=True)
            elif tag in ('DONE', 'ENOUGH'):
                done['v'] = True
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
        try:
            result['final'] = script.exports_sync.dump(); flush()
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
    print(json.dumps({'captures': len(caps), 'out': os.path.abspath(a.out)}, indent=2), flush=True)


if __name__ == '__main__':
    main()
