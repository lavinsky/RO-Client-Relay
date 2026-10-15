#!/usr/bin/env python3
"""Observação read-only do caminho natural do 0x035F + descoberta do transporte.

NÃO chama função nativa, NÃO escreve memória, NÃO lê corpos de pacote/cifra.
Objetivo: confirmar que os observadores funcionam num MOVIMENTO NATURAL e coletar,
em eventos ordenados, quatro pontos distintos e independentes:
  - dispatcher  (0xd473b0, código interno 0x11, slots de 64 bits) — entrada observada;
  - receptor    (gepard+0x10a90, código 0x8a) — entrada observada;
  - store       (gepard+0x18eff2, `mov [ecx],bl`) — SEM gate de janela de pilha, para
                 distinguir 'store executou' de 'store ausente' (só id [ecx-2] e 3 bytes);
  - transporte  (DESCOBERTO): hooka um conjunto de candidatos de envio e filtra pela
                 conexão do servidor (porta remota). Registra api/fd/bytes/ordem/região
                 do retorno — NÃO lê o buffer (sem material de cifra), NÃO condiciona ao
                 store. Uma chamada de envio não equivale a pacote nem à fronteira da cifra.
Também observa 0x0087 recebido (framing por tabela), como evento próprio.

Contexto/pilha mínimos: só o endereço de retorno imediato classificado por região.
Em código virtualizado, isso NÃO prova a cadeia causal — a análise trata como correlação.

Requer JANELA EXCLUSIVA (usa registradores de depuração; colide com a sonda de cifra).
Limites: timeout e teto de eventos; limpeza idempotente dos breakpoints próprios.

Uso:  observe_path.py --pid PID --out ARQ [--port 27053] [--timeout-ms 10000]
                      [--server-port 5121] [--event-cap 4000] [--dispatcher 0xd473b0]
"""
import argparse
import json
from pathlib import Path
import signal
import threading
import time

import frida

TABLE = "/var/home/bazzite/Documentos/Projetos/improvement/data/uaro_recvpackets.txt"


def load_lengths(path):
    lengths = {}
    for line in Path(path).read_text().splitlines():
        f = line.split()
        if len(f) >= 2:
            try:
                lengths[int(f[0], 16)] = int(f[1])
            except ValueError:
                pass
    return lengths


def build_source(opts, lengths):
    return (JS
            .replace("TIMEOUT_MS", str(opts.timeout_ms))
            .replace("EVENT_CAP", str(opts.event_cap))
            .replace("SERVER_PORT", str(opts.server_port))
            .replace("DISPATCHER_PTR", json.dumps(opts.dispatcher))
            .replace("PACKET_LENGTHS", json.dumps(lengths)))


# O corpo JS é read-only: só breakpoints de execução, hooks de leitura e getpeername/getsockname.
JS = r"""
'use strict';
if (Process.arch !== 'ia32') throw new Error('Expected ia32');
var th = Process.enumerateThreads().filter(t => t.id === Process.id)[0];
if (!th) throw new Error('Main thread absent');
var gb = null;
Process.enumerateRanges({protection: '---', coalesce: false}).forEach(function (r) {
  if (r.file && /\/gepard\.dll$/i.test(r.file.path) && (gb === null || r.base.compare(gb) < 0)) gb = r.base;
});
if (!gb) throw new Error('Gepard mapping absent');

// Revalidação do build: âncora de store documentada.
var store = gb.add(0x18eff2);
if (Instruction.parse(store).toString() !== 'mov byte ptr [ecx], bl') throw new Error('Store anchor mismatch');
// Receptor resolvido pelo manager (vtable slot 0x18), confirmado == gepard+0x10a90.
var m = ptr('0x1213338');
if (m.add(0x58).readU32() !== 1) throw new Error('Receiver not ready');
var receiverObject = m.add(4).readPointer();
var receiver = receiverObject.readPointer().add(0x18).readPointer();
if (!receiver.equals(gb.add(0x10a90))) throw new Error('Receiver changed');
var dispatcher = ptr(DISPATCHER_PTR);
var dr = Process.findRangeByAddress(dispatcher);
if (!dr || dr.protection.indexOf('x') < 0) throw new Error('Dispatcher not executable (base shifted?)');

var LO = ptr('0x401000'), HI = ptr('0x1717000');
function region(p) {
  if (p === null) return 'null';
  if (p.compare(LO) >= 0 && p.compare(HI) < 0) return 'uaRO';
  if (p.compare(gb) >= 0 && p.compare(gb.add(0x2000000)) < 0) return 'gepard';
  var mod = Process.findModuleByAddress(p);
  return mod ? mod.name : 'other';
}
function tryU32(p) { try { return p.readU32(); } catch (e) { return null; } }
function sendmsgRequested(msg) {   // soma iov_len do msghdr (32-bit), SEM ler o buffer
  try {
    var iov = msg.add(8).readPointer(), n = msg.add(12).readU32(), tot = 0;
    for (var i = 0; i < Math.min(n, 32); i++) tot += iov.add(i * 8 + 4).readU32();
    return tot;
  } catch (e) { return null; }
}

var t0 = Date.now(), ord = 0, events = [], saturated = false, done = false;
var CAP = EVENT_CAP;
function emit(ev) {
  if (events.length >= CAP) { saturated = true; return; }
  ev.order = ++ord; ev.ms = Date.now() - t0; events.push(ev);
}

// ---- transporte: descoberta por candidatos, filtrado pela conexão do servidor ----
var peerFn = new NativeFunction(Module.getGlobalExportByName('getpeername'), 'int', ['int', 'pointer', 'pointer']);
var serverFd = {};                       // fd -> bool (porta remota == SERVER_PORT)
function isServerFd(fd) {
  if (fd in serverFd) return serverFd[fd];
  var sa = Memory.alloc(32), len = Memory.alloc(4); len.writeU32(32);
  var ok = false;
  if (peerFn(fd, sa, len) === 0 && sa.readU16() === 2) {
    var remote = (sa.add(2).readU8() << 8) | sa.add(3).readU8();
    ok = (remote === SERVER_PORT);
  }
  serverFd[fd] = ok; return ok;
}
var transportApisSeen = {};
var candidates = ['send', 'sendto', 'sendmsg', 'sendmmsg', 'write', 'writev', '__send', '__libc_send'];
var lenArgIndex = {send: 2, sendto: 2, write: 2};   // tamanho solicitado facilmente legível
var hookedT = {};
candidates.forEach(function (name) {
  var fn = Module.findGlobalExportByName(name);
  if (!fn || hookedT[fn.toString()]) return; hookedT[fn.toString()] = true;
  Interceptor.attach(fn, {
    onEnter: function (args) {
      if (done) return;
      this.fd = args[0].toInt32();
      this.ok = this.fd >= 0 && isServerFd(this.fd);
      if (!this.ok) return;
      this.api = name;
      if (name in lenArgIndex) this.req = args[lenArgIndex[name]].toInt32();
      else if (name === 'sendmsg') this.req = sendmsgRequested(args[1]);
      else this.req = null;
      this.ret_region = region(this.returnAddress);  // endereço de retorno imediato (mínimo)
    },
    onLeave: function (retval) {
      if (done || !this.ok) return;
      transportApisSeen[this.api] = (transportApisSeen[this.api] || 0) + 1;
      emit({site: 'transport', api: this.api, fd: this.fd,
            bytes_requested: this.req, bytes_returned: retval.toInt32(),
            ret_region: this.ret_region});   // NÃO lê o buffer
    }
  });
});

// ---- recepção do 0x0087 (framing por tabela), evento próprio, não condiciona store ----
var localFn = new NativeFunction(Module.getGlobalExportByName('getsockname'), 'int', ['int', 'pointer', 'pointer']);
var lengths = PACKET_LENGTHS, flows = {}, framingErrors = 0;
function flowKey(fd) {
  var sa = Memory.alloc(32), len = Memory.alloc(4); len.writeU32(32);
  if (peerFn(fd, sa, len) !== 0 || sa.readU16() !== 2) return null;
  if (((sa.add(2).readU8() << 8) | sa.add(3).readU8()) !== SERVER_PORT) return null;
  len.writeU32(32); if (localFn(fd, sa, len) !== 0) return null;
  return fd + ':' + (((sa.add(2).readU8() << 8) | sa.add(3).readU8()));
}
function receive(key, bytes) {
  var f = flows[key] || (flows[key] = {buf: new Uint8Array(0), valid: true});
  if (!f.valid) return;
  if (f.buf.length + bytes.length > 65536) { f.valid = false; framingErrors++; return; }
  var b = new Uint8Array(f.buf.length + bytes.length); b.set(f.buf); b.set(bytes, f.buf.length);
  var pos = 0;
  while (pos + 2 <= b.length) {
    var id = b[pos] | (b[pos + 1] << 8), n = lengths[id];
    if (n === -1) { if (pos + 4 > b.length) break; n = b[pos + 2] | (b[pos + 3] << 8); if (n < 4) { f.valid = false; framingErrors++; return; } }
    if (n === undefined || n < 2 || n > 65536) { f.valid = false; framingErrors++; return; }
    if (pos + n > b.length) break;
    if (id === 0x87 && n === 12) {
      var v = b.subarray(pos + 6, pos + 12);
      emit({site: 'recv_0087',
            src: [(v[0] << 2) | (v[1] >> 6), ((v[1] & 63) << 4) | (v[2] >> 4)],
            dst: [((v[2] & 15) << 6) | (v[3] >> 2), ((v[3] & 3) << 8) | v[4]]});
    }
    pos += n;
  }
  f.buf = b.slice(pos);
}
var hookedR = {};
['__recvmsg64', 'recvmsg'].forEach(function (name) {
  var fn = Module.findGlobalExportByName(name); if (!fn || hookedR[fn.toString()]) return; hookedR[fn.toString()] = true;
  Interceptor.attach(fn, {
    onEnter: function (args) { this.key = flowKey(args[0].toInt32()); this.msg = args[1]; },
    onLeave: function (ret) {
      var total = ret.toInt32(); if (done || !this.key || total <= 0 || total > 65536) return;
      var iov = this.msg.add(8).readPointer(), n = this.msg.add(12).readU32();
      if (n > 32) { flows[this.key] = {buf: new Uint8Array(0), valid: false}; framingErrors++; return; }
      for (var i = 0; i < Math.min(n, 32) && total > 0; i++) {
        var at = iov.add(i * 8), buf = at.readPointer(), take = Math.min(total, at.add(4).readU32());
        if (take > 0) receive(this.key, new Uint8Array(buf.readByteArray(take))); total -= take;
        if (done) return;
      }
    }
  });
});

// ---- âncoras de execução (3 breakpoints de hardware, read-only) ----
var armed = [], active = false;
function stop() {
  var errors = [], remaining = [];
  armed.forEach(function (i) { try { th.unsetHardwareBreakpoint(i); } catch (e) { errors.push(String(e)); remaining.push(i); } });
  armed = remaining; active = armed.length > 0; return {ok: !active, errors: errors};
}
var cleanup = {ok: true, errors: []};
function finish(extra) {
  if (done) return; done = true; cleanup = stop();
  send(Object.assign({tag: 'DONE', cleared: cleanup.ok, elapsed_ms: Date.now() - t0,
                      events: events, saturated: saturated, framing_errors: framingErrors,
                      transport_apis_seen: transportApisSeen}, extra));
}
rpc.exports = {stop: function () { return stop(); }};

var points = [dispatcher, receiver, store];   // DR0, DR1, DR2
Process.setExceptionHandler(function (d) {
  if (!active || d.type !== 'breakpoint') return false;
  var c = d.context, n = -1;
  for (var i = 0; i < points.length; i++) if (c.pc.equals(points[i])) { n = i; break; }
  if (n < 0) return false;
  try {
    if (n === 0) {                                   // dispatcher: só o código 0x11 interessa
      var lo = c.esp.add(8).readU32(), hi = c.esp.add(12).readU32();
      var code = (hi === 0 && lo <= 0x95) ? lo : null;
      if (code === 0x11) {
        var x = c.esp.add(16).readU32(), xh = c.esp.add(20).readU32(),
            y = c.esp.add(24).readU32(), yh = c.esp.add(28).readU32();
        var ret = c.esp.readPointer();
        emit({site: 'dispatcher_0x11', coord: (x <= 1023 && y <= 1023 && xh === 0 && yh === 0) ? [x, y] : null,
              return_addr: ret.toString(), return_region: region(ret),
              this_ecx: c.ecx.toString(), this_region: region(c.ecx),
              gate70: tryU32(c.ecx.add(0x70)), counter520: tryU32(c.ecx.add(0x520))});
      }
    } else if (n === 1) {                            // receptor: só o código 0x8a
      if (c.esp.add(4).readU32() === 0x8a) {
        var rx = c.esp.add(8).readU32(), ry = c.esp.add(12).readU32();
        var rret = c.esp.readPointer();
        emit({site: 'receptor_0x8a', coord: (rx <= 1023 && ry <= 1023) ? [rx, ry] : null,
              this_is_manager: c.ecx.equals(receiverObject),
              this_ecx: c.ecx.toString(),
              tail_args_zero: c.esp.add(16).readU32() === 0 && c.esp.add(20).readU32() === 0,
              return_addr: rret.toString(), return_region: region(rret)});
      }
    } else if (n === 2) {                            // store: SEM gate de janela de pilha
      var q = c.ecx, inStack = (q.compare(c.esp) >= 0 && q.compare(c.esp.add(0x10000)) < 0);
      var id = null, body = null;
      try { id = q.sub(2).readU16(); } catch (e) {}
      if (id === 0x035f) {
        var b0 = q.readU8(), b1 = q.add(1).readU8(), b2 = q.add(2).readU8();
        body = {coord: [(b0 << 2) | (b1 >> 6), ((b1 & 63) << 4) | (b2 >> 4)], dir: b2 & 15};
      }
      emit({site: 'store_035f', id_at_ecx_minus2: id, in_current_stack: inStack,
            ecx_region: region(q), body: body});
    }
  } catch (e) { emit({site: 'handler_error', message: e.message}); }
  return true;
});

active = true;
try { for (var i = 0; i < points.length; i++) { th.setHardwareBreakpoint(i, points[i]); armed.push(i); } }
catch (e) { stop(); throw e; }
send({tag: 'READY', read_only: true, anchors: points.map(function (p) { return p.toString(); }),
      store: store.toString(), receiver: receiver.toString()});
setTimeout(function () { finish({reason: 'timeout'}); }, TIMEOUT_MS);
"""


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--pid', type=int, required=True)
    ap.add_argument('--out', required=True)
    ap.add_argument('--port', type=int, default=27053)
    ap.add_argument('--timeout-ms', type=int, default=10000)
    ap.add_argument('--server-port', type=int, default=5121)
    ap.add_argument('--event-cap', type=int, default=4000)
    ap.add_argument('--dispatcher', default='0xd473b0')
    ap.add_argument('--table', default=TABLE)
    a = ap.parse_args(argv)
    assert 1000 <= a.timeout_ms <= 10000, 'timeout-ms fora de [1000,10000]'
    assert 1 <= a.event_cap <= 20000
    assert Path('/proc', str(a.pid), 'comm').read_text().strip().lower() == 'uaro.exe', 'alvo nao e uaRO.exe'
    source = build_source(a, load_lengths(a.table))

    result = {'events': []}
    done = threading.Event()
    signal.signal(signal.SIGTERM, lambda *_: done.set())
    signal.signal(signal.SIGINT, lambda *_: done.set())

    def on_message(msg, data):
        if msg['type'] == 'send':
            v = msg['payload']; result['events'].append(v)
            if v.get('tag') == 'READY':
                print('READY', flush=True)
            if v.get('tag') == 'DONE':
                done.set()
        elif msg['type'] == 'error':
            result['events'].append({'tag': 'ERROR', 'message': msg.get('description')}); done.set()

    dev = frida.get_device_manager().add_remote_device('127.0.0.1:' + str(a.port))
    session = dev.attach('Gadget'); script = None
    try:
        script = session.create_script(source); script.on('message', on_message); script.load()
        if not done.wait(a.timeout_ms / 1000 + 5):
            result['events'].append({'tag': 'TIMEOUT'})
    finally:
        if script is not None:
            state = script.exports_sync.stop()        # limpeza idempotente, com retentativa
            while not state['ok']:
                print('CLEANUP_RETRY', flush=True); time.sleep(1); state = script.exports_sync.stop()
            result['cleanup_calls_succeeded'] = True
            script.unload()
        session.detach()
    Path(a.out).write_text(json.dumps(result, indent=2) + '\n')
    end = next((x for x in result['events'] if x.get('tag') == 'DONE'), {})
    print(json.dumps({'cleared': end.get('cleared'), 'events': len(end.get('events', [])),
                      'transport_apis_seen': end.get('transport_apis_seen'),
                      'saturated': end.get('saturated')}), flush=True)
    assert end.get('cleared'), 'Limpeza da sonda nao confirmada'


if __name__ == '__main__':
    main()
