#!/usr/bin/env python3
"""Etapa 6.4: UMA tentativa nativa delimitada do receptor 0x8A, com os observadores
independentes já validados (dispatcher, receptor, store SEM gate de pilha, transporte
sendmsg, recv 0x0087). NÃO faz retry, NÃO copia objetos, NÃO altera outro estado.

Diferença testada vs. o ensaio anterior: o transporte (`sendmsg`) é observado como ponto
INDEPENDENTE e o store é observado SEM o gate de janela de pilha. Assim, se a chamada
emitir bytes sem o store ser reconhecido, isso aparece — resolvendo se o negativo anterior
era observabilidade (H1). O ponto de chamada (dreno main-thread poll/select) é mantido
CONSTANTE de propósito; NÃO se afirma equivalência com o contexto natural da VM.

Pré-condições (validadas em runtime, aborta se falharem): arch ia32, thread principal,
Gepard mapeado, store `mov [ecx],bl`, receptor == gepard+0x10a90 resolvido pelo manager.
Antes de disparar, revalida objeto/receptor. Uma tentativa, propagate, observa até 10s,
limpeza idempotente. Destino em COORDENADAS DE MAPA (as mesmas do receptor natural),
escolhido com o responsável, diferente da posição atual.

Uso:  native_trial.py --pid PID --out ARQ --emit-x MX --emit-y MY [--port 27053]
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
var store = gb.add(0x18eff2);
if (Instruction.parse(store).toString() !== 'mov byte ptr [ecx], bl') throw new Error('Store anchor mismatch');
var m = ptr('0x1213338');
if (m.add(0x58).readU32() !== 1) throw new Error('Receiver not ready');
var receiverObject = m.add(4).readPointer();
var receiver = receiverObject.readPointer().add(0x18).readPointer();
if (!receiver.equals(gb.add(0x10a90))) throw new Error('Receiver changed');
var dispatcher = ptr(DISPATCHER_PTR);

var LO = ptr('0x401000'), HI = ptr('0x1717000');
function region(p) {
  if (p === null) return 'null';
  if (p.compare(LO) >= 0 && p.compare(HI) < 0) return 'uaRO';
  if (p.compare(gb) >= 0 && p.compare(gb.add(0x2000000)) < 0) return 'gepard';
  var mod = Process.findModuleByAddress(p); return mod ? mod.name : 'other';
}
function sendmsgRequested(msg) {
  try { var iov = msg.add(8).readPointer(), n = msg.add(12).readU32(), tot = 0;
        for (var i = 0; i < Math.min(n, 32); i++) tot += iov.add(i * 8 + 4).readU32(); return tot;
  } catch (e) { return null; }
}

var t0 = Date.now(), ord = 0, events = [], saturated = false, done = false, CAP = EVENT_CAP;
function emit(ev) { if (events.length >= CAP) { saturated = true; return; } ev.order = ++ord; ev.ms = Date.now() - t0; events.push(ev); }

var peerFn = new NativeFunction(Module.getGlobalExportByName('getpeername'), 'int', ['int', 'pointer', 'pointer']);
var localFn = new NativeFunction(Module.getGlobalExportByName('getsockname'), 'int', ['int', 'pointer', 'pointer']);
var serverFd = {};
function isServerFd(fd) {
  if (fd in serverFd) return serverFd[fd];
  var sa = Memory.alloc(32), len = Memory.alloc(4); len.writeU32(32); var ok = false;
  if (peerFn(fd, sa, len) === 0 && sa.readU16() === 2) ok = (((sa.add(2).readU8() << 8) | sa.add(3).readU8()) === SERVER_PORT);
  serverFd[fd] = ok; return ok;
}
var transportApisSeen = {}, hookedT = {};
var candidates = ['send', 'sendto', 'sendmsg', 'sendmmsg', 'write', 'writev', '__send', '__libc_send'];
var lenArgIndex = {send: 2, sendto: 2, write: 2};
candidates.forEach(function (name) {
  var fn = Module.findGlobalExportByName(name); if (!fn || hookedT[fn.toString()]) return; hookedT[fn.toString()] = true;
  Interceptor.attach(fn, {
    onEnter: function (args) {
      if (done) return; this.fd = args[0].toInt32(); this.ok = this.fd >= 0 && isServerFd(this.fd); if (!this.ok) return;
      this.api = name;
      if (name in lenArgIndex) this.req = args[lenArgIndex[name]].toInt32();
      else if (name === 'sendmsg') this.req = sendmsgRequested(args[1]); else this.req = null;
      this.ret_region = region(this.returnAddress);
    },
    onLeave: function (retval) {
      if (done || !this.ok) return; transportApisSeen[this.api] = (transportApisSeen[this.api] || 0) + 1;
      emit({site: 'transport', api: this.api, fd: this.fd, bytes_requested: this.req,
            bytes_returned: retval.toInt32(), ret_region: this.ret_region});
    }
  });
});

var lengths = PACKET_LENGTHS, flows = {}, framingErrors = 0;
function flowKey(fd) {
  var sa = Memory.alloc(32), len = Memory.alloc(4); len.writeU32(32);
  if (peerFn(fd, sa, len) !== 0 || sa.readU16() !== 2) return null;
  if (((sa.add(2).readU8() << 8) | sa.add(3).readU8()) !== SERVER_PORT) return null;
  len.writeU32(32); if (localFn(fd, sa, len) !== 0) return null;
  return fd + ':' + (((sa.add(2).readU8() << 8) | sa.add(3).readU8()));
}
function receive(key, bytes) {
  var f = flows[key] || (flows[key] = {buf: new Uint8Array(0), valid: true}); if (!f.valid) return;
  if (f.buf.length + bytes.length > 65536) { f.valid = false; framingErrors++; return; }
  var b = new Uint8Array(f.buf.length + bytes.length); b.set(f.buf); b.set(bytes, f.buf.length); var pos = 0;
  while (pos + 2 <= b.length) {
    var id = b[pos] | (b[pos + 1] << 8), n = lengths[id];
    if (n === -1) { if (pos + 4 > b.length) break; n = b[pos + 2] | (b[pos + 3] << 8); if (n < 4) { f.valid = false; framingErrors++; return; } }
    if (n === undefined || n < 2 || n > 65536) { f.valid = false; framingErrors++; return; }
    if (pos + n > b.length) break;
    if (id === 0x87 && n === 12) { var v = b.subarray(pos + 6, pos + 12);
      emit({site: 'recv_0087', src: [(v[0] << 2) | (v[1] >> 6), ((v[1] & 63) << 4) | (v[2] >> 4)],
            dst: [((v[2] & 15) << 6) | (v[3] >> 2), ((v[3] & 3) << 8) | v[4]]}); }
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
        if (take > 0) receive(this.key, new Uint8Array(buf.readByteArray(take))); total -= take; if (done) return;
      }
    }
  });
});

var armed = [], active = false;
function stop() {
  var errors = [], remaining = [];
  armed.forEach(function (i) { try { th.unsetHardwareBreakpoint(i); } catch (e) { errors.push(String(e)); remaining.push(i); } });
  armed = remaining; active = armed.length > 0; return {ok: !active, errors: errors};
}
var cleanup = {ok: true, errors: []}, emitState = {attempted: false, returned: false, thread_ok: false};
function finish(extra) {
  if (done) return; done = true; cleanup = stop();
  send(Object.assign({tag: 'DONE', cleared: cleanup.ok, elapsed_ms: Date.now() - t0, events: events,
                      saturated: saturated, framing_errors: framingErrors, emit_state: emitState,
                      transport_apis_seen: transportApisSeen}, extra));
}
rpc.exports = {stop: function () { return stop(); }};

var points = [dispatcher, receiver, store];
Process.setExceptionHandler(function (d) {
  if (!active || d.type !== 'breakpoint') return false;
  var c = d.context, n = -1; for (var i = 0; i < points.length; i++) if (c.pc.equals(points[i])) { n = i; break; }
  if (n < 0) return false;
  try {
    if (n === 0) {
      var lo = c.esp.add(8).readU32(), hi = c.esp.add(12).readU32(); var code = (hi === 0 && lo <= 0x95) ? lo : null;
      if (code === 0x11) { var x = c.esp.add(16).readU32(), y = c.esp.add(24).readU32();
        emit({site: 'dispatcher_0x11', coord: (x <= 1023 && y <= 1023) ? [x, y] : null,
              return_addr: c.esp.readPointer().toString(), this_ecx: c.ecx.toString()}); }
    } else if (n === 1) {
      if (c.esp.add(4).readU32() === 0x8a) { var rx = c.esp.add(8).readU32(), ry = c.esp.add(12).readU32();
        emit({site: 'receptor_0x8a', coord: (rx <= 1023 && ry <= 1023) ? [rx, ry] : null,
              this_is_manager: c.ecx.equals(receiverObject), this_ecx: c.ecx.toString(),
              return_addr: c.esp.readPointer().toString()}); }
    } else if (n === 2) {
      var q = c.ecx, id = null, body = null, inStack = (q.compare(c.esp) >= 0 && q.compare(c.esp.add(0x10000)) < 0);
      try { id = q.sub(2).readU16(); } catch (e) {}
      if (id === 0x035f) { var b0 = q.readU8(), b1 = q.add(1).readU8(), b2 = q.add(2).readU8();
        body = {coord: [(b0 << 2) | (b1 >> 6), ((b1 & 63) << 4) | (b2 >> 4)], dir: b2 & 15}; }
      emit({site: 'store_035f', id_at_ecx_minus2: id, in_current_stack: inStack, ecx_region: region(q), body: body});
    }
  } catch (e) { emit({site: 'handler_error', message: e.message}); }
  return true;
});
active = true;
try { for (var i = 0; i < points.length; i++) { th.setHardwareBreakpoint(i, points[i]); armed.push(i); } }
catch (e) { stop(); throw e; }
send({tag: 'READY', read_only: false, trial: 'native-0x8a-leaf', dest: [EMIT_X, EMIT_Y]});

// Uma tentativa, propagate, disparada no dreno main-thread; ponto mantido constante.
var emitFn = new NativeFunction(receiver, 'void', ['pointer', 'uint', 'uint', 'uint', 'uint', 'uint'],
                                {abi: 'thiscall', exceptions: 'propagate'});
var emitPending = false, ticks = {};
['poll', 'ppoll', 'select', 'pselect', 'pselect6'].forEach(function (name) {
  var fn = Module.findGlobalExportByName(name); if (!fn || ticks[fn.toString()]) return; ticks[fn.toString()] = true;
  Interceptor.attach(fn, {onEnter: function () {
    if (!emitPending || done || Process.getCurrentThreadId() !== th.id) return;
    emitPending = false; emitState.thread_ok = true;
    // Revalida objeto/receptor imediatamente antes da chamada.
    if (m.add(0x58).readU32() !== 1 || !m.add(4).readPointer().equals(receiverObject) ||
        !receiverObject.readPointer().add(0x18).readPointer().equals(receiver)) {
      emit({site: 'emit_abort', reason: 'receiver changed before call'}); return;
    }
    try { emitState.attempted = true; emit({site: 'emit_call', dest: [EMIT_X, EMIT_Y]});
      emitFn(receiverObject, 0x8a, EMIT_X, EMIT_Y, 0, 0); emitState.returned = true;
      emit({site: 'emit_return'});
    } catch (e) { emit({site: 'emit_error', message: e.message}); }
  }});
});
if (Object.keys(ticks).length === 0) throw new Error('No main-thread drain hook');
setTimeout(function () { emitPending = true; }, DELAY_MS);        // dispara uma vez, após armar
setTimeout(function () { finish({reason: 'timeout'}); }, TIMEOUT_MS);
"""


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--pid', type=int, required=True)
    ap.add_argument('--out', required=True)
    ap.add_argument('--emit-x', type=int, required=True)
    ap.add_argument('--emit-y', type=int, required=True)
    ap.add_argument('--port', type=int, default=27053)
    ap.add_argument('--timeout-ms', type=int, default=10000)
    ap.add_argument('--delay-ms', type=int, default=150)
    ap.add_argument('--server-port', type=int, default=5121)
    ap.add_argument('--event-cap', type=int, default=4000)
    ap.add_argument('--dispatcher', default='0xd473b0')
    ap.add_argument('--table', default=TABLE)
    a = ap.parse_args(argv)
    assert 1000 <= a.timeout_ms <= 10000
    assert 100 <= a.delay_ms <= 2000
    assert 0 <= a.emit_x <= 1023 and 0 <= a.emit_y <= 1023, 'destino em coord de mapa 0..1023'
    assert Path('/proc', str(a.pid), 'comm').read_text().strip().lower() == 'uaro.exe'
    source = (JS.replace('TIMEOUT_MS', str(a.timeout_ms)).replace('DELAY_MS', str(a.delay_ms))
              .replace('EVENT_CAP', str(a.event_cap)).replace('SERVER_PORT', str(a.server_port))
              .replace('DISPATCHER_PTR', json.dumps(a.dispatcher))
              .replace('PACKET_LENGTHS', json.dumps(load_lengths(a.table)))
              .replace('EMIT_X', str(a.emit_x)).replace('EMIT_Y', str(a.emit_y)))

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
            state = script.exports_sync.stop()
            while not state['ok']:
                print('CLEANUP_RETRY', flush=True); time.sleep(1); state = script.exports_sync.stop()
            result['cleanup_calls_succeeded'] = True
            script.unload()
        session.detach()
    Path(a.out).write_text(json.dumps(result, indent=2) + '\n')
    end = next((x for x in result['events'] if x.get('tag') == 'DONE'), {})
    print(json.dumps({'cleared': end.get('cleared'), 'emit_state': end.get('emit_state'),
                      'events': len(end.get('events', [])), 'transport_apis_seen': end.get('transport_apis_seen')}),
          flush=True)
    assert end.get('cleared'), 'Limpeza da sonda nao confirmada'


if __name__ == '__main__':
    main()
