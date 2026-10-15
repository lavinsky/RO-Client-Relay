#!/usr/bin/env python3
"""Ensaio nativo do DISPATCHER 0x11 (cadeia de preparação completa), autorizado.

Testa H2/H3 e o objetivo de §13 (ARCHITECTURE): disparar um 0x035F ESPONTÂNEO pelo
caminho de pilha correto. Em vez da folha 0x8A (insuficiente, 6.4), chama o dispatcher
`0xd473b0` com a ABI observada (thiscall; pilha `(u32 0, u64 0x11, u64 x, u64 y, u64 0,
u64 0)`), que executa `0x11→0x0D→0x5B→0x8A` e deve montar/armazenar/enviar o 035F.

O objeto `this` do dispatcher é de heap (sem âncora global): é CAPTURADO de UM passo
natural (BP de execução read-only) e reusado na MESMA sessão. A chamada nativa é feita
UMA vez, no dreno main-thread (poll/select), para um destino de mapa diferente, sem clique.
Observadores independentes (dispatcher, receptor, store SEM gate de pilha, transporte
sendmsg, recv 0087) ficam armados. Revalida build/objeto; limpeza idempotente.

Autorização: o responsável autorizou chamadas nativas e aceita relogin se o cliente cair.

Uso:  dispatcher_trial.py --pid PID --out ARQ --emit-x MX --emit-y MY [--port 27053]
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
if (!Process.findRangeByAddress(dispatcher)) throw new Error('Dispatcher unmapped');

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
function emit(ev) {
  if (events.length >= CAP) { saturated = true; return; }
  ev.order = ++ord; ev.ms = Date.now() - t0; events.push(ev);
  try { send({tag: 'EV', ev: ev}); } catch (e) {}   // stream imediato: sobrevive a um freeze
}

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
      this.ret_region = region(this.returnAddress); this.in_call = inCall;
    },
    onLeave: function (retval) {
      if (done || !this.ok) return; transportApisSeen[this.api] = (transportApisSeen[this.api] || 0) + 1;
      emit({site: 'transport', api: this.api, fd: this.fd, bytes_requested: this.req,
            bytes_returned: retval.toInt32(), ret_region: this.ret_region, during_call: this.in_call});
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
      emit({site: 'recv_0087', during_call: inCall,
            src: [(v[0] << 2) | (v[1] >> 6), ((v[1] & 63) << 4) | (v[2] >> 4)],
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
var cleanup = {ok: true, errors: []};
var emitState = {captured: false, attempted: false, returned: false, thread_ok: false};
var dispThis = null, inCall = false, capCoord = null, dispUnarmed = false;
var emitPending = false, emitScheduled = false, fired = false, ticks = {};
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
      if (code === 0x11) {
        var x = c.esp.add(16).readU32(), y = c.esp.add(24).readU32();
        if (dispThis === null && !inCall) { dispThis = c.ecx; capCoord = [x, y]; emitState.captured = true;
          emit({site: 'disp_captured', this_ecx: c.ecx.toString(), coord: [x, y]});
          // dispara a chamada nativa POUCO depois da captura, enquanto a main thread ainda está
          // ativa (polls frequentes); um timer de parede fixo pegava a thread ociosa e não disparava.
          if (!emitScheduled) { emitScheduled = true; setTimeout(function () { emitPending = true; }, DELAY_MS); } }
        emit({site: 'dispatcher_0x11', coord: (x <= 1023 && y <= 1023) ? [x, y] : null,
              return_addr: c.esp.readPointer().toString(), return_region: region(c.esp.readPointer()),
              this_ecx: c.ecx.toString(), during_call: inCall});
      }
    } else if (n === 1) {
      if (c.esp.add(4).readU32() === 0x8a) { var rx = c.esp.add(8).readU32(), ry = c.esp.add(12).readU32();
        emit({site: 'receptor_0x8a', coord: (rx <= 1023 && ry <= 1023) ? [rx, ry] : null,
              this_is_manager: c.ecx.equals(receiverObject), this_ecx: c.ecx.toString(),
              return_addr: c.esp.readPointer().toString(), return_region: region(c.esp.readPointer()),
              during_call: inCall}); }
    } else if (n === 2) {
      var q = c.ecx, id = null, body = null, inStack = (q.compare(c.esp) >= 0 && q.compare(c.esp.add(0x10000)) < 0);
      try { id = q.sub(2).readU16(); } catch (e) {}
      if (id === 0x035f) { var b0 = q.readU8(), b1 = q.add(1).readU8(), b2 = q.add(2).readU8();
        body = {coord: [(b0 << 2) | (b1 >> 6), ((b1 & 63) << 4) | (b2 >> 4)], dir: b2 & 15}; }
      if (id === 0x035f || inCall)
        emit({site: 'store_035f', id_at_ecx_minus2: id, in_current_stack: inStack, ecx_region: region(q), body: body, during_call: inCall});
    }
  } catch (e) { emit({site: 'handler_error', message: e.message}); }
  return true;
});
active = true;
try { for (var i = 0; i < points.length; i++) { th.setHardwareBreakpoint(i, points[i]); armed.push(i); } }
catch (e) { stop(); throw e; }
send({tag: 'READY', read_only: false, trial: 'native-dispatcher-0x11', dest_delta: [DELTA_X, DELTA_Y]});

// thiscall: 1º arg = this(ecx); pilha (u32 0, u64 0x11, u64 x, u64 y, u64 0, u64 0).
var dispFn = new NativeFunction(dispatcher, 'uint',
  ['pointer', 'uint32', 'uint64', 'uint64', 'uint64', 'uint64', 'uint64'],
  {abi: 'thiscall', exceptions: 'propagate'});
['poll', 'ppoll', 'select', 'pselect', 'pselect6'].forEach(function (name) {
  var fn = Module.findGlobalExportByName(name); if (!fn || ticks[fn.toString()]) return; ticks[fn.toString()] = true;
  Interceptor.attach(fn, {onEnter: function () {
    if (done || fired || Process.getCurrentThreadId() !== th.id) return;
    if (dispThis === null || capCoord === null) return;   // espera capturar this+coord de um passo natural
    if (!emitPending) return;
    // Remove TODOS os HW breakpoints ANTES de chamar: o freeze anterior ocorreu com store/receptor
    // BPs disparando DENTRO da nossa própria chamada (single-step/handler reentrante). Observação
    // do efeito passa a ser só pelos hooks Interceptor (transport sendmsg + recv_0087), que não
    // interferem na execução. (UNARM_ALL)
    if (!dispUnarmed) {
      stop(); dispUnarmed = true; emit({site: 'all_bp_unarmed'});
    }
    fired = true; emitState.thread_ok = true;
    if (m.add(0x58).readU32() !== 1 || !m.add(4).readPointer().equals(receiverObject)) {
      emit({site: 'emit_abort', reason: 'manager changed before call'}); return;
    }
    // destino = coordenada do passo natural capturado + delta pequeno (garante tile válido/andável
    // perto da posição atual, seja qual for); diferente do capturado para forçar deslocamento.
    var dx = capCoord[0] + DELTA_X, dy = capCoord[1] + DELTA_Y;
    if (dx < 0) dx = 0; if (dx > 1023) dx = 1023; if (dy < 0) dy = 0; if (dy > 1023) dy = 1023;
    try { emitState.attempted = true;
      emit({site: 'emit_call', dest: [dx, dy], from_captured: capCoord, this_ecx: dispThis.toString()});
      inCall = true;
      dispFn(dispThis, 0, 0x11, dx, dy, 0, 0);
      inCall = false; emitState.returned = true; emit({site: 'emit_return'});
    } catch (e) { inCall = false; emit({site: 'emit_error', message: e.message}); }
  }});
});
if (Object.keys(ticks).length === 0) throw new Error('No main-thread drain hook');
// emitPending é agendado DELAY_MS após a captura do this (ver handler), não por relógio de parede.
setTimeout(function () { finish({reason: 'timeout'}); }, TIMEOUT_MS);
"""


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--pid', type=int, required=True)
    ap.add_argument('--out', required=True)
    ap.add_argument('--emit-dx', type=int, default=4, help='delta X sobre a coord natural capturada')
    ap.add_argument('--emit-dy', type=int, default=0, help='delta Y sobre a coord natural capturada')
    ap.add_argument('--port', type=int, default=27053)
    ap.add_argument('--timeout-ms', type=int, default=10000)
    ap.add_argument('--delay-ms', type=int, default=4000)
    ap.add_argument('--server-port', type=int, default=5121)
    ap.add_argument('--event-cap', type=int, default=6000)
    ap.add_argument('--dispatcher', default='0xd473b0')
    ap.add_argument('--table', default=TABLE)
    a = ap.parse_args(argv)
    assert 1000 <= a.timeout_ms <= 10000
    assert 100 <= a.delay_ms <= 9000
    assert -64 <= a.emit_dx <= 64 and -64 <= a.emit_dy <= 64, 'delta pequeno (tile vizinho andável)'
    assert (a.emit_dx, a.emit_dy) != (0, 0), 'delta nao-nulo para forcar deslocamento'
    assert Path('/proc', str(a.pid), 'comm').read_text().strip().lower() == 'uaro.exe'
    source = (JS.replace('TIMEOUT_MS', str(a.timeout_ms)).replace('DELAY_MS', str(a.delay_ms))
              .replace('EVENT_CAP', str(a.event_cap)).replace('SERVER_PORT', str(a.server_port))
              .replace('DISPATCHER_PTR', json.dumps(a.dispatcher))
              .replace('PACKET_LENGTHS', json.dumps(load_lengths(a.table)))
              .replace('DELTA_X', str(a.emit_dx)).replace('DELTA_Y', str(a.emit_dy)))

    result = {'events': []}
    done = threading.Event()
    signal.signal(signal.SIGTERM, lambda *_: done.set())
    signal.signal(signal.SIGINT, lambda *_: done.set())

    def flush_file():
        try:
            Path(a.out).write_text(json.dumps(result, indent=2) + '\n')
        except OSError:
            pass

    def on_message(msg, data):
        if msg['type'] == 'send':
            v = msg['payload']
            # Eventos em streaming (tag EV) sao gravados incrementalmente para sobreviver a um
            # freeze/kill; o DONE (se vier) traz o resumo/limpeza.
            result['events'].append(v); flush_file()
            if v.get('tag') == 'READY':
                print('READY', flush=True)
            if v.get('tag') == 'DONE':
                done.set()
        elif msg['type'] == 'error':
            result['events'].append({'tag': 'ERROR', 'message': msg.get('description')}); flush_file(); done.set()

    dev = frida.get_device_manager().add_remote_device('127.0.0.1:' + str(a.port))
    session = dev.attach('Gadget'); script = None
    try:
        script = session.create_script(source); script.on('message', on_message); script.load()
        if not done.wait(a.timeout_ms / 1000 + 5):
            result['events'].append({'tag': 'TIMEOUT'}); flush_file()
    finally:
        if script is not None:
            try:
                state = script.exports_sync.stop(); tries = 0
                while not state['ok'] and tries < 3:   # limpeza LIMITADA (cliente pode estar travado)
                    print('CLEANUP_RETRY', flush=True); time.sleep(1); tries += 1
                    state = script.exports_sync.stop()
                result['cleanup_calls_succeeded'] = bool(state.get('ok'))
            except Exception as e:
                result['cleanup_error'] = str(e)
            try:
                script.unload()
            except Exception:
                pass
        try:
            session.detach()
        except Exception:
            pass
    flush_file()
    end = next((x for x in result['events'] if x.get('tag') == 'DONE'), {})
    print(json.dumps({'cleared': end.get('cleared'), 'emit_state': end.get('emit_state'),
                      'events': len(end.get('events', [])), 'transport_apis_seen': end.get('transport_apis_seen')}),
          flush=True)
    assert end.get('cleared'), 'Limpeza da sonda nao confirmada'


if __name__ == '__main__':
    main()
