#!/usr/bin/env python3
"""Rodada MOVER-...-06: dispara a MESMA chamada 13-dword do dispatcher 0x11, mas de um sítio de
MAIN-LOOP do uaRO.exe (HW exec BP em CÓDIGO, base fixa 0x400000), FORA do contexto do `read` do
wineserver — teste discriminante da hipótese de reentrância Wine (rodadas 04/05: chamada chegou ao
scrambler mas return+freeze a 700ms / abort-mid-call a 2s, ambas disparadas de dentro de um `read`).

CAUTELAS (Orquestrador): (1) HW exec BP em código é OK; NÃO é o watchpoint de DADOS no slot de pilha
que derrubou o cliente antes; sem hook inline em uaRO/gepard. (2) Disparar de dentro do callback do
HW BP roda a chamada no contexto do handler de exceção do Frida — outro contexto não-natural; sucesso
classifica SÓ como "o contexto do read/wineserver era o problema". (3) Sítio eleito por observação
(~1x/frame na main thread, fora da subárvore do dispatcher) — use --observe-only primeiro. Uma
tentativa, sem retry.

Dois modos:
  --observe-only : arma só o fire-site e CONTA hits por thread por --observe-secs (SEM chamada nativa).
  (padrão)       : observadores §13.5 (3 HW BP) + hooks libc send/recv + fire-site (4º HW BP). No fire,
                   DESARMA os 3 observadores durante a chamada (evita falha de BP aninhado) e rearma
                   depois; mantém hooks libc p/ ver sendmsg/recv associados; diagnóstico /proc integrado.

Uso: dispatcher_trial_pesite.py --pid PID --out ARQ --fire-site 0x54aed0 [--observe-only] \
        [--dest-x MX --dest-y MY] [--delay-ms 700] [--post-ms 10000]
"""
import argparse
import hashlib
import json
import os
import shutil
import signal
import threading
import time
from pathlib import Path

import frida

import sample_thread

TABLE = Path(__file__).resolve().parents[2] / "data" / "uaro_recvpackets.txt"


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
var mainTid = Process.id;
var th = Process.enumerateThreads().filter(t => t.id === mainTid)[0];
if (!th) throw new Error('Main thread absent');
var gb = null;
Process.enumerateRanges({protection: '---', coalesce: false}).forEach(function (r) {
  if (r.file && /\/gepard\.dll$/i.test(r.file.path) && (gb === null || r.base.compare(gb) < 0)) gb = r.base;
});
if (!gb) throw new Error('Gepard mapping absent');
var store = gb.add(0x18eff2);
if (Instruction.parse(store).toString() !== 'mov byte ptr [ecx], bl') throw new Error('Store anchor mismatch');
var m = ptr('0x1213338');
var OBSERVE_ONLY = OBSERVE_FLAG;
var receiverObject = null, receiver = null;
if (!OBSERVE_ONLY) {
  if (m.add(0x58).readU32() !== 1) throw new Error('Receiver not ready');
  receiverObject = m.add(4).readPointer();
  receiver = receiverObject.readPointer().add(0x18).readPointer();
  if (!receiver.equals(gb.add(0x10a90))) throw new Error('Receiver changed');
}
var dispatcher = ptr(DISPATCHER_PTR);
if (!Process.findRangeByAddress(dispatcher)) throw new Error('Dispatcher unmapped');
var retIns = Instruction.parse(ptr('0xd47e61'));
if (!/ret\s+0x34/.test(retIns.toString())) throw new Error('ret 0x34 mismatch: ' + retIns.toString());
var fireSite = ptr(FIRE_SITE);
if (!Process.findRangeByAddress(fireSite)) throw new Error('fire-site unmapped: ' + fireSite);

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
  try { send({tag: 'EV', ev: ev}); } catch (e) {}
}

var inCall = false;
var emitState = {captured: false, attempted: false, returned: false, retval: null, exception: null, return_ms: null};
var dispThis = null, capFrame = null, capCoord = null;
var emitPending = false, emitScheduled = false, fired = false, postScheduled = false;
var fireHitsMain = 0, fireHitsOther = 0;

// ---- observadores libc (só no modo fire) ----
var peerFn = new NativeFunction(Module.getGlobalExportByName('getpeername'), 'int', ['int', 'pointer', 'pointer']);
var localFn = new NativeFunction(Module.getGlobalExportByName('getsockname'), 'int', ['int', 'pointer', 'pointer']);
var serverFd = {};
function isServerFd(fd) {
  if (fd in serverFd) return serverFd[fd];
  var sa = Memory.alloc(32), len = Memory.alloc(4); len.writeU32(32); var ok = false;
  if (peerFn(fd, sa, len) === 0 && sa.readU16() === 2) ok = (((sa.add(2).readU8() << 8) | sa.add(3).readU8()) === SERVER_PORT);
  serverFd[fd] = ok; return ok;
}
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
      emit({site: 'recv_0087', during_call: inCall, phase: (inCall ? 'sync' : (emitState.returned ? 'post_return' : 'pre')),
            src: [(v[0] << 2) | (v[1] >> 6), ((v[1] & 63) << 4) | (v[2] >> 4)],
            dst: [((v[2] & 15) << 6) | (v[3] >> 2), ((v[3] & 3) << 8) | v[4]]}); }
    pos += n;
  }
  f.buf = b.slice(pos);
}
if (!OBSERVE_ONLY) {
  var hookedT = {};
  ['send', 'sendto', 'sendmsg', 'write', 'writev'].forEach(function (name) {
    var fn = Module.findGlobalExportByName(name); if (!fn || hookedT[fn.toString()]) return; hookedT[fn.toString()] = true;
    var lenIdx = {send: 2, sendto: 2, write: 2};
    Interceptor.attach(fn, {
      onEnter: function (args) {
        if (done) return; this.fd = args[0].toInt32(); this.ok = this.fd >= 0 && isServerFd(this.fd); if (!this.ok) return;
        this.api = name;
        if (name in lenIdx) this.req = args[lenIdx[name]].toInt32();
        else if (name === 'sendmsg') this.req = sendmsgRequested(args[1]); else this.req = null;
        this.in_call = inCall;
      },
      onLeave: function (retval) {
        if (done || !this.ok) return;
        emit({site: 'transport', api: this.api, fd: this.fd, bytes_requested: this.req,
              bytes_returned: retval.toInt32(), during_call: this.in_call,
              phase: (this.in_call ? 'sync' : (emitState.returned ? 'post_return' : 'pre'))});
      }
    });
  });
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
}

// ---- gestão de HW breakpoints ----
var armed = {};                     // slot -> addr
function armSlot(slot, addr) { th.setHardwareBreakpoint(slot, addr); armed[slot] = addr; }
function unarmSlot(slot) { try { th.unsetHardwareBreakpoint(slot); } catch (e) {} delete armed[slot]; }
function stop() {
  var errors = [];
  Object.keys(armed).forEach(function (s) { try { th.unsetHardwareBreakpoint(parseInt(s)); } catch (e) { errors.push(String(e)); } });
  armed = {}; return {ok: errors.length === 0, errors: errors};
}
var cleanup = {ok: true, errors: []};
function finish(extra) {
  if (done) return; done = true; cleanup = stop();
  send(Object.assign({tag: 'DONE', cleared: cleanup.ok, elapsed_ms: Date.now() - t0, events: events,
                      saturated: saturated, framing_errors: framingErrors, emit_state: emitState,
                      main_tid: mainTid, fire_hits_main: fireHitsMain, fire_hits_other: fireHitsOther}, extra));
}
rpc.exports = {stop: function () { return stop(); }};

var dispFn = new NativeFunction(dispatcher, 'uint',
  ['pointer', 'uint32', 'uint32', 'uint32', 'uint32', 'uint32', 'uint32', 'uint32',
   'uint32', 'uint32', 'uint32', 'uint32', 'uint32', 'uint32'],
  {abi: 'thiscall', exceptions: 'propagate'});

var active = false;
function doFire(c) {
  fired = true; emitState.thread_ok = true;
  if (m.add(0x58).readU32() !== 1 || !m.add(4).readPointer().equals(receiverObject)) {
    emit({site: 'emit_abort', reason: 'manager changed before call'}); return;
  }
  var dx = DEST_X, dy = DEST_Y;
  if (dx < 0) dx = 0; if (dx > 1023) dx = 1023; if (dy < 0) dy = 0; if (dy > 1023) dy = 1023;
  if (dx === capCoord[0] && dy === capCoord[1]) { emit({site: 'emit_abort', reason: 'dest == captured', captured: capCoord}); return; }
  var f;
  if (capFrame === null) { f = [0, 0x11, 0, dx >>> 0, 0, dy >>> 0, 0, 0, 0, 0, 0, 0, 0]; }  // construct mode
  else { f = capFrame.slice(); f[3] = dx >>> 0; f[5] = dy >>> 0; }
  if (f[1] !== 0x11) { emit({site: 'emit_abort', reason: 'frame code != 0x11', frame: f}); return; }
  // DESARMA observadores (slots 0..2) e o fire-site (3) ANTES de chamar, p/ evitar BP aninhado
  unarmSlot(0); unarmSlot(1); unarmSlot(2); unarmSlot(3);
  try {
    emitState.attempted = true;
    emit({site: 'emit_call', dest: [dx, dy], from_captured: capCoord, fire_site: fireSite.toString(),
          this_ecx: dispThis.toString(), frame: f.map(function (v) { return v >>> 0; })});
    inCall = true;
    var rv = dispFn.apply(null, [dispThis].concat(f.map(function (v) { return v >>> 0; })));
    inCall = false; emitState.returned = true; emitState.retval = rv >>> 0; emitState.return_ms = Date.now() - t0;
    emit({site: 'emit_return', retval: rv >>> 0});
  } catch (e) {
    inCall = false; emit({site: 'emit_error', message: e.message});
  }
  // rearma observadores (não o fire-site: disparo único) p/ a janela pós-retorno
  try { armSlot(0, dispatcher); armSlot(1, receiver); armSlot(2, store); } catch (e) { emit({site: 'rearm_error', message: e.message}); }
  if (!postScheduled) { postScheduled = true; setTimeout(function () { finish({reason: 'post_window'}); }, POST_MS); }
}

var points = [dispatcher, receiver, store];
Process.setExceptionHandler(function (d) {
  if (d.type !== 'breakpoint') {
    if (inCall && emitState.exception === null) {
      emitState.exception = {type: d.type, address: d.address ? d.address.toString() : null,
                             pc: d.context ? d.context.pc.toString() : null};
      try { emit({site: 'native_exception', type: d.type,
                  address: d.address ? d.address.toString() : null,
                  pc: d.context ? d.context.pc.toString() : null,
                  region: d.context ? region(d.context.pc) : null}); } catch (e) {}
    }
    return false;
  }
  if (!active) return false;
  var c = d.context;
  // fire-site?
  if (c.pc.equals(fireSite)) {
    var onMain = (Process.getCurrentThreadId() === mainTid);
    if (OBSERVE_ONLY) { if (onMain) fireHitsMain++; else fireHitsOther++; return true; }
    if (done || fired || !onMain) return true;
    if (dispThis === null || !emitPending) return true;   // capFrame pode ser null no modo construct
    try { doFire(c); } catch (e) { emit({site: 'fire_handler_error', message: e.message}); }
    return true;
  }
  if (OBSERVE_ONLY) return false;
  var n = -1; for (var i = 0; i < points.length; i++) if (c.pc.equals(points[i])) { n = i; break; }
  if (n < 0) return false;
  try {
    if (n === 0) {
      var lo = c.esp.add(8).readU32(), hi = c.esp.add(12).readU32(); var code = (hi === 0 && lo <= 0x95) ? lo : null;
      // Captura de dispThis: modo CONSTRUCT = qualquer code (dispatcher é a switch principal, chamada
      // passivamente p/ 0x78 etc.); modo natural = só 0x11 (walk real).
      if (dispThis === null && !inCall && (CONSTRUCT_FLAG || code === 0x11)) {
        dispThis = c.ecx; capCoord = [-1, -1]; emitState.captured = true;
        if (CONSTRUCT_FLAG) {
          capFrame = null;   // frame 0x11 será construído em doFire a partir do destino
          emit({site: 'disp_captured', mode: 'construct', code: code, this_ecx: c.ecx.toString()});
        } else {
          var frame = []; for (var k = 0; k < 13; k++) frame.push(c.esp.add(4 + k * 4).readU32());
          capFrame = frame; capCoord = [c.esp.add(16).readU32(), c.esp.add(24).readU32()];
          emit({site: 'disp_captured', mode: 'natural', this_ecx: c.ecx.toString(), coord: capCoord, frame: frame.map(function (v) { return v >>> 0; })});
        }
        if (!emitScheduled) { emitScheduled = true; setTimeout(function () {
          emitPending = true; try { armSlot(3, fireSite); emit({site: 'fire_site_armed', addr: fireSite.toString()}); }
          catch (e) { emit({site: 'fire_arm_error', message: e.message}); } }, DELAY_MS); }
      }
      if (code === 0x11) {
        var x = c.esp.add(16).readU32(), y = c.esp.add(24).readU32();
        emit({site: 'dispatcher_0x11', coord: (x <= 1023 && y <= 1023) ? [x, y] : null,
              return_addr: c.esp.readPointer().toString(), return_region: region(c.esp.readPointer()),
              this_ecx: c.ecx.toString(), during_call: inCall});
      }
    } else if (n === 1) {
      if (c.esp.add(4).readU32() === 0x8a) { var rx = c.esp.add(8).readU32(), ry = c.esp.add(12).readU32();
        emit({site: 'receptor_0x8a', coord: (rx <= 1023 && ry <= 1023) ? [rx, ry] : null,
              this_is_manager: c.ecx.equals(receiverObject), this_ecx: c.ecx.toString(),
              return_addr: c.esp.readPointer().toString(), return_region: region(c.esp.readPointer()), during_call: inCall}); }
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
try {
  if (OBSERVE_ONLY) { armSlot(0, fireSite); }
  else { armSlot(0, dispatcher); armSlot(1, receiver); armSlot(2, store); }  // fire-site (3) armado tardiamente
} catch (e) { stop(); throw e; }

send({tag: 'READY', read_only: OBSERVE_ONLY, trial: 'native-dispatcher-0x11-pesite',
      main_tid: mainTid, dest: [DEST_X, DEST_Y], fire_site: fireSite.toString(), observe_only: OBSERVE_ONLY});
setTimeout(function () { finish({reason: 'timeout'}); }, TIMEOUT_MS);
"""


def _hash_copy(src, dst_dir):
    try:
        data = Path(src).read_bytes()
        h = hashlib.sha256(data).hexdigest()
        shutil.copy2(src, os.path.join(dst_dir, os.path.basename(src)))
        return {'src': str(src), 'sha256': h}
    except OSError as e:
        return {'src': str(src), 'error': str(e)}


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--pid', type=int, required=True)
    ap.add_argument('--out', required=True)
    ap.add_argument('--fire-site', default='0x54aed0', help='endereço de CÓDIGO uaRO.exe do sítio de disparo')
    ap.add_argument('--observe-only', action='store_true', help='só conta hits do fire-site por thread (read-only)')
    ap.add_argument('--construct-frame', action='store_true',
                    help='captura dispThis de QUALQUER code do dispatcher e CONSTRÓI o frame 0x11 do destino '
                         '(não exige passo natural/0x11). Assume dispThis compartilhado entre codes.')
    ap.add_argument('--dest-x', type=int, default=0)
    ap.add_argument('--dest-y', type=int, default=0)
    ap.add_argument('--port', type=int, default=27053)
    ap.add_argument('--timeout-ms', type=int, default=20000)
    ap.add_argument('--post-ms', type=int, default=10000)
    ap.add_argument('--delay-ms', type=int, default=700)
    ap.add_argument('--server-port', type=int, default=5121)
    ap.add_argument('--event-cap', type=int, default=6000)
    ap.add_argument('--dispatcher', default='0xd473b0')
    ap.add_argument('--table', default=TABLE)
    a = ap.parse_args(argv)
    assert 2000 <= a.timeout_ms <= 60000
    assert 1000 <= a.post_ms <= 10000
    assert 100 <= a.delay_ms <= 9000
    if not a.observe_only:
        assert 0 <= a.dest_x <= 1023 and 0 <= a.dest_y <= 1023, 'destino absoluto fora do mapa'
    assert Path('/proc', str(a.pid), 'comm').read_text().strip().lower() == 'uaro.exe'
    source = (JS.replace('TIMEOUT_MS', str(a.timeout_ms)).replace('DELAY_MS', str(a.delay_ms))
              .replace('POST_MS', str(a.post_ms)).replace('EVENT_CAP', str(a.event_cap))
              .replace('SERVER_PORT', str(a.server_port))
              .replace('DISPATCHER_PTR', json.dumps(a.dispatcher))
              .replace('PACKET_LENGTHS', json.dumps(load_lengths(a.table)))
              .replace('FIRE_SITE', json.dumps(a.fire_site))
              .replace('OBSERVE_FLAG', 'true' if a.observe_only else 'false')
              .replace('CONSTRUCT_FLAG', 'true' if a.construct_frame else 'false')
              .replace('DEST_X', str(a.dest_x)).replace('DEST_Y', str(a.dest_y)))

    out_dir = os.path.dirname(os.path.abspath(a.out))
    here = os.path.dirname(os.path.abspath(__file__))
    manifest = [_hash_copy(os.path.join(here, 'dispatcher_trial_pesite.py'), out_dir),
                _hash_copy(os.path.join(here, 'sample_thread.py'), out_dir)]

    result = {'events': [], 'probe_manifest': manifest}
    done = threading.Event()
    state = {'main_tid': None, 'returned': False, 'hang_diag': None}
    signal.signal(signal.SIGTERM, lambda *_: done.set())
    signal.signal(signal.SIGINT, lambda *_: done.set())

    def flush_file():
        try:
            Path(a.out).write_text(json.dumps(result, indent=2) + '\n')
        except OSError:
            pass

    def hang_watch():
        deadline = time.time() + 2.0
        while time.time() < deadline:
            if state['returned'] or done.is_set():
                return
            time.sleep(0.1)
        if state['returned'] or done.is_set() or state['main_tid'] is None:
            return
        series = sample_thread.sample_series(a.pid, state['main_tid'], interval_ms=500, duration_ms=5000)
        verdict = sample_thread.classify(series)
        state['hang_diag'] = {'classification': verdict, 'samples': len(series), 'series': series}
        result['hang_diagnosis'] = state['hang_diag']; flush_file()
        print('HANG_DIAG=%s' % verdict, flush=True)

    def on_message(msg, data):
        if msg['type'] == 'send':
            v = msg['payload']; result['events'].append(v); flush_file()
            if v.get('tag') == 'READY':
                state['main_tid'] = v.get('main_tid')
                print('READY main_tid=%s observe_only=%s fire_site=%s'
                      % (state['main_tid'], v.get('observe_only'), v.get('fire_site')), flush=True)
            if v.get('tag') == 'EV':
                site = (v.get('ev') or {}).get('site')
                if site == 'emit_call':
                    threading.Thread(target=hang_watch, daemon=True).start()
                elif site in ('emit_return', 'emit_error'):
                    state['returned'] = True
            if v.get('tag') == 'DONE':
                done.set()
        elif msg['type'] == 'error':
            result['events'].append({'tag': 'ERROR', 'message': msg.get('description')}); flush_file(); done.set()

    dev = frida.get_device_manager().add_remote_device('127.0.0.1:' + str(a.port))
    session = dev.attach('Gadget'); script = None
    try:
        script = session.create_script(source); script.on('message', on_message); script.load()
        if not done.wait(a.timeout_ms / 1000 + a.post_ms / 1000 + 6):
            result['events'].append({'tag': 'TIMEOUT'}); flush_file()
    finally:
        if script is not None:
            try:
                st = script.exports_sync.stop()
                result['cleanup_calls_succeeded'] = bool(st.get('ok'))
            except Exception as e:
                result['cleanup_error'] = str(e)
            try: script.unload()
            except Exception: pass
        try: session.detach()
        except Exception: pass
    flush_file()
    end = next((x for x in result['events'] if x.get('tag') == 'DONE'), {})
    print(json.dumps({'cleared': end.get('cleared'), 'emit_state': end.get('emit_state'),
                      'fire_hits_main': end.get('fire_hits_main'), 'fire_hits_other': end.get('fire_hits_other'),
                      'hang_diagnosis': result.get('hang_diagnosis')}), flush=True)


if __name__ == '__main__':
    main()
