#!/usr/bin/env python3
"""Ensaio nativo do dispatcher 0x11 disparado no onLeave de poll/select (pós-poll, main thread).

Rodada MOVER-20261015-03 (plano aprovado pelo Orquestrador). Igual a `dispatcher_trial13.py` na ABI
(13 dwords u32, `ret 0x34`), identidade do objeto e observadores (§13.5: 3 HW exec BP em
dispatcher/receptor/store + hooks SÓ em exports da libc send/recv/poll). Diferenças:
  - **disparo no `onLeave`** de poll/select da libc (fase pós-poll), não no `onEnter`;
  - **trava armada ANTES da chamada** (`fired=true` antes de `dispFn`; o dispatcher pode reentrar poll);
  - **destino ABSOLUTO validado** (`--dest-x/--dest-y`), p.ex. o tile de origem A do controle natural;
  - **janela pós-retorno** (`--post-ms`, até 10 s) mantendo observadores para `sendmsg`/`recv` associados;
  - **diagnóstico de travamento independente**: o driver Python, ao ver `emit_call` sem `emit_return`,
    amostra `/proc/<pid>/task/<main_tid>/{stat,wchan,syscall}` (via `sample_thread`, ≤10 amostras/5 s) e
    classifica progresso/loop/espera/término/perda-do-observador — SEM depender do callback JS.
  - **sem** `Interceptor.attach` em código do uaRO/gepard (regra da rodada).

Uma tentativa, sem retry. Destino confirmado com o Orquestrador. Build re-conferido por hash.

Uso: dispatcher_trial_onleave.py --pid PID --out ARQ --dest-x MX --dest-y MY [--post-ms 10000] [--port 27053]
"""
import argparse
import hashlib
import json
import os
import shutil
from pathlib import Path
import signal
import threading
import time

import frida

import sample_thread   # mesmo diretório; amostrador /proc independente do Frida

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
if (m.add(0x58).readU32() !== 1) throw new Error('Receiver not ready');
var receiverObject = m.add(4).readPointer();
var receiver = receiverObject.readPointer().add(0x18).readPointer();
if (!receiver.equals(gb.add(0x10a90))) throw new Error('Receiver changed');
var dispatcher = ptr(DISPATCHER_PTR);
if (!Process.findRangeByAddress(dispatcher)) throw new Error('Dispatcher unmapped');
var retIns = Instruction.parse(ptr('0xd47e61'));
if (!/ret\s+0x34/.test(retIns.toString())) throw new Error('ret 0x34 mismatch: ' + retIns.toString());

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
            bytes_returned: retval.toInt32(), ret_region: this.ret_region,
            during_call: this.in_call, phase: (this.in_call ? 'sync' : (emitState.returned ? 'post_return' : 'pre'))});
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
      emit({site: 'recv_0087', during_call: inCall, phase: (inCall ? 'sync' : (emitState.returned ? 'post_return' : 'pre')),
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
var emitState = {captured: false, attempted: false, returned: false, retval: null, exception: null, return_ms: null};
var dispThis = null, inCall = false, capFrame = null, capCoord = null;
var emitPending = false, emitScheduled = false, fired = false, ticks = {}, postScheduled = false;
function finish(extra) {
  if (done) return; done = true; cleanup = stop();
  send(Object.assign({tag: 'DONE', cleared: cleanup.ok, elapsed_ms: Date.now() - t0, events: events,
                      saturated: saturated, framing_errors: framingErrors, emit_state: emitState,
                      main_tid: mainTid, transport_apis_seen: transportApisSeen}, extra));
}
rpc.exports = {stop: function () { return stop(); }};

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
  var c = d.context, n = -1; for (var i = 0; i < points.length; i++) if (c.pc.equals(points[i])) { n = i; break; }
  if (n < 0) return false;
  try {
    if (n === 0) {
      var lo = c.esp.add(8).readU32(), hi = c.esp.add(12).readU32(); var code = (hi === 0 && lo <= 0x95) ? lo : null;
      if (code === 0x11) {
        var x = c.esp.add(16).readU32(), y = c.esp.add(24).readU32();
        if (dispThis === null && !inCall) {
          var frame = []; for (var k = 0; k < 13; k++) frame.push(c.esp.add(4 + k * 4).readU32());
          dispThis = c.ecx; capFrame = frame; capCoord = [x, y]; emitState.captured = true;
          emit({site: 'disp_captured', this_ecx: c.ecx.toString(), coord: [x, y], frame: frame.map(function (v) { return v >>> 0; })});
          if (!emitScheduled) { emitScheduled = true; setTimeout(function () { emitPending = true; }, DELAY_MS); }
        }
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

var dispFn = new NativeFunction(dispatcher, 'uint',
  ['pointer', 'uint32', 'uint32', 'uint32', 'uint32', 'uint32', 'uint32', 'uint32',
   'uint32', 'uint32', 'uint32', 'uint32', 'uint32', 'uint32'],
  {abi: 'thiscall', exceptions: 'propagate'});

send({tag: 'READY', read_only: false, trial: 'native-dispatcher-0x11-onleave', main_tid: mainTid,
      dest: [DEST_X, DEST_Y]});

// Disparo no onLeave do pump de wait/drain da main thread — fase pós-espera. Trava ANTES da chamada.
// Cliente Wine: o loop principal drena o wineserver via `read`/`writev`, NÃO libc poll (census
// read-only: read=1308 cham./5s na main vs poll=2). Âncora configurável via ANCHOR_LIST.
ANCHOR_LIST.forEach(function (name) {
  var fn = Module.findGlobalExportByName(name); if (!fn || ticks[fn.toString()]) return; ticks[fn.toString()] = true;
  Interceptor.attach(fn, {onLeave: function () {
    if (done || fired || Process.getCurrentThreadId() !== mainTid) return;
    if (dispThis === null || capFrame === null) return;   // precisa do frame natural capturado
    if (!emitPending) return;
    fired = true; emitState.thread_ok = true;             // TRAVA armada antes da chamada
    if (m.add(0x58).readU32() !== 1 || !m.add(4).readPointer().equals(receiverObject)) {
      emit({site: 'emit_abort', reason: 'manager changed before call'}); return;
    }
    var dx = DEST_X, dy = DEST_Y;                          // destino ABSOLUTO validado (tile A)
    if (dx < 0) dx = 0; if (dx > 1023) dx = 1023; if (dy < 0) dy = 0; if (dy > 1023) dy = 1023;
    if (dx === capCoord[0] && dy === capCoord[1]) { emit({site: 'emit_abort', reason: 'dest == captured (no displacement)', captured: capCoord}); return; }
    var f = capFrame.slice(); f[3] = dx >>> 0; f[5] = dy >>> 0;
    if (f[1] !== 0x11) { emit({site: 'emit_abort', reason: 'frame code != 0x11', frame: f}); return; }
    try { emitState.attempted = true;
      emit({site: 'emit_call', dest: [dx, dy], from_captured: capCoord, this_ecx: dispThis.toString(),
            anchor: name, frame: f.map(function (v) { return v >>> 0; })});
      inCall = true;
      var rv = dispFn.apply(null, [dispThis].concat(f.map(function (v) { return v >>> 0; })));
      inCall = false; emitState.returned = true; emitState.retval = rv >>> 0; emitState.return_ms = Date.now() - t0;
      emit({site: 'emit_return', retval: rv >>> 0});
      if (!postScheduled) { postScheduled = true; setTimeout(function () { finish({reason: 'post_window'}); }, POST_MS); }
    } catch (e) { inCall = false; emit({site: 'emit_error', message: e.message});
      if (!postScheduled) { postScheduled = true; setTimeout(function () { finish({reason: 'post_window_after_error'}); }, POST_MS); } }
  }});
});
if (Object.keys(ticks).length === 0) throw new Error('No main-thread drain hook');
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
    ap.add_argument('--dest-x', type=int, required=True, help='destino ABSOLUTO x validado (tile A)')
    ap.add_argument('--dest-y', type=int, required=True, help='destino ABSOLUTO y validado (tile A)')
    ap.add_argument('--port', type=int, default=27053)
    ap.add_argument('--timeout-ms', type=int, default=20000)
    ap.add_argument('--post-ms', type=int, default=10000, help='janela de observação após emit_return')
    ap.add_argument('--delay-ms', type=int, default=700)
    ap.add_argument('--anchor', default='read',
                    help='exports libc cujo onLeave serve de âncora pós-espera (CSV). Wine: read')
    ap.add_argument('--server-port', type=int, default=5121)
    ap.add_argument('--event-cap', type=int, default=6000)
    ap.add_argument('--dispatcher', default='0xd473b0')
    ap.add_argument('--table', default=TABLE)
    a = ap.parse_args(argv)
    assert 2000 <= a.timeout_ms <= 30000
    assert 1000 <= a.post_ms <= 10000
    assert 100 <= a.delay_ms <= 9000
    assert 0 <= a.dest_x <= 1023 and 0 <= a.dest_y <= 1023, 'destino absoluto fora do mapa'
    assert Path('/proc', str(a.pid), 'comm').read_text().strip().lower() == 'uaro.exe'
    source = (JS.replace('TIMEOUT_MS', str(a.timeout_ms)).replace('DELAY_MS', str(a.delay_ms))
              .replace('POST_MS', str(a.post_ms))
              .replace('EVENT_CAP', str(a.event_cap)).replace('SERVER_PORT', str(a.server_port))
              .replace('DISPATCHER_PTR', json.dumps(a.dispatcher))
              .replace('PACKET_LENGTHS', json.dumps(load_lengths(a.table)))
              .replace('DEST_X', str(a.dest_x)).replace('DEST_Y', str(a.dest_y))
              .replace('ANCHOR_LIST', json.dumps([s.strip() for s in a.anchor.split(',') if s.strip()])))

    out_dir = os.path.dirname(os.path.abspath(a.out))
    # Passo 6: cópia+hash das sondas executadas no diretório do artefato.
    here = os.path.dirname(os.path.abspath(__file__))
    scratch_elect = ("/tmp/claude-1000/-var-home-bazzite-Documentos-Projetos-improvement/"
                     "22fd4a14-e55f-414c-b643-efe43d5cf5ef/scratchpad/elect_firesite.py")
    manifest = [_hash_copy(os.path.join(here, 'dispatcher_trial_onleave.py'), out_dir),
                _hash_copy(os.path.join(here, 'sample_thread.py'), out_dir)]
    if os.path.exists(scratch_elect):
        manifest.append(_hash_copy(scratch_elect, out_dir))

    result = {'events': [], 'probe_manifest': manifest}
    done = threading.Event()
    state = {'main_tid': None, 'call_t': None, 'returned': False, 'hang_diag': None}
    signal.signal(signal.SIGTERM, lambda *_: done.set())
    signal.signal(signal.SIGINT, lambda *_: done.set())

    def flush_file():
        try:
            Path(a.out).write_text(json.dumps(result, indent=2) + '\n')
        except OSError:
            pass

    def hang_watch():
        # Diagnóstico independente do callback JS: se emit_call sem emit_return em ~2 s,
        # amostra /proc (<=10 amostras em 5 s) e classifica. Não preenche lacuna por memória.
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
                state['main_tid'] = v.get('main_tid'); print('READY main_tid=%s' % state['main_tid'], flush=True)
            if v.get('tag') == 'EV':
                site = (v.get('ev') or {}).get('site')
                if site == 'emit_call' and state['call_t'] is None:
                    state['call_t'] = time.time(); threading.Thread(target=hang_watch, daemon=True).start()
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
                state_cl = script.exports_sync.stop(); tries = 0
                while not state_cl['ok'] and tries < 3:
                    print('CLEANUP_RETRY', flush=True); time.sleep(1); tries += 1
                    state_cl = script.exports_sync.stop()
                result['cleanup_calls_succeeded'] = bool(state_cl.get('ok'))
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
                      'events': len(end.get('events', [])), 'hang_diagnosis': result.get('hang_diagnosis'),
                      'transport_apis_seen': end.get('transport_apis_seen')}), flush=True)


if __name__ == '__main__':
    main()
