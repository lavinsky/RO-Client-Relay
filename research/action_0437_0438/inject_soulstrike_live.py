#!/usr/bin/env python3
"""DEMONSTRACAO LIVE (autorizada pelo responsavel) — injecao de Soul Strike (skill 0x0d=13) lvl 10
via DISPATCHER NATIVO do cliente, metodo capture+replay (sem chute de ABI).

Fundamento (OBSERVADO, research/action_0437_0438): o pacote CZ 0x0438 (pericia) e originado pelo
dispatcher 0xd473b0 com `code 0x2a`, que NAO leva args no frame — le alvo/skill/nivel de estado
global montado pela cadeia de preparacao (0x0a alvo -> 0x29 skill+GID -> 0x5a nivel -> 0x2a dispara).
Reusa o mecanismo de disparo VALIDADO do PoC 035f (agent/relay_hook_linux.js:647-752, rodadas 06b/08):
captura passiva do `this` no dispatcher + chamada thiscall a partir do fire-site de main-loop 0x4dcba0.

Metodo (2 fases, 1 execucao):
  FASE CAPTURE: DR0 no dispatcher 0xd473b0 (le code=[esp+8] e os 13 dwords do frame; captura `this`=ecx);
    DR1 na SendPacket 0xC16640 (le o 0x0438 em claro p/ confirmar skill=13 nivel=10 e o GID). O
    responsavel lanca Soul Strike UMA vez num monstro. Gravamos a cadeia de (code,frame) ate o 0x2a.
  FASE REPLAY: congela a cadeia (do ultimo 0x0a ate o 0x2a), DESARMA DR0/DR1 (sem BP aninhado), arma
    DR3 no fire-site 0x4dcba0 e, na proxima passada da main, REPETE fn(this, frame) para cada (code,frame)
    capturado, em ordem, numa unica visita (tight loop) — o cliente remonta/cifra/envia o proprio 0x0438.
  Confirmacao de envio: Interceptor em sendmsg (fora de HW BP) registra o egress durante o replay; o
    efeito (dano) e visivel no cliente.

Seguranca: so dispara se a cadeia terminar em 0x2a; so na main thread; `this` capturado; UMA vez (fired).
Read-mostly: a unica escrita e a chamada thiscall com frames que o PROPRIO cliente acabou de produzir.
Se o cliente travar/alertar, pare. Servidor proprio do responsavel; autorizacao direta e ao vivo.

Uso: inject_soulstrike_live.py --pid PID --out ARQ [--port 27053] [--timeout-ms 60000]
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

var UA_BASE = ptr('0x400000'), UA_LO = ptr('0x401000'), UA_HI = ptr('0x1717000');
var dispatcher = ptr('0xd473b0');
var fireSite   = ptr('0x4dcba0');
var sendpacket = UA_BASE.add(SENDPKT_RVA);
var RET34      = ptr('0xd47e61');   // ancora: ret 0x34 (13 dwords) do epilogo do dispatcher
var IDLE = 0x78;
var SKILL_ID = 0x0438, CAST_CODE = 0x2a;
// allowlist ESTRITA da cadeia de pericia: set-skill+GID, set-nivel, selecionar-alvo, disparar.
// Tudo fora disso (movimento 0x11, housekeeping 0x0d/0x5b/0x0f, code 0x00, etc.) e PROIBIDO no replay.
var SKILL_CODES = {0x29: 1, 0x5a: 1, 0x0a: 1, 0x2a: 1};

for (var k = 0; k < 3; k++) {
  var chk = [dispatcher, fireSite, sendpacket][k];
  if (!Process.findRangeByAddress(chk)) throw new Error('addr unmapped: ' + chk);
}
if (!/ret\s+0x34/.test(Instruction.parse(RET34).toString())) throw new Error('ret 0x34 anchor mismatch');

var th = Process.enumerateThreads().filter(function (t) { return t.id === mainTid; })[0];
if (!th) throw new Error('main thread absent');
var types = ['pointer']; for (var i = 0; i < 13; i++) types.push('uint32');
var dispFn = new NativeFunction(dispatcher, 'uint', types, {abi: 'thiscall', exceptions: 'propagate'});

var t0 = Date.now();
function ms() { return Date.now() - t0; }

var phase = 'capture';
var thisp = null;
var chain = [];           // {code, frame[13]} rolantes de codes != idle
var captured = null;      // cadeia congelada p/ replay
var fired = false;
var done = false;

function readFrame(ctx) {
  var f = [];
  for (var k = 0; k < 13; k++) { try { f.push(ctx.esp.add(4 + k * 4).readU32() >>> 0); } catch (e) { f.push(0); } }
  return f;
}
function plausibleId(v) { return v >= 0x0001 && v <= 0x0fff; }

function freezeChain() {
  // cauda MINIMA e CONTIGUA de codes de pericia que termina em 0x2a: anda pra tras a partir do
  // ultimo 0x2a incluindo SO codes da allowlist; para no primeiro code fora dela. Nunca engloba
  // movimento/housekeeping. Exige ao menos {0x29,0x5a,0x2a} e tamanho pequeno (<=6).
  var last2a = -1, i;
  for (i = chain.length - 1; i >= 0; i--) { if (chain[i].code === CAST_CODE) { last2a = i; break; } }
  if (last2a < 0) return null;
  var start = last2a;
  for (i = last2a - 1; i >= 0; i--) { if (SKILL_CODES[chain[i].code]) start = i; else break; }
  var sub = chain.slice(start, last2a + 1);
  // guarda dura: toda code na allowlist, tem 0x29 e 0x5a, termina em 0x2a, tamanho <=6.
  var seen = {}, ok = true;
  sub.forEach(function (x) { if (!SKILL_CODES[x.code]) ok = false; seen[x.code] = 1; });
  if (!ok || sub.length === 0 || sub.length > 6) return null;
  if (!seen[0x29] || !seen[0x5a] || sub[sub.length - 1].code !== CAST_CODE) return null;
  return sub;
}

function disarm(slot) { try { th.unsetHardwareBreakpoint(slot); } catch (e) {} }

Process.setExceptionHandler(function (d) {
  if (d.type !== 'breakpoint' || done) return false;
  var c = d.context, pc = c.pc;

  if (pc.equals(dispatcher)) {
    if (Process.getCurrentThreadId() !== mainTid) return true;
    var lo, hi;
    try { lo = c.esp.add(8).readU32() >>> 0; hi = c.esp.add(12).readU32() >>> 0; } catch (e) { return true; }
    if (!(hi === 0 && lo <= 0x95)) return true;
    if (thisp === null) { thisp = c.ecx; send({site: 'this_captured', ms: ms(), 'this': thisp.toString(), code: lo}); }
    if (phase === 'capture' && lo !== IDLE) {
      var fr = readFrame(c);
      chain.push({code: lo, frame: fr});
      if (chain.length > 48) chain.shift();
    }
    return true;
  }

  if (pc.equals(sendpacket)) {
    if (phase !== 'capture') return true;
    var buf = null, id = null;
    for (var j = 1; j <= 4; j++) {
      var a = null; try { a = c.esp.add(j * 4).readPointer(); } catch (e) {}
      if (a !== null) { var idv = null; try { idv = a.readU16(); } catch (e) {} if (idv !== null && plausibleId(idv)) { buf = a; id = idv; break; } }
    }
    if (id === null) return true;
    var body = null; try { body = buf.readByteArray(16); } catch (e) {}
    send({site: 'sendpacket_capture', ms: ms(), id_hex: '0x' + id.toString(16)}, body);
    if (id === SKILL_ID && captured === null) {
      captured = freezeChain();
      if (captured === null) { send({site: 'no_chain', ms: ms(), chain: chain.map(function (x){return x.code;})}); return true; }
      send({site: 'chain_frozen', ms: ms(), codes: captured.map(function (x){return x.code;}),
            frames: captured.map(function (x){return x.frame;})});
      // transicao p/ replay: sem BP aninhado
      disarm(0); disarm(1);
      phase = 'replay';
      try { th.setHardwareBreakpoint(3, fireSite); send({site: 'replay_armed', ms: ms()}); }
      catch (e) { send({site: 'error', e: 'arm fireSite: ' + e.message}); }
    }
    return true;
  }

  if (pc.equals(fireSite)) {
    if (phase !== 'replay' || fired || thisp === null || captured === null) return true;
    if (Process.getCurrentThreadId() !== mainTid) return true;
    fired = true;
    disarm(3); disarm(0);   // garante: nada aninhado durante as chamadas
    send({site: 'replay_fire', ms: ms(), n: captured.length, 'this': thisp.toString()});
    for (var q = 0; q < captured.length; q++) {
      var step = captured[q], rv = null, ex = null;
      try { rv = dispFn.apply(null, [thisp].concat(step.frame)) >>> 0; }
      catch (e) { ex = String(e.message || e); }
      send({site: 'replay_step', ms: ms(), idx: q, code: step.code, retval: rv, exception: ex});
    }
    send({site: 'replay_done', ms: ms()});
    return true;
  }
  return false;
});

// egress out-of-band (confirma envio no replay sem HW BP aninhado)
var sm = Module.findGlobalExportByName('sendmsg');
if (sm) {
  Interceptor.attach(sm, { onEnter: function (a) {
    try {
      var msg = a[1], iov = msg.add(8).readPointer(), n = msg.add(12).readU32(), tot = 0;
      for (var i = 0; i < Math.min(n, 32); i++) tot += iov.add(i * 8 + 4).readU32();
      if (tot > 0 && tot <= 80) send({site: 'sendmsg', bytes: tot, ms: ms(), phase: phase});
    } catch (e) {}
  }});
}

try { th.setHardwareBreakpoint(0, dispatcher); th.setHardwareBreakpoint(1, sendpacket); }
catch (e) { throw new Error('HW BP arm failed: ' + e.message); }
send({site: 'READY', ms: ms(), main_tid: mainTid, dispatcher: dispatcher.toString(),
      fireSite: fireSite.toString(), sendpacket: sendpacket.toString()});

setTimeout(function () { done = true; disarm(0); disarm(1); disarm(3);
  send({site: 'DONE', ms: ms(), fired: fired}); }, TIMEOUT_MS);
rpc.exports = { stop: function () { done = true; disarm(0); disarm(1); disarm(3); return {fired: fired}; } };
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
    result = {'meta': {'pid': a.pid, 'generated': time.strftime('%Y-%m-%dT%H:%M:%S'),
                       'task': 'inject soul-strike lvl10 via native dispatcher (capture+replay)'},
              'events': []}

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
            if tag in ('READY', 'this_captured', 'sendpacket_capture', 'chain_frozen', 'no_chain',
                       'replay_armed', 'replay_fire', 'replay_step', 'replay_done', 'sendmsg', 'error', 'DONE'):
                print(json.dumps(v), flush=True)
            if tag == 'DONE':
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
    ev = result['events']
    fired = any(e.get('site') == 'replay_done' for e in ev)
    steps = [e for e in ev if e.get('site') == 'replay_step']
    sends_replay = [e for e in ev if e.get('site') == 'sendmsg' and e.get('phase') == 'replay']
    print(json.dumps({'out': str(Path(a.out).resolve()), 'replay_fired': fired,
                      'steps': [{'code': hex(s['code']), 'retval': s.get('retval'), 'exc': s.get('exception')} for s in steps],
                      'sendmsg_during_replay': len(sends_replay)}, indent=2), flush=True)


if __name__ == '__main__':
    main()
