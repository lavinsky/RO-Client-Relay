#!/usr/bin/env python3
"""Mapeia o laço principal (READ-ONLY) para eleger um ponto de disparo pós-poll.

Objetivo: achar um call-site estável em `uaRO.exe` (base fixa) que recorra ~1x/frame na main
thread, DEPOIS do retorno de poll/select e ANTES do próximo poll, e que NÃO esteja dentro de uma
execução de movimento (subárvore do dispatcher 0xd473b0 / receptor). Não faz chamada nativa, não
escreve memória, não arma watchpoints de dados. Usa Stalker (call-summary) por janelas curtas
entre dois limiares de poll.

Uso: loop_map.py --pid PID --out ARQ [--census-ms 250] [--windows 6] [--port 27053]
"""
import argparse
import json
from pathlib import Path
import signal
import threading
import time

import frida

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
var dispatcher = ptr('0xd473b0');            // função de movimento (excluir subárvore)
var LO = ptr('0x401000'), HI = ptr('0x1717000');
function inUaRO(p) { return p.compare(LO) >= 0 && p.compare(HI) < 0; }
// Extensão aproximada da função do dispatcher (0xd473b0 .. epílogo 0xd47e61 + tabela): excluir.
var DLO = ptr('0xd473b0'), DHI = ptr('0xd47f00');
function inDispatcher(p) { return p.compare(DLO) >= 0 && p.compare(DHI) < 0; }

var t0 = Date.now(), events = [];
function emit(ev) { ev.ms = Date.now() - t0; events.push(ev); try { send({tag:'EV', ev:ev}); } catch(e){} }

var pollFns = [], pollSeen = 0, lastPollLeave = 0, windowsDone = 0, following = false;
var census = {};   // addr(hex) -> count (somado entre janelas pós-poll)
var CENSUS_MS = CENSUS_MS_V, WINDOWS = WINDOWS_V;

function startCensus() {
  if (following || windowsDone >= WINDOWS) return;
  following = true;
  try {
    Stalker.follow(mainTid, {
      events: {call: true},
      onCallSummary: function (summary) {
        for (var addr in summary) {
          var p = ptr(addr);
          if (!inUaRO(p) || inDispatcher(p)) continue;
          census[addr] = (census[addr] || 0) + summary[addr];
        }
      }
    });
  } catch (e) { emit({site:'stalker_error', message:String(e)}); following = false; return; }
  setTimeout(function () {
    try { Stalker.unfollow(mainTid); Stalker.flush(); } catch (e) {}
    following = false; windowsDone++;
    emit({site:'census_window', n: windowsDone, distinct: Object.keys(census).length});
    if (windowsDone >= WINDOWS) finish();
  }, CENSUS_MS);
}

['poll','ppoll','select','pselect','pselect6'].forEach(function (name) {
  var fn = Module.findGlobalExportByName(name); if (!fn) return; pollFns.push(name);
  Interceptor.attach(fn, {
    onEnter: function () { if (Process.getCurrentThreadId() !== mainTid) return; this.main = true; },
    onLeave: function () {
      if (!this.main) return;
      pollSeen++; lastPollLeave = Date.now();
      // dispara um censo logo após o retorno do poll (contexto pós-poll da main thread)
      if (!following && windowsDone < WINDOWS) startCensus();
    }
  });
});
if (pollFns.length === 0) throw new Error('No poll/select export');

var done = false;
function finish() {
  if (done) return; done = true;
  try { if (following) { Stalker.unfollow(mainTid); Stalker.flush(); } } catch (e) {}
  // ranking por contagem
  var ranked = Object.keys(census).map(function (a) { return {addr: a, count: census[a]}; })
                     .sort(function (x, y) { return y.count - x.count; }).slice(0, 40);
  send({tag:'DONE', main_tid: mainTid, gepard_base: gb.toString(), poll_fns: pollFns,
        poll_boundaries: pollSeen, windows: windowsDone, ranked: ranked, events: events});
}
rpc.exports = { finish: function () { finish(); return true; } };
send({tag:'READY', main_tid: mainTid, poll_fns: pollFns});
setTimeout(function () { finish(); }, TIMEOUT_MS);
"""


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--pid', type=int, required=True)
    ap.add_argument('--out', required=True)
    ap.add_argument('--census-ms', type=int, default=250)
    ap.add_argument('--windows', type=int, default=6)
    ap.add_argument('--timeout-ms', type=int, default=15000)
    ap.add_argument('--port', type=int, default=27053)
    a = ap.parse_args(argv)
    assert 50 <= a.census_ms <= 1000
    assert 1 <= a.windows <= 30
    assert 2000 <= a.timeout_ms <= 30000
    assert Path('/proc', str(a.pid), 'comm').read_text().strip().lower() == 'uaro.exe'
    source = (JS.replace('CENSUS_MS_V', str(a.census_ms)).replace('WINDOWS_V', str(a.windows))
              .replace('TIMEOUT_MS', str(a.timeout_ms)))

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
            v = msg['payload']; result['events'].append(v); flush_file()
            if v.get('tag') == 'READY':
                print('READY main_tid=%s' % v.get('main_tid'), flush=True)
            if v.get('tag') == 'DONE':
                result['done'] = v; flush_file(); done.set()
        elif msg['type'] == 'error':
            result['events'].append({'tag': 'ERROR', 'message': msg.get('description')}); flush_file(); done.set()

    dev = frida.get_device_manager().add_remote_device('127.0.0.1:' + str(a.port))
    session = dev.attach('Gadget'); script = None
    try:
        script = session.create_script(source); script.on('message', on_message); script.load()
        if not done.wait(a.timeout_ms / 1000 + 5):
            result['events'].append({'tag': 'TIMEOUT'}); flush_file()
        try:
            script.exports_sync.finish()
        except Exception:
            pass
    finally:
        if script is not None:
            try:
                script.unload()
            except Exception:
                pass
        try:
            session.detach()
        except Exception:
            pass
    flush_file()
    d = result.get('done', {})
    ranked = d.get('ranked', [])[:10]
    print(json.dumps({'poll_boundaries': d.get('poll_boundaries'), 'windows': d.get('windows'),
                      'top': ranked}, indent=2), flush=True)


if __name__ == '__main__':
    main()
