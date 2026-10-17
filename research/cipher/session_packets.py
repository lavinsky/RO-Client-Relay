"""Passive packet inventory: login through ten seconds after map acceptance.

No relay connection, server writes, debug registers, or synthetic input. Only control
packet bodies are retained, in a caller-supplied private directory; HTTP bodies,
account IDs, character lists and authentication bodies are never written.
"""
import argparse
import collections
import hashlib
import json
import os
from pathlib import Path
import queue
import signal
import sys
import time

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
from relay.packets import NEED_MORE, load_lengths, packet_len

CONTROL = {0x4754, 0x5395, 0xc392, 0x8280}
MAP_ACCEPT = {0x0073, 0x02eb, 0x0a18}


def window_reason(map_ts, seconds, finished, had_interruption=False):
    if map_ts is None:
        return 'timeout_after_map_interrupt' if had_interruption else 'timeout_before_map'
    return 'map_window_complete' if finished >= map_ts / 1000 + seconds else 'timeout_during_map'


class PacketInventory:
    """Strict directional reassembly. Unknown lengths halt that stream, without guessing."""
    def __init__(self, lengths, emit):
        self.lengths, self.emit = lengths, emit
        self.streams = {}
        self.connections = {}
        self.next_connection = 1
        self.counts = collections.Counter()
        self.map_accept_ts = None
        self.map_ts = None
        self.map_connection = None
        self.interrupted_windows = []

    def push(self, m):
        direction = 'R' if m['tag'] == 'RECV' else 'S'
        port = int(m['sock'].rsplit(':', 1)[1])
        key = (m.get('conn'), m['sock'], direction)
        if key[:2] not in self.connections:
            self.connections[key[:2]] = self.next_connection
            self.next_connection += 1
        cid = self.connections[key[:2]]
        state = self.streams.setdefault(key, dict(buf=b'', off=0, first=True, halted=False,
                                                  connection=cid, spans=[]))
        raw = bytes.fromhex(m['C'])
        if port in (3000, 6700):
            self.counts['non_ro_bytes'] += len(raw)
            return
        if state['halted']:
            self.counts['unparsed_bytes'] += len(raw)
            return
        start = state['off'] + len(state['buf'])
        state['spans'].append((start, start + len(raw), m['ts'], m['seq']))
        state['buf'] += raw
        while len(state['buf']) >= 2:
            buf = state['buf']
            n = packet_len(self.lengths, buf, 0)
            if n == NEED_MORE:
                break
            if n is None:
                # Observed char-server preamble; discard only the unframed four-byte AID.
                if state['first'] and direction == 'R' and port == 6121:
                    if len(buf) < 4:
                        break
                    state['buf'], state['off'], state['first'] = buf[4:], state['off'] + 4, False
                    self.counts['account_preamble_bytes'] += 4
                    continue
                state['halted'] = True
                self.counts['unparsed_bytes'] += len(buf)
                self.emit('anomaly', dict(connection=state['connection'], direction=direction,
                                         port=port, offset=state['off'], id=f'{int.from_bytes(buf[:2], "little"):04x}',
                                         reason='unknown_or_invalid_length', bytes=len(buf)))
                state['buf'] = b''
                break
            if len(buf) < n:
                break
            packet, off = buf[:n], state['off']
            span = next(s for s in state['spans'] if s[0] <= off < s[1])
            pid = int.from_bytes(packet[:2], 'little')
            rec = dict(connection=state['connection'], direction=direction, port=port,
                       id=f'{pid:04x}', length=n, offset=off, ts=span[2], seq=span[3],
                       completed_ts=m['ts'], callers=m.get('callers', []))
            self.emit('packet', rec)
            if pid in CONTROL:
                self.emit('control', dict(rec, hex=packet.hex()))
            if direction == 'R' and port == 5121 and pid in MAP_ACCEPT:
                if self.map_ts is not None:
                    self.interrupt_map(m['ts'], 'new_map_acceptance')
                self.map_accept_ts = m['ts']
                self.map_connection = cid
            if (direction == 'S' and port == 5121 and pid == 0x007d
                    and cid == self.map_connection and self.map_accept_ts is not None and self.map_ts is None):
                self.map_ts = m['ts']
            if direction == 'S' and port == 5121 and pid == 0x00b2:
                self.interrupt_map(m['ts'], 'restart_request')
            self.counts[f'{direction}:{pid:04x}'] += 1
            state['buf'], state['off'], state['first'] = buf[n:], off + n, False
            state['spans'] = [s for s in state['spans'] if s[1] > state['off']]

    def close(self, m):
        base = (m.get('conn'), m['sock'])
        cid = self.connections.pop(base, None)
        if cid == self.map_connection:
            self.interrupt_map(m['ts'], 'map_socket_closed')
        for direction in ('R', 'S'):
            state = self.streams.pop(base + (direction,), None)
            if state and state['buf']:
                self.counts['closed_partial_bytes'] += len(state['buf'])
                self.emit('anomaly', dict(connection=state['connection'], direction=direction,
                                         reason='closed_with_partial', bytes=len(state['buf'])))

    def interrupt_map(self, ts, reason):
        if self.map_ts is not None:
            self.interrupted_windows.append(dict(start=self.map_ts, end=ts, reason=reason))
        self.map_ts = self.map_accept_ts = self.map_connection = None

    def summary(self):
        return dict(counts=dict(self.counts), map_ts=self.map_ts, map_accept_ts=self.map_accept_ts,
                    interrupted_windows=self.interrupted_windows,
                    pending_bytes=sum(len(s['buf']) for s in self.streams.values()),
                    halted_streams=sum(s['halted'] for s in self.streams.values()))


def instrument_source(source):
    """Add bounded accurate call stacks to the existing libc observers, without arming HW BPs."""
    helper = """
function controlCallers(ctx, h) {
    var id = pktId(h);
    if (['4754','5395','c392','8280'].indexOf(id) < 0) return [];
    try { return Thread.backtrace(ctx, Backtracer.ACCURATE).slice(0,32).map(function(a) {
        var c = codeAt(a);
        return c ? {module:c.name, rva:a.sub(c.base).toString()} : {unresolved:a.toString()};
    }); } catch(e) { return [{error:String(e)}]; }
}
var closeAddress = Module.findGlobalExportByName('close');
if (closeAddress) Interceptor.attach(closeAddress, {
    onEnter: function(args) {
        this.fd = args[0].toInt32();
        var cached = peerCache[this.fd];
        this.peer = cached ? (peerOf(this.fd) || cached) : null;
        this.conn = connCache[this.fd];
    },
    onLeave: function(ret) {
        if (ret.toInt32() === 0 && this.peer) {
            send({tag:'CLOSE',sock:this.peer,conn:this.conn,seq:seq++,ts:Date.now()});
            delete peerCache[this.fd]; delete connCache[this.fd];
        }
    }
});
"""
    old = '        iovs(this.msg, n).forEach(function (v, k) {'
    if source.count(old) != 1:
        raise ValueError('recv observer changed; review instrumentation adapter')
    source = source.replace(old, '        var callCtx = this.context;\n' + old)
    old = "ptr: v[0].toString(), seq: seq++, ts: Date.now(),"
    if source.count(old) != 1:
        raise ValueError('recv message changed')
    source = source.replace(old, "callers: controlCallers(callCtx, h), " + old)
    old = "len: n, id: pktId(h), C: h, seq: seq++, ts: Date.now()};"
    if source.count(old) != 1:
        raise ValueError('send message changed')
    source = source.replace(old, "callers: controlCallers(this.context, h), " + old)
    return source + helper


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--port', type=int, required=True)
    ap.add_argument('--pid', type=int, required=True)
    ap.add_argument('--out', type=Path, required=True)
    ap.add_argument('--exclusive-confirmed', action='store_true', required=True)
    ap.add_argument('--map-seconds', type=float, default=10)
    ap.add_argument('--max-seconds', type=float, default=300)
    ap.add_argument('--start-now', action='store_true', help='bounded map-only follow-up; no login coverage')
    args = ap.parse_args(argv)
    if not (0 < args.map_seconds <= 30 and 0 < args.max_seconds <= 600):
        ap.error('bounded capture required')
    os.umask(0o077)
    args.out.mkdir(mode=0o700, parents=True, exist_ok=True)
    if args.out.stat().st_mode & 0o077:
        ap.error('output directory must be private (0700)')
    import frida
    from relay.agent import pid_of_port
    if pid_of_port(args.port) != args.pid:
        ap.error('Gadget port does not belong to the requested PID')
    identity = Path(f'/proc/{args.pid}/stat').read_text().rsplit(')', 1)[1].split()[19]
    original = (ROOT / 'agent/relay_hook_linux.js').read_text()
    source = instrument_source(original)
    (args.out / 'executed-agent.js').write_text(source)
    driver = Path(__file__).read_bytes()
    (args.out / 'executed-driver.py').write_bytes(driver)
    events = queue.Queue(maxsize=10000)
    losses = []
    def on_message(msg, data):
        try:
            events.put_nowait(msg)
        except queue.Full:
            losses.append('queue_full')
    files = {k: (args.out / f'{k}s.jsonl').open('x', buffering=1)
             for k in ('packet', 'control', 'anomaly')}
    def emit(kind, rec):
        files[kind].write(json.dumps(rec) + '\n')
    inv = PacketInventory(load_lengths(ROOT / 'data/uaro_recvpackets.txt'), emit)
    for sig in (signal.SIGTERM, signal.SIGINT):
        signal.signal(sig, lambda s, f: (_ for _ in ()).throw(KeyboardInterrupt()))
    started, stopped = time.time(), 'timeout_before_map'
    if args.start_now:
        inv.map_ts = started * 1000
        stopped = 'map_window_complete'
    errors, transport, last_seq = [], collections.Counter(), None
    device = frida.get_device_manager().add_remote_device(f'127.0.0.1:{args.port}')
    session = device.attach('Gadget')
    script = session.create_script(source)
    script.on('message', on_message)
    loaded = False
    try:
        script.load(); loaded = True
        print('READY: passive capture; ' + ('map-only follow-up' if args.start_now else
              'complete login, then remain in map for ten seconds'), flush=True)
        deadline = started + args.max_seconds
        if args.start_now:
            deadline = min(deadline, started + args.map_seconds)
        while time.time() < deadline:
            try:
                msg = events.get(timeout=0.1)
            except queue.Empty:
                continue
            if msg.get('type') == 'error':
                errors.append(msg.get('description', 'script_error'))
                continue
            m = msg.get('payload')
            if not isinstance(m, dict) or m.get('tag') not in ('RECV', 'SEND', 'CLOSE'):
                continue
            if last_seq is not None and m['seq'] != last_seq + 1:
                losses.append('sequence_gap')
            last_seq = m['seq']
            if m['tag'] == 'CLOSE':
                transport['CLOSE'] += 1
                inv.close(m)
                deadline = started + args.max_seconds if inv.map_ts is None else deadline
                continue
            if inv.map_ts is not None and m['ts'] > inv.map_ts + args.map_seconds * 1000:
                stopped = 'map_window_complete'
                break
            transport[m['tag']] += 1
            inv.push(m)
            deadline = started + args.max_seconds
            if inv.map_ts is not None:
                deadline = min(started + args.max_seconds, inv.map_ts / 1000 + args.map_seconds)
                stopped = 'map_window_complete'
    except KeyboardInterrupt:
        stopped = 'interrupted'
    finally:
        if stopped != 'interrupted':
            stopped = window_reason(inv.map_ts, args.map_seconds, time.time(), bool(inv.interrupted_windows))
        cleanup = {}
        if loaded:
            try:
                script.unload(); cleanup['unload'] = True
            except Exception as exc:
                cleanup['unload'] = type(exc).__name__
        try:
            session.detach(); cleanup['detach'] = True
        except Exception as exc:
            cleanup['detach'] = type(exc).__name__
        for f in files.values():
            f.close()
        summary = dict(inv.summary(), started=started, finished=time.time(), reason=stopped,
                       map_seconds=args.map_seconds, transport=dict(transport), errors=errors,
                       mode='map_only' if args.start_now else 'login_through_map',
                       losses=losses, cleanup=cleanup, pid=args.pid,
                       starttime_ticks=identity,
                       driver_sha256=hashlib.sha256(driver).hexdigest(),
                       source_sha256=hashlib.sha256(source.encode()).hexdigest())
        (args.out / 'summary.json').write_text(json.dumps(summary, indent=2) + '\n')
        print(json.dumps(summary), flush=True)
    complete = not (summary['pending_bytes'] or summary['halted_streams']
                    or inv.counts['unparsed_bytes'] or inv.counts['closed_partial_bytes'])
    clean = cleanup.get('unload') is True and cleanup.get('detach') is True
    return 0 if stopped == 'map_window_complete' and complete and clean and not (errors or losses) else 1


if __name__ == '__main__':
    raise SystemExit(main())
