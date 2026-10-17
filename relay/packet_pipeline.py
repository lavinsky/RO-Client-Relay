"""Ragnarok packet framing, ordered receive recovery and sanitized client send feed."""
import collections
import threading
import time
from contextlib import nullcontext

from .actor_recovery import ActorDecrypt
from .frida_bridge import conn_of, ring_msg
from .traffic_safety import client_packet_to_feed, is_game_sock, is_login_sock, looks_like_http


VAR = -1                                           # length table: variable length, read from bytes 2-3
NEED_MORE = 0                                      # packet_len(): the length isn't readable yet
MOVE_ID = 0x0087                                   # ZC_NOTIFY_PLAYERMOVE (own-character move)


def load_lengths(path):
    """{packet id: length} from an the consumer recvpackets.txt ('<hex id> <len> ...' per line).
    Lengths that can't frame a packet (0, 1, < -1) are skipped, so the id counts as unknown
    instead of stalling a tokenizer on a zero-length packet. Raises OSError if unreadable."""
    lengths = {}
    with open(path) as f:
        for line in f:
            p = line.split()
            if len(p) < 2:
                continue
            try:
                pid, L = int(p[0], 16), int(p[1])
            except ValueError:
                continue
            if L == VAR or L >= 2:
                lengths[pid] = L
    return lengths


def packet_len(lengths, buf, pos):
    """Length of the packet starting at buf[pos] (needs pos + 2 <= len(buf)).
    None = unknown id or impossible length; NEED_MORE = a variable length isn't in buf yet."""
    pid = buf[pos] | (buf[pos + 1] << 8)
    L = lengths.get(pid)
    if L == VAR:
        if pos + 4 > len(buf):
            return NEED_MORE
        L = buf[pos + 2] | (buf[pos + 3] << 8)
        return L if L >= 4 else None
    return L if L is not None and L >= 2 else None


class WireFilter:
    """Per-connection packet tokenizer for --wire mode (the default).

    uaRO's server->client stream is CLEARTEXT on the wire except the bodies of a few packets
    (09fd actor_moved, 09ff actor_exists: they are encrypted; id+length stay clear). So we
    feed the wire bytes and only cut out those garbage-bodied packets (plus --drop-ids), whole,
    so the consumer's tokenizer stays aligned. Keyed by TCP connection (agent's local port), so a
    partial packet left on a closed connection never bleeds into the next one. The first
    4 bytes of a connection with an unknown id are the bare account ID the char server sends
    before received_characters - passed through for the consumer. Any other unknown id switches
    that connection to pass-through (fail open: the consumer resyncs better than we would)."""

    def __init__(self, lengths, drop):
        self.L, self.drop = lengths, drop
        self.conns = {}                                # conn -> {'buf', 'start', 'raw', 'off'}
        self.on_packet = None                          # callback(conn, pid, stream_offset, packet)

    def carried(self, conn):
        """Bytes of a partial packet waiting for the next chunk of this connection."""
        st = self.conns.get(conn)
        return len(st['buf']) if st else 0

    def push(self, conn, data):
        """Bytes to feed for this chunk (encrypted-body packets dropped)."""
        return b''.join(it[1] for it in self.push_items(conn, data) if it[0] == 'B')

    def push_items(self, conn, data, enc=()):
        """Ordered feed items for this chunk: ('B', bytes) to feed as is, or ('E', pid, packet,
        stream_offset) for a packet in `enc` (encrypted body) the caller must fill in from
        the client's decrypted copy (ActorDecrypt) or drop."""
        st = self.conns.setdefault(conn, {'buf': b'', 'start': True, 'raw': False, 'off': 0})
        if st['raw']:
            return [('B', data)]
        buf, out, pos, items = st['buf'] + data, bytearray(), 0, []
        while pos + 2 <= len(buf):
            L = packet_len(self.L, buf, pos)
            if L == NEED_MORE:
                break
            if L is None:
                if st['start'] and pos == 0:
                    if len(buf) < 4:
                        break
                    out += buf[:4]; pos = 4; st['start'] = False   # bare account ID
                    continue
                pid = buf[pos] | (buf[pos + 1] << 8)
                print(f'[wire] conn {conn}: unknown id 0x{pid:04x} - passing this connection through raw')
                st['raw'] = True
                out += buf[pos:]; pos = len(buf)
                break
            if pos + L > len(buf):
                break
            st['start'] = False
            pid = buf[pos] | (buf[pos + 1] << 8)
            pkt = buf[pos:pos + L]
            if self.on_packet:
                self.on_packet(conn, pid, st['off'] + pos, pkt)
            if pid in enc:
                if out:
                    items.append(('B', bytes(out))); out = bytearray()
                items.append(('E', pid, pkt, st['off'] + pos))
            elif pid not in self.drop:
                out += pkt
            pos += L
        st['off'] += pos
        st['buf'] = buf[pos:]
        if out:
            items.append(('B', bytes(out)))
        return items


def pack_move(x, y, d=0):
    """The 3-byte packed body of a client move (035f) for destination (x, y) and direction d."""
    return bytes(((x >> 2) & 0xff,
                  ((x & 3) << 6) | ((y >> 4) & 0x3f),
                  ((y & 0xf) << 4) | (d & 0xf)))


def unpack_move(body3):
    """Inverse of pack_move: (x, y, d) from the 3-byte packed body of a client move (035f)."""
    b = bytes(body3)
    if len(b) < 3:
        raise ValueError('035f body needs 3 bytes')
    return (b[0] << 2) | (b[1] >> 6), ((b[1] & 0x3f) << 4) | (b[2] >> 4), b[2] & 0xf


def unpack_pos2(b):
    """(src_x, src_y, dst_x, dst_y) from the 6-byte MoveData2 (the RO WBUFPOS2 packing)."""
    sx = (b[0] << 2) | (b[1] >> 6)
    sy = ((b[1] & 0x3f) << 4) | (b[2] >> 4)
    dx = ((b[2] & 0x0f) << 6) | (b[3] >> 2)
    dy = ((b[3] & 0x03) << 8) | b[4]
    return sx, sy, dx, dy


class MoveTracker:
    """Decodes the server's 0087 move confirmation and, when a walk request is known (tests/offline
    replays set it via on_walk), cross-checks it. In live captures the client's own 035f is not
    recovered, so MOVE-CHECKs carry no request and the 0087 destination is the walk destination."""

    def __init__(self, log=None):
        self.log = log
        self.last_walk = None                      # (x, y) of the most recent recovered 035f
        self.stats = collections.Counter()

    def on_walk(self, x, y, d=0):
        self.last_walk = (x, y)

    def on_recv_packet(self, conn, pid, off, pkt):
        """WireFilter.on_packet hook: on a 0087, decode its destination and compare to the walk."""
        if pid != MOVE_ID or len(pkt) < 12:
            return
        sx, sy, dx, dy = unpack_pos2(pkt[6:12])
        req = self.last_walk
        state = 'match' if req == (dx, dy) else ('mismatch' if req else 'no-request')
        self.stats[state] += 1
        rec = {'tag': 'MOVE-CHECK', 'id': '0087', 'src': [sx, sy], 'dst': [dx, dy],
               'req': list(req) if req else None, 'match': req == (dx, dy)}
        if self.log:
            self.log.write(rec)
        self.last_walk = None                      # each 0087 confirms at most one walk
        return rec


def new_chunk(sock, conn, items, cstart, d):
    """One received chunk waiting in the feed queue.
      items   WireFilter.push_items() output: ('B', bytes) | ('E', pid, packet, stream offset)
      enc     True if any item is 'E' (the chunk waits for ActorDecrypt)
      cstart  stream offset of the chunk's first byte; d = its expected ring delta
      t       arrival time (s); closed = agent ts (ms) of the next recv on the socket, or None
      snaps   [(ring bytes, ring base, ts)] RINGSNAPs taken before the next chunk landed
      B       {item index: slot bytes before the decrypt}; Bsafe = B came from inside recvmsg
      ev      {item index: [(ms, slot bytes)]} live reads; tfinal = when evidence was complete
      res     None while undecided, then {item index: decrypted packet or None (drop)}"""
    return {'sock': sock, 'conn': conn, 'items': items, 'cstart': cstart, 'd': d,
            'enc': any(it[0] == 'E' for it in items), 't': time.time(), 'snaps': [], 'closed': None,
            'B': {}, 'tfinal': None, 'ev': collections.defaultdict(list), 'res': None}


class WireFeed:
    POLL = 0.005                                       # re-check interval while a chunk is held
    IDLE_WAIT = 1.0                                    # feeder sleep when nothing is queued
    STATS_EVERY = 30
    DEFAULT_SPAN = 0x4000                              # ring bytes the agent copies unless told more
    SPAN_MARGIN = 0x800                                # context copied past the end of a chunk

    def __init__(self, wire, relay, log, post, dec=None, diag=None, probe=None, actor_delay=0.15,
                 report_stats=None):
        self.wire, self.relay, self.log, self.post = wire, relay, log, post
        self.dec, self.diag, self.probe = dec, diag, probe
        self.delay = actor_delay
        self.report_stats = report_stats               # callback() printing component counters
        self.pending = collections.deque()             # chunks in arrival order awaiting feed
        self.cond = threading.Condition()              # guards pending (and each chunk's snaps/closed)
        self.game_socks = set()                        # sockets the agent should snapshot the ring for
        self.ring_span = {}                            # sock -> ring bytes the agent copies
        self.epoch = 0
        self.revision = 0
        self.generation = 0
        self.on_timing = None

    def reset_session(self, epoch, generation=0):
        with self.cond:
            self.epoch = epoch
            self.revision += 1
            self.generation = generation
            self.pending.clear()
            self.wire.conns.clear()
            self.game_socks.clear()
            self.ring_span.clear()
            self.cond.notify_all()

    # ---- worker thread ----------------------------------------------------------------------
    def on_recv(self, m):
        pre_img, pre_base = m.pop('data', None), m.pop('pre', None)
        C = bytes.fromhex(m['C'])
        if not is_game_sock(m['sock']):                # HTTP config API / Relay backend: log only
            m['tag'] = 'RECV-HTTP' if looks_like_http(C) else 'RECV-RAW'
            self.log.write(m)
            return
        conn = conn_of(m)
        if self.probe:
            self.probe.note_chunk(conn, m['len'], int(m['ptr'], 16), C)
        if self.relay and self.wire:
            pre = (pre_img, int(pre_base, 16)) if pre_img and pre_base else None
            self._queue(m, conn, C, pre)
        m['tag'] = 'RECV-WIRE'
        self.log.write(m)

    def _queue(self, m, conn, C, pre):
        sock, dec = m['sock'], self.dec
        if sock not in self.game_socks:
            self.game_socks.add(sock)
            base = dec.base if dec else None
            if base is not None:                       # snapshot this socket's ring too
                self.post(ring_msg(sock, base))
        if dec:
            items, cstart, d = self._split_for_decrypt(sock, conn, C)
        else:
            items, cstart, d = [('B', self.wire.push(conn, C))], 0, None
        e = new_chunk(sock, conn, items, cstart, d)
        e['epoch'] = self.epoch
        e['revision'] = self.revision
        e['generation'] = self.generation if hasattr(self.relay, 'generation') else None
        e['decoder'] = dec
        e['mono_ns'] = m.get('observed_ns', time.monotonic_ns())
        if e['enc']:
            dec.before(e, pre)
        closed_at = m.get('ts') or time.time() * 1000
        with self.cond:
            for p in self.pending:                     # the next chunk can now overwrite their slots
                if p['sock'] == sock and p['closed'] is None:
                    p['closed'] = closed_at
            self.pending.append(e)
            self.cond.notify()

    def _split_for_decrypt(self, sock, conn, C):
        dec, diag = self.dec, self.diag
        t_in = time.time()
        if diag:
            diag.next_recv[conn] = t_in
        left = self.wire.carried(conn)
        cstart, d = dec.note_chunk(conn, C, left)
        items = self.wire.push_items(conn, C, ActorDecrypt.ENC)
        for it in items:
            if it[0] == 'E':
                dec.note_enc(conn, it[3], len(it[2]))
                if diag:
                    diag.on_packet(conn, sock, it[1], it[2], it[3], cstart, left, t_in)
        base = dec.base
        if base is not None:
            need = d + len(C) + self.SPAN_MARGIN       # chained chunks sit further into the ring
            if need > self.ring_span.get(sock, self.DEFAULT_SPAN):
                self.ring_span[sock] = need
                self.post(ring_msg(sock, base, need))
        elif not left and not is_login_sock(sock):
            dec.start_quick_discover(conn, C, items, cstart)
        return items, cstart, d

    def on_ringsnap(self, m):
        """Taken at the START of a recvmsg: the ring still holds the decrypted copy of every chunk
        of that connection received so far, so attach it to each one still undecided."""
        if self.diag:
            self.diag.snap_t[m['sock']] = time.time()
        data = m.get('data')
        if data is None:
            return
        snap, conn = (data, int(m['base'], 16), m.get('ts', 0)), m.get('conn')
        with self.cond:
            for e in self.pending:
                same = e['conn'] == conn if conn is not None else e['sock'] == m['sock']
                if same and e['enc'] and e['res'] is None and e['closed'] is None:
                    e['snaps'].append(snap)

    def on_ring_found(self, base):
        for sock in list(self.game_socks):
            self.post(ring_msg(sock, base))

    # ---- feeder thread ----------------------------------------------------------------------
    def run(self):
        last_stats = time.time()
        while True:
            with self.cond:
                if not self.pending:
                    self.cond.wait(self.IDLE_WAIT)
                held = [e for e in self.pending if e['enc'] and e['res'] is None]
            for e in held:                             # poll every held chunk's slots, not just the head
                if e.get('epoch', self.epoch) == self.epoch:
                    e['res'] = e.get('decoder', self.dec).settle(e, time.time(), self.delay)
            if self._feed_ready():
                time.sleep(self.POLL)                  # head chunk still waiting for its evidence
            if self.report_stats and time.time() - last_stats > self.STATS_EVERY:
                last_stats = time.time()
                self.report_stats()

    def _feed_ready(self):
        """Feed finished chunks from the head, in order. True if the head is still held."""
        while True:
            with self.cond:
                if not self.pending:
                    return False
                e = self.pending[0]
                if e['enc'] and e['res'] is None:
                    return True
                self.pending.popleft()
            data = b''.join(it[1] if it[0] == 'B' else (e['res'].get(i) or b'')
                            for i, it in enumerate(e['items']))
            if data:
                # Guard under Relay.lock: a popped chunk must not reach a new socket.
                with getattr(self.relay, 'lock', nullcontext()):
                    if e.get('revision', self.revision) != self.revision or e.get('epoch', self.epoch) != self.epoch:
                        continue
                    generation = e.get('generation')
                    ready_ns = time.monotonic_ns()
                    if generation is None:
                        self.relay.feed(data)  # legacy offline fixtures
                    else:
                        self.relay.feed(data, generation=generation)
                if self.on_timing and 'mono_ns' in e:
                    self.on_timing('receive_ready_ms', (ready_ns - e['mono_ns']) / 1e6)
                    self.on_timing('consumer_send_call_ms', (time.monotonic_ns() - ready_ns) / 1e6)


class ClientSendFeed:
    """Client -> server packets in --wire mode: credential-safe, encrypted ones recovered or dropped."""

    def __init__(self, relay, feed_send, sendwatch=None):
        self.relay, self.feed_send, self.sendwatch = relay, feed_send, sendwatch

    def on_send(self, m, emit=True):
        W = m.pop('W', None)
        sock = m['sock']
        if not is_game_sock(sock):
            return
        P = client_packet_to_feed(sock, bytes.fromhex(m['C']))
        if P and self.sendwatch and not is_login_sock(sock):
            P = self.sendwatch.resolve(m, P, W)        # encrypted ids: plaintext or dropped
        if P and self.relay and self.feed_send:
            if emit:
                self.relay.feed_send(P)
            return P
