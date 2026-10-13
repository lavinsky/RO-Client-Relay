"""The default (--wire) pipeline.

Server -> client: each RECV chunk is split into packets (WireFilter), queued in arrival order,
and fed to the relay by one feeder thread. A chunk holding an encrypted 09fd/09ff waits (at most
--actor-delay) until ActorDecrypt has verified the client's decrypted copy; chunks behind it wait
too, so the consumer always gets the exact stream order.

Client -> server: ClientSendFeed redacts login traffic, recovers encrypted sends (SendWatch) and
feeds each as an "S" frame immediately; those need no ordering buffer."""
import collections
import threading
import time

from .actors import ActorDecrypt
from .protocol import conn_of, ring_msg
from .safety import client_packet_to_feed, is_game_sock, is_login_sock, looks_like_http


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
                e['res'] = self.dec.settle(e, time.time(), self.delay)
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
                self.relay.feed(data)


class ClientSendFeed:
    """Client -> server packets in --wire mode: credential-safe, encrypted ones recovered or dropped."""

    def __init__(self, relay, feed_send, sendwatch=None):
        self.relay, self.feed_send, self.sendwatch = relay, feed_send, sendwatch

    def on_send(self, m):
        W = m.pop('W', None)
        sock = m['sock']
        if not is_game_sock(sock):
            return
        P = client_packet_to_feed(sock, bytes.fromhex(m['C']))
        if P and self.sendwatch and not is_login_sock(sock):
            P = self.sendwatch.resolve(m, P, W)        # encrypted ids: plaintext or dropped
        if P and self.relay and self.feed_send:
            self.relay.feed_send(P)
