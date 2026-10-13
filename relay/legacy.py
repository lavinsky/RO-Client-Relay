"""LEGACY --no-wire path: read "decrypted" copies of every chunk from client memory.

Superseded by the wire path (wire_feed.py): RingMatcher's cached ring went stale and produced
garbage. Kept, isolated here, for comparison runs. Nothing in the default path imports it."""
import collections
import os
import threading
import time

from . import ROOT
from .memory import MAX_REGION, ProcessMemory, regions
from .protocol import ring_msg
from .safety import client_packet_to_feed, is_game_sock, looks_like_http


class RingMatcher:
    """Finds where Relay put the decrypted copy of each received chunk.

    Relay recvs into a stack buffer and decrypts into the client's receive
    ring (a heap block, chunks back to back). We read the game's memory from
    outside via /proc/<pid>/mem (needs ptrace_scope 0 or root), which never
    pauses it: the copy starts with the same header, cleartext packets in it
    are byte-identical, and it is normally right after the previous chunk."""
    WIN = 0x10000

    def __init__(self, pid):
        self.pid = pid
        self.mem = ProcessMemory(pid)
        self.rings = {}                       # sock -> [base, end, next]
        self.on_ring = None                   # callback(sock, base) when a ring is found
        self.recent = collections.defaultdict(lambda: collections.deque(maxlen=32))
        self.misses = collections.Counter()
        self.busy = set()
        self.tried_cache = set()
        self.cache = os.path.join(ROOT, '.relay_ring')
        self.relay_sock = None                # first ring sock = the Relay game stream we relay
        self.active_ring_base = None          # most recent ring base (the client reuses one recv
                                              # heap buffer across sequential login->char->map conns)
        self.unconfirmed = set()              # socks given a reused ring not yet verified by a hit

    def read(self, addr, n):
        return self.mem.read(addr, n)

    def anon_regions(self):
        for lo, hi, _ in regions(self.pid, max_size=MAX_REGION, paths=('', '[heap]')):
            yield lo, hi

    def eager_reuse(self, sock):
        """Assign a new game socket the most recently discovered ring immediately, so its FIRST
        recv (e.g. the char server's received_characters, which fills the consumer's @chars) can be
        decrypted via RINGSNAP instead of lost to discovery lag. If wrong, RINGSNAP simply won't
        match and _discover corrects it (sock stays `unconfirmed` until a real hit)."""
        if sock in self.rings or self.active_ring_base is None:
            return False
        for lo, hi in self.anon_regions():
            if lo == self.active_ring_base:
                self.unconfirmed.add(sock)
                self.set_ring(sock, lo, hi, 'reused from sibling connection (unverified)')
                return True
        return False

    def set_ring(self, sock, lo, hi, why):
        self.rings[sock] = [lo, hi, None]
        self.misses[sock] = 0
        self.active_ring_base = lo
        if self.relay_sock is None:
            self.relay_sock = sock
            print(f'[relay] relaying decrypted stream of {sock}')
        print(f'[+] client recv ring for {sock}: 0x{lo:x}-0x{hi:x} ({why})')
        try:
            with open(self.cache, 'w') as f:
                f.write(f'{lo:x}')
        except OSError:
            pass
        if self.on_ring:
            self.on_ring(sock, lo)

    def try_cached(self, sock):
        if sock in self.tried_cache:              # once per socket; a bad cache must not loop
            return False
        self.tried_cache.add(sock)
        try:
            with open(self.cache) as f:
                base = int(f.read().strip(), 16)
        except (OSError, ValueError):
            return False
        for lo, hi in self.anon_regions():
            if lo == base:
                self.set_ring(sock, lo, hi, 'cached address from last run')
                return True
        return False

    def miss(self, sock):
        self.misses[sock] += 1
        if self.misses[sock] >= 15 and sock in self.rings:
            print(f'[!] ring for {sock} stopped matching, rediscovering')
            del self.rings[sock]

    def discover(self, sock, C, ptr):
        """Remember chunk; kick a background pass that matches recent chunks against one memory read."""
        if len(C) >= 64:
            self.recent[sock].append((C, ptr))
        if sock in self.busy or not self.recent[sock]:
            return
        self.busy.add(sock)
        threading.Thread(target=self._discover, args=(sock,), daemon=True).start()

    def _discover(self, sock):
        try:
            best = None
            for lo, hi in self.anon_regions():
                blk = self.read(lo, hi - lo)
                for C, ptr in list(self.recent[sock]):
                    i = blk.find(C[:4])
                    while i != -1:
                        a = lo + i
                        if not ptr - 0x2000 <= a < ptr + 0x2000 + len(C):
                            sc = self.score(blk[i:i + len(C)], C)
                            if sc >= 0.6 * len(C) and (best is None or sc / len(C) > best[2]):
                                best = (lo, hi, sc / len(C), a)
                        i = blk.find(C[:4], i + 1)
            if best and (sock not in self.rings or sock in self.unconfirmed):
                if not (sock in self.rings and self.rings[sock][0] == best[0]):
                    self.set_ring(sock, best[0], best[1], f'anchor 0x{best[3]:x}, {best[2]:.0%} bytes equal')
                self.unconfirmed.discard(sock)                     # scan result is authoritative
        finally:
            self.busy.discard(sock)

    @staticmethod
    def score(P, C):
        return sum(a == b for a, b in zip(P, C)) if len(P) == len(C) else -1

    def best_in(self, lo, hi, C, skip):
        hdr, best, pos = C[:2], None, lo
        while pos < hi:
            blk = self.read(pos, min(0x1000000, hi - pos) + len(C))
            i = blk.find(hdr)
            while i != -1 and i < 0x1000000:
                a = pos + i
                if not skip[0] <= a < skip[1]:
                    sc = self.score(blk[i:i + len(C)], C)
                    if best is None or sc > best[1]:
                        best = (a, sc, blk[i:i + len(C)])
                i = blk.find(hdr, i + 1)
            pos += 0x1000000
        return best

    @staticmethod
    def anchored_in_snap(snap, base, C):
        # the client decrypts each chunk to the SAME ring offset (+0x40). The id and length are
        # cleartext, so a 2-byte id match at +0x40 confirms it is this chunk's copy.
        P = snap[0x40:0x40 + len(C)]
        if len(P) == len(C) and P[:2] == C[:2]:
            return (base + 0x40, RingMatcher.score(P, C), P)
        return None

    @staticmethod
    def best_in_snap(snap, base, C):
        # 2-byte id only: fixed-size packets like 0x007f are encrypted from offset 2
        hdr, best, i = C[:2], None, snap.find(C[:2])
        key = None
        while i != -1:
            P = snap[i:i + len(C)]
            sc = RingMatcher.score(P, C)
            k = (sc, -abs(i - 0x40))          # ties (short packets): the client recvs at ring+0x40
            if key is None or k > key:
                key, best = k, (base + i, sc, P)
            i = snap.find(hdr, i + 1)
        return best

    def match(self, sock, C, ptr):
        """Live-read fallback once the ring is known (snapshots are preferred)."""
        r = self.rings.get(sock)
        if r is None:
            return None
        skip = (ptr - 0x2000, ptr + 0x2000 + len(C))
        hit = None
        if r[2] is not None:
            P = self.read(r[2], len(C))
            if P[:2] == C[:2]:
                hit = (r[2], self.score(P, C), P)
        if hit is None:
            lo = max(r[0], r[2] - self.WIN) if r[2] else r[0]
            hi = min(r[1], r[2] + self.WIN) if r[2] else min(r[1], r[0] + 2 * self.WIN)
            hit = self.best_in(lo, hi, C, skip)
        if hit:
            r[2] = hit[0] + len(C)
        return hit

    def lookup(self, sock, C, ptr, snap, base):
        """Best decrypted copy of chunk C: at ring+0x40 in the snapshot, else anywhere in it,
        else a live read. (addr, score, bytes) or None."""
        hit = self.anchored_in_snap(snap, base, C)
        if not hit or hit[1] < len(C):           # not a clean copy there -> search the window
            alt = self.best_in_snap(snap, base, C)
            if alt and (not hit or alt[1] > hit[1]):
                hit = alt
        if not hit or hit[1] < 4:
            hit = self.match(sock, C, ptr)
        if hit:
            self.misses[sock] = 0
            self.unconfirmed.discard(sock)       # reused ring verified by a real hit
        else:
            self.miss(sock)
        return hit


class SendFinder:
    """Finds the client's PLAINTEXT copy of outgoing packets, before they are encrypted.

    The client assembles each outgoing packet in its own buffer first. If that buffer is separate
    from the socket buffer, the plaintext persists there: same cleartext id (and length) prefix
    as the ciphertext, different body. We search for that, cache the buffer address per socket,
    and read from it on later sends. Scans run on a background thread. (In practice Relay
    encrypts in place, so this rarely finds anything; SendWatch replaced it.)"""

    def __init__(self, pid):
        self.pid = pid
        self.mem = ProcessMemory(pid)
        self.base = {}                                 # sock -> plaintext send buffer address
        self.busy = set()
        self.recent = collections.defaultdict(lambda: collections.deque(maxlen=16))

    def read(self, addr, n):
        return self.mem.read(addr, n)

    def anon_regions(self):
        for lo, hi, _ in regions(self.pid, max_size=MAX_REGION, paths=('', '[heap]', '[stack]')):
            yield lo, hi

    @staticmethod
    def _prefix(a, b):
        n = 0
        while n < len(a) and n < len(b) and a[n] == b[n]:
            n += 1
        return n

    def resolve(self, sock, C):
        """Read the plaintext for this send from the cached buffer; None if unknown/stale."""
        b = self.base.get(sock)
        if b is None:
            return None
        P = self.read(b, len(C))
        if len(P) == len(C) and P[:2] == C[:2] and P != C:
            return (b, P)
        return None

    def discover(self, sock, C):
        """Remember a send and kick a one-shot background scan for its plaintext buffer."""
        if len(C) >= 10:
            self.recent[sock].append(C)
        if sock in self.busy or not self.recent[sock]:
            return
        self.busy.add(sock)
        threading.Thread(target=self._discover, args=(sock,), daemon=True).start()

    def _discover(self, sock):
        try:
            best = None                                # (prefix_len, addr, plaintext, cipher)
            for lo, hi in self.anon_regions():
                blk = self.read(lo, hi - lo)
                for C in list(self.recent[sock]):
                    i = blk.find(C[:2])
                    while i != -1:
                        cand = blk[i:i + len(C)]
                        if len(cand) == len(C) and cand != C and sum(cand) > 0:
                            p = self._prefix(cand, C)          # shared cleartext header
                            if p >= 2 and (best is None or p > best[0]):
                                best = (p, lo + i, cand, C)
                        i = blk.find(C[:2], i + 1)
            if best and sock not in self.base:
                self.base[sock] = best[1]
                print(f'[+] plaintext send buffer for {sock}: 0x{best[1]:x} '
                      f'(cleartext header {best[0]}B; plaintext differs from ciphertext)')
        finally:
            self.busy.discard(sock)


class LegacyPipeline:
    """--no-wire: every game RECV is held until a RINGSNAP arrives, its decrypted copy is looked
    up (RingMatcher), and the result is parked at the chunk's arrival index; the reorder buffer
    feeds strictly in arrival order. A watchdog flushes a slot stuck > STUCK_AFTER as ciphertext
    (id/length are cleartext, so the consumer still tokenizes past it)."""
    WATCHDOG_EVERY = 0.2
    STUCK_AFTER = 0.5

    def __init__(self, pid, relay, log, post, feed_send=False, find_send=False):
        self.relay, self.log, self.feed_send = relay, log, feed_send
        self.matcher = RingMatcher(pid)
        self.matcher.on_ring = lambda sock, base: post(ring_msg(sock, base))
        self.sendfinder = SendFinder(pid) if find_send else None
        self.waiting = {}                              # sock -> [RECV msgs waiting for a RINGSNAP]
        # Reorder buffer, keyed by arrival index (ridx). Guarded by self.lock (worker + watchdog).
        self.lock = threading.Lock()
        self.reorder = {}                              # ridx -> bytes to feed (None = skip, e.g. HTTP)
        self.raw = {}                                  # ridx -> ciphertext, if its slot gets stuck
        self.next_feed = 0                             # next ridx to feed
        self.next_ridx = 0                             # next ridx to assign (worker only)
        self.last_advance = time.time()

    # ---- worker thread ----------------------------------------------------------------------
    def on_recv(self, m):
        m.pop('data', None)
        m.pop('pre', None)
        sock = m['sock']
        if not is_game_sock(sock):
            self.finish(m, None)
            return
        m['ridx'] = self.next_ridx                     # reserve the chunk's slot in feed order now
        self.next_ridx += 1
        C, ptr = bytes.fromhex(m['C']), int(m['ptr'], 16)
        if sock not in self.matcher.rings:
            # Get this socket a ring NOW (cached base, or a sibling's) so even its FIRST recv is
            # held for RINGSNAP. Critical for the char server: its first packet is
            # received_characters (fills the consumer @chars).
            got = self.matcher.try_cached(sock) or self.matcher.eager_reuse(sock)
            self.matcher.discover(sock, C, ptr)        # find, or verify/correct the guess
            if not got:
                self.finish(m, None)
                return
        with self.lock:
            self.raw[m['ridx']] = C
        self.waiting.setdefault(sock, []).append(m)

    def on_ringsnap(self, m):
        snap = m.get('data')
        if snap is None:
            return
        base = int(m['base'], 16)
        for r in self.waiting.pop(m['sock'], []):
            hit = self.matcher.lookup(r['sock'], bytes.fromhex(r['C']), int(r['ptr'], 16), snap, base)
            self.finish(r, hit)

    def on_send(self, m):
        sock = m['sock']
        if not (self.sendfinder and is_game_sock(sock)):
            return
        C = bytes.fromhex(m['C'])
        hit = self.sendfinder.resolve(sock, C)         # read plaintext from cached buffer
        if not hit:
            self.sendfinder.discover(sock, C)          # background: locate the buffer
            return
        m.update(tag='SEND-PLAIN', P=hit[1].hex(), src=hex(hit[0]))
        P = client_packet_to_feed(sock, hit[1])
        if self.relay and self.feed_send and P:
            self.relay.feed_send(P)

    def finish(self, m, hit):
        C = bytes.fromhex(m['C'])
        if hit is None:
            m['tag'] = 'RECV-LOST' if is_game_sock(m['sock']) else 'RECV-RAW'
        elif hit[2] != C:
            m.update(tag='RECV-PLAIN', P=hit[2].hex(), dest=hex(hit[0]))
            # short packets encrypted right after the id (e.g. 0x007f) only anchor on
            # 2 bytes, so a stale copy can win: flag instead of trusting it
            if hit[1] <= 2 or (hit[1] < 0.5 * len(C) and len(C) < 32):
                m['uncertain'] = True
        else:
            m['tag'] = 'RECV-RAW'
        feed_bytes = hit[2] if (hit is not None and hit[2] != C) else C
        is_http = looks_like_http(feed_bytes)          # uaRO HTTP/token exchange: not RO packets
        if is_http:
            m['tag'] = 'RECV-HTTP'
        if self.relay and 'ridx' in m:
            with self.lock:
                self.raw.pop(m['ridx'], None)
                if m['ridx'] >= self.next_feed:        # not already flushed by the watchdog
                    self.reorder[m['ridx']] = None if is_http else feed_bytes
                    self._drain()
        self.log.write(m)

    def _drain(self):                                  # caller holds self.lock
        while self.next_feed in self.reorder:
            b = self.reorder.pop(self.next_feed)
            self.next_feed += 1
            self.last_advance = time.time()
            if b:
                self.relay.feed(b)

    # ---- watchdog thread --------------------------------------------------------------------
    def run_watchdog(self):
        """A held chunk whose RINGSNAP never arrives (its socket closed at a login->char->map
        switch) would block the ordered feed. Flush it as ciphertext once later chunks wait."""
        while True:
            time.sleep(self.WATCHDOG_EVERY)
            with self.lock:
                nxt = self.next_feed
                if (nxt not in self.reorder and nxt in self.raw and any(k > nxt for k in self.reorder)
                        and time.time() - self.last_advance > self.STUCK_AFTER):
                    self.relay.feed(self.raw.pop(nxt))
                    self.next_feed = nxt + 1
                    self.last_advance = time.time()
                    self._drain()
