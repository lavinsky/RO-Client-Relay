"""ActorDecrypt: fills in the encrypted bodies of 09fd/09ff from the client's own decrypted copy."""
import collections
import os
import threading
import time

from . import ROOT
from .memory import MAX_REGION, ProcessMemory, region_at, regions


def valid_actor(P):
    """Does P parse as a plausible 09fd/09ff actor packet? (object_type <= 12, sane walk_speed,
    printable NUL-padded name.) Garbage (still encrypted) bodies fail this."""
    if len(P) < 60 or P[4] > 12:
        return False
    speed = P[13] | (P[14] << 8)
    name = P[len(P) - 24:] if len(P) >= 90 else b''
    nm = name.split(b'\0', 1)
    ok_name = all(32 <= c < 127 or c >= 0x80 for c in nm[0]) and (len(nm) == 1 or not nm[1].strip(b'\0'))
    return 20 <= speed <= 1000 and ok_name


class ActorDecrypt:
    """Fills in the encrypted bodies of 09fd/09ff from the client's own decrypted copy.

    Only those bodies are encrypted on the wire. The client decrypts each received chunk into its
    recv ring (an rw heap block; found at 0x24dd0000) - the copy is NOT in the recvmsg buffer.
    Ring layout (measured with --actor-diag): a chunk that starts on a packet boundary lands at
    ring+0x40; a chunk that continues a partial packet is appended right after the previous chunk
    (d = previous d + previous length). The copy appears ~5-20 ms after recvmsg returns and stays
    until the client processes the next chunk on that socket.

    Evidence per encrypted packet: live reads of its expected slot (while no later recv on the
    socket has happened) and the agent's RINGSNAPs (taken at every recvmsg entry, i.e. before the
    next chunk can land). Accepted when:
      fresh - the slot changed after the chunk arrived (vs. the 'before' read B) to a copy with the
              same cleartext id+len whose body parses as a valid actor; or
      score - the older context check: the cleartext wire bytes around the candidate match the
              ring (+bonus at the expected slot, +bonus if neighbouring packets name its ID), with
              a margin over the runner-up (stale copies of older packets share the header).
    Unverifiable -> DROPPED, never guessed. Read-only via /proc/<pid>/mem.

    Threads: the worker calls note_chunk/note_enc/before/start_quick_discover, the wire feeder
    calls settle/resolve, a short-lived thread runs quick_discover. `lock` guards the ring
    location, stats and `fed`; code outside it reads `self.base` once into a local, because
    the ring can be dropped (set to None) for rediscovery at any moment. Code that needs both
    ends reads `self.region` instead: (base, hi) replaced in one assignment, never torn."""
    ENC = (0x09fd, 0x09ff)
    CTX = 64                                           # wire bytes compared on each side of a candidate
    HDR = 0x40                                         # ring offset of a chunk that starts clean
    STREAM_KEEP = 0x20000                              # recent wire bytes kept per connection
    LIVE_READ = 0x20000                                # ring bytes read for a live search
    DISCOVER_WAIT = 0.03                               # no ring yet: let the copy land before a full scan
    SCAN_BACKOFF = 1.0                                 # after a failed full scan, wait before the next
    REDISCOVER_AFTER = 20                              # consecutive unverified -> forget the ring

    def __init__(self, pid):
        self.pid = pid
        self.mem = ProcessMemory(pid)
        self.base = self.hi = None                     # ring region [base, hi)
        self.region = None                             # (base, hi) as one value, or None
        self.chain = {}                                # conn -> (ring delta, length) of last chunk
        self.stream = {}                               # conn -> [stream offset of bytes[0], bytes]; replaced, never mutated
        self.spans = collections.defaultdict(lambda: collections.deque(maxlen=256))  # conn -> enc (start, end)
        self.coff = collections.Counter()              # conn -> stream offset of next chunk
        self.stats = collections.Counter()
        self.on_ring = None                            # callback(base) when the ring is found
        self.lock = threading.Lock()
        self.fed = {}                                  # decrypted packet -> time last fed
        self.fails = 0                                 # consecutive unverified -> rediscover the ring
        self.quick_busy = False
        self.next_scan = 0.0                           # earliest time for another full scan
        self.cache = os.path.join(ROOT, '.relay_actor_ring')
        self._load_cache()

    def _load_cache(self):
        # safe to trust: every copy is verified, and a wrong base just fails -> rediscovery
        try:
            with open(self.cache) as f:
                r = region_at(self.pid, int(f.read().strip(), 16))
        except (OSError, ValueError):
            return
        if r:
            self.base, self.hi = r
            self.region = r
            print(f'[actor] recv ring 0x{r[0]:x}-0x{r[1]:x} (cached; verified per packet)')

    def read(self, a, n):
        return self.mem.read(a, n)

    # ---- bookkeeping (worker thread) --------------------------------------------------------
    def note_chunk(self, conn, C, left=0):
        """Record a chunk's wire bytes (`left` = bytes of a partial packet carried over from the
        previous chunk); returns (stream offset, expected ring delta)."""
        start = self.coff[conn]
        self.coff[conn] += len(C)
        sb0, sb = self.stream.get(conn, (start, b''))
        sb += C
        if len(sb) > self.STREAM_KEEP:
            cut = len(sb) - self.STREAM_KEEP
            sb0, sb = sb0 + cut, sb[cut:]
        self.stream[conn] = [sb0, sb]                  # one assignment: readers never see a half update
        pd, pl = self.chain.get(conn, (self.HDR, 0))
        d = pd + pl if left else self.HDR
        self.chain[conn] = (d, len(C))
        return start, d

    def note_enc(self, conn, off, L):
        self.spans[conn].append((off + 4, off + L))   # body only; id+len are cleartext

    def copy_ok(self, pkt, P):
        return len(P) == len(pkt) and P[:4] == pkt[:4] and P != pkt and valid_actor(P)

    def slot(self, d, off, cstart, base=None):
        """Ring address where this packet's decrypted copy should be."""
        return (self.base if base is None else base) + d + off - cstart

    def before(self, e, pre=None):
        """Content of each encrypted packet's slot BEFORE the client could decrypt the chunk:
        from the agent's copy taken inside recvmsg (`pre` = (bytes, base)); without it, a live
        read now (usually still before the decrypt, but not guaranteed -> no 'Bsafe')."""
        base = self.base
        if base is None:
            return
        for i, it in enumerate(e['items']):
            if it[0] != 'E':
                continue
            a = self.slot(e['d'], it[3], e['cstart'], base)
            if pre is not None and pre[1] == base and 0 <= a - base and a - base + len(it[2]) <= len(pre[0]):
                e['B'][i] = pre[0][a - base:a - base + len(it[2])]
                e['Bsafe'] = True
            else:
                e['B'][i] = self.read(a, len(it[2]))

    # ---- finding the ring -------------------------------------------------------------------
    def start_quick_discover(self, conn, C, items, cstart):
        """Kick a background quick_discover for a clean-start chunk, if none is running."""
        if self.base is not None or self.quick_busy:
            return
        self.quick_busy = True
        rel = [(it[3] - cstart + 4, it[3] - cstart + len(it[2])) for it in items if it[0] == 'E']
        threading.Thread(target=self.quick_discover, args=(conn, C, rel), name='actor-quick', daemon=True).start()

    def quick_discover(self, conn, C, enc_rel):
        """Cheap ring search: the region whose bytes at +0x40 equal this whole chunk (encrypted
        bodies masked). Run ~20 ms after a clean-start chunk arrives, while its copy is there."""
        try:
            mask = bytearray(len(C))
            for a, b in enc_rel:
                a, b = max(0, a), max(0, b)
                mask[a:b] = b'\1' * (b - a)
            if len(C) - sum(mask) < 64:
                return False
            time.sleep(0.02)
            for lo, hi, _ in regions(self.pid):
                if self.base is not None:
                    return False
                if hi - lo < self.HDR + len(C):
                    continue
                R = self.read(lo + self.HDR, len(C))
                if len(R) == len(C) and all(m or r == c for r, c, m in zip(R, C, mask)):
                    with self.lock:
                        if self.base is None:
                            self._set_ring(lo, hi, f'quick: chunk of {len(C)} bytes at +0x40')
                    return True
        finally:
            self.quick_busy = False
        return False

    def _set_ring(self, lo, hi, why):                  # caller holds self.lock
        self.base, self.hi = lo, hi
        self.region = (lo, hi)
        self.fails = 0
        try:
            with open(self.cache, 'w') as f:
                f.write(f'{lo:x}')
        except OSError:
            pass
        print(f'[actor] decrypted recv ring: 0x{lo:x}-0x{hi:x} ({why})')
        if self.on_ring:
            self.on_ring(lo)

    def discover(self, conn, pkt, off, cstart):
        """Full rw scan for the ring: the region holding a strongly context-matched copy.
        Caller holds self.lock."""
        best = None
        for lo, hi, _ in regions(self.pid, max_size=MAX_REGION):
            c = self._best(self.read(lo, hi - lo), lo, conn, pkt, off, cstart)
            if c and c[0][1] + c[0][2] >= 24 and (best is None or c[0][0] > best[0][0]):
                best = (c[0], lo, hi)
        if best:
            self._set_ring(best[1], best[2], f'copy @0x{best[0][3]:x}, ctx pre{best[0][1]}/post{best[0][2]}')
        return best is not None

    def _scan_for_ring(self, conn, pkt, off, cstart):
        """Full discovery, at most once per SCAN_BACKOFF while it keeps failing: a scan reads
        every rw region and would otherwise stall the feed for each held chunk. Caller holds lock."""
        if time.time() < self.next_scan:
            return False
        if self.discover(conn, pkt, off, cstart):
            return True
        self.next_scan = time.time() + self.SCAN_BACKOFF
        return False

    # ---- scoring candidates -----------------------------------------------------------------
    def _ctx(self, buf, i, conn, off, L):
        """Cleartext wire bytes matching around candidate buf[i:i+L] (pre, post)."""
        sb0, sb = self.stream.get(conn, (0, b''))
        lo, hi = off - self.CTX, off + L + self.CTX
        spans = [(a, b) for a, b in list(self.spans[conn]) if a < hi and b > lo]   # only nearby ones

        def enc(pos):
            return any(a <= pos < b for a, b in spans)
        pre = 0
        for j in range(1, self.CTX + 1):
            sp = off - j
            if sp < sb0 or i - j < 0:
                break
            if enc(sp):
                continue
            if buf[i - j] != sb[sp - sb0]:
                break
            pre += 1
        post = 0
        for j in range(self.CTX):
            sp = off + L + j
            if sp - sb0 >= len(sb) or i + L + j >= len(buf):
                break
            if enc(sp):
                continue
            if buf[i + L + j] != sb[sp - sb0]:
                break
            post += 1
        return pre, post

    def _best(self, buf, bufbase, conn, pkt, off, cstart, exp_d=None):
        """Candidates for pkt's decrypted copy in buf, best first: (score, pre, post, addr, d, P)."""
        L, cands = len(pkt), []
        sb0, sb = self.stream.get(conn, (0, b''))
        near = sb[max(0, off - sb0 - self.CTX):max(0, off - sb0)] + sb[off - sb0 + L:off - sb0 + L + self.CTX]
        if exp_d is None:
            exp_d = self.HDR
        ring = self.base or bufbase
        hdr = pkt[:4]
        i = buf.find(hdr)
        while i != -1:
            P = buf[i:i + L]
            if len(P) == L and P != pkt and valid_actor(P):
                pre, post = self._ctx(buf, i, conn, off, L)
                sc = pre + post
                if P[5:9] in near:
                    sc += 8                            # neighbouring cleartext packets name this actor
                d = (bufbase + i - ring) - (off - cstart)
                if d == exp_d:
                    sc += 16                           # at the slot the ring layout predicts
                cands.append((sc, pre, post, bufbase + i, d, P))
            i = buf.find(hdr, i + 1)
        cands.sort(key=lambda c: c[0], reverse=True)
        return cands

    def _accept(self, P, src, strong):
        """Book-keeping for an accepted copy; None if it's a suspicious repeat. Caller holds lock."""
        now = time.time()
        if not strong and now - self.fed.get(P, -99) < 10:
            # byte-identical to a copy we fed moments ago: the server re-sent it, or a stale copy
            # won - only trust it with strong evidence
            self.stats['dup-rejected'] += 1
            return None
        self.fed[P] = now
        if len(self.fed) > 4096:
            self.fed = {k: t for k, t in self.fed.items() if now - t < 10}
        self.stats['ok-' + src] += 1
        self.fails = 0
        return P

    def resolve(self, conn, pid, pkt, off, cstart, snap=None, exp_d=None, live=True, snaps=None, stale=None):
        """Context-scored pick (the 'score' rule). Decrypted packet bytes, or None (drop).
        Buffers tried: snapshots newest first, then a live read if `live`."""
        with self.lock:
            if self.base is None and not self._scan_for_ring(conn, pkt, off, cstart):
                self.stats['no-ring'] += 1
                return None
            bufs = [(s[0], s[1], 'snap') for s in reversed(snaps or [])]
            if snap is not None:
                bufs.append((snap[0], snap[1], 'snap'))
            if live:
                bufs.append((None, self.base, 'live'))
            c, src = [], None
            for buf, bufbase, src in bufs:
                if buf is None:
                    buf = self.read(self.base, min(self.hi - self.base, self.LIVE_READ))
                c = [x for x in self._best(buf, bufbase, conn, pkt, off, cstart, exp_d) if x[5] != stale]
                if c and c[0][0] >= 16:
                    break
            second = c[1][0] if len(c) > 1 else 0
            if c and c[0][0] >= 16 and c[0][0] - second >= 8:
                sc, pre, post, a, d, P = c[0]
                return self._accept(P, src, pre + post >= 24)
            self.stats['unverified'] += 1
            self.fails += 1
            if self.fails >= self.REDISCOVER_AFTER:
                print(f'[actor] {self.REDISCOVER_AFTER} unverified in a row - rediscovering the recv ring')
                self.base = self.region = None
                self.fails = 0
                self.next_scan = 0.0
            if c:
                print(f'[actor] 0x{pid:04x} unverified: best {c[0][:3]} second {second} ({len(c)} cands)')
            return None

    # ---- deciding one held chunk (wire feeder thread) ---------------------------------------
    def settle(self, e, now, delay, settle_wait=0.03):
        """Advance one held chunk. Returns None to keep waiting, else {item index: packet or None}.

        While no later recv on the socket has happened (e['closed'] is None) we poll each slot.
        A live read at time T is only trusted once we know the next chunk had not been received by
        T (its agent timestamp > T, or none arrived settle_wait after T) - so it cannot be the next
        chunk's copy. Snapshots attached to the entry all predate the next chunk."""
        E = [i for i, it in enumerate(e['items']) if it[0] == 'E']
        base = self.base
        if base is None:                               # no ring yet: full discovery (score rule)
            if now - e['t'] < min(delay, self.DISCOVER_WAIT):
                return None
            return {i: self.resolve(e['conn'], e['items'][i][1], e['items'][i][2], e['items'][i][3],
                                    e['cstart'], snaps=e['snaps'], exp_d=e['d']) for i in E}
        closed = e['closed']                           # read once: the worker may set it any time
        if closed is None:
            fresh = True
            for i in E:
                _, pid, pkt, off = e['items'][i]
                P = self.read(self.slot(e['d'], off, e['cstart'], base), len(pkt))
                e['ev'][i].append((now * 1000, P))
                fresh &= self.copy_ok(pkt, P) and P != e['B'].get(i)
            if e['tfinal'] is None and (fresh or now - e['t'] >= delay):
                e['tfinal'] = now                      # evidence complete as of this read
            if e['tfinal'] is None or now - e['tfinal'] < settle_wait:
                return None
            cut = e['tfinal'] * 1000 + 1
        else:
            cut = closed - 1                           # reads after the next chunk arrived: unsafe
        out = {}
        for i in E:
            _, pid, pkt, off = e['items'][i]
            ev = [(T, P) for T, P in e['ev'][i] if T < cut]
            rel = e['d'] + off - e['cstart']
            for data, _sbase, ts in list(e['snaps']):
                if 0 <= rel and rel + len(pkt) <= len(data):
                    ev.append((ts, data[rel:rel + len(pkt)]))
            ev.sort(key=lambda x: x[0])
            V = next((P for T, P in reversed(ev) if self.copy_ok(pkt, P)), None)
            B = e['B'].get(i)
            if V is not None and i in e['B'] and V != B:
                with self.lock:
                    out[i] = self._accept(V, 'fresh', True)
                continue
            # the slot never changed: with a pre-decrypt image that's proof the copy there is stale
            out[i] = self.resolve(e['conn'], pid, pkt, off, e['cstart'], exp_d=e['d'],
                                  live=closed is None, snaps=e['snaps'],
                                  stale=B if e.get('Bsafe') else None)
        return out
