"""ActorDecrypt: fills in the encrypted bodies of 09fd/09ff from the client's own decrypted copy."""
import collections
import threading
import time
import unicodedata

from .memory import MAX_REGION, ProcessMemory, regions



# Explicit legacy Windows encoding: do not try multiple codecs until one passes.
# Change only after confirming the character encoding used by this server.
ACTOR_NAME_ENCODING = 'cp1252'
# The client can receive NPC names containing printable ASCII symbols such as
# 'Kafra Employee#prt1'. Extended CP1252 remains limited to letters/digits and
# a few typography marks; controls, undefined codepoints and binary garbage fail.
ACTOR_NAME_PUNCTUATION = frozenset(' ‘’“”–—…')


def allowed_actor_name_character(c):
    return (unicodedata.category(c)[0] in ('L', 'N') or
            (c.isascii() and c.isprintable()) or
            c in ACTOR_NAME_PUNCTUATION)


def valid_actor_name(raw):
    """Validate a fixed-width (24-byte) NUL-padded name, never a cipher proof."""
    if len(raw) != 24:
        return False
    name_bytes, sep, padding = raw.partition(b'\x00')
    if not name_bytes or (sep and any(padding)):
        return False
    try:
        name = name_bytes.decode(ACTOR_NAME_ENCODING, errors='strict')
    except UnicodeDecodeError:
        return False
    if name != name.strip():
        return False
    return all(allowed_actor_name_character(c) for c in name)


def actor_name_rejection(raw):
    """Diagnostic category only: never expose the actor's raw name or bytes."""
    if len(raw) != 24:
        return 'invalid-length'
    if not any(raw):
        return 'empty'
    name_bytes, sep, padding = raw.partition(b'\x00')
    if sep and any(padding):
        return 'invalid-padding'
    try:
        name = name_bytes.decode(ACTOR_NAME_ENCODING, errors='strict')
    except UnicodeDecodeError:
        return 'invalid-encoding'
    if name != name.strip():
        return 'edge-whitespace'
    if not all(allowed_actor_name_character(c) for c in name):
        return 'forbidden-character'
    return 'ok'


def fresh_empty_name_actor(pkt, plain):
    """Structural exception for a *freshly observed* 09FF slot, not a generic copy_ok.

    The caller must separately establish same-ring safe preimage, a changed
    post-recv copy in the expected slot, and that the read predates the next recv.
    This function is deliberately never used by ring discovery or scoring.
    """
    return (len(pkt) >= 90 and len(plain) == len(pkt) and
            pkt[:2] == b'\xff\x09' and plain[:4] == pkt[:4] and
            plain != pkt and plain[4] <= 12 and
            0 <= (plain[13] | (plain[14] << 8)) <= 2000 and
            plain[5:9] != b'\x00' * 4 and
            plain[-24:] == b'\x00' * 24)


def valid_actor(P):
    """Does P parse as a plausible 09fd/09ff actor packet? (object_type <= 12, sane walk_speed,
    printable NUL-padded name.) Garbage (still encrypted) bodies fail this."""
    if len(P) < 60 or P[4] > 12:
        return False
    speed = P[13] | (P[14] << 8)
    name = P[-24:] if len(P) >= 90 else b''
    return 0 <= speed <= 2000 and valid_actor_name(name)


def copy_validation(pkt, P):
    """Boolean-only breakdown of the existing copy_ok rules; no packet content logged.

    For 0229, speed/type/name do not apply. `accepted` must exactly mirror
    ActorDecrypt.copy_ok, including its special six-byte fixed-packet check.
    """
    n = len(pkt)
    same_length = len(P) == n
    changed = P != pkt
    pid = int.from_bytes(pkt[:2], 'little') if n >= 2 else None
    hdrlen = 2 if pid in (0x0229, 0x043f, 0x0983) else 4
    header = n >= 2 and same_length and P[:hdrlen] == pkt[:hdrlen]
    result = {'length_match': same_length, 'header_match': header,
              'body_changed': changed, 'object_type_ok': None,
              'walk_speed_ok': None, 'name_format_ok': None,
              'fixed_gid_ok': None}
    if pid == 0x0983:
        result['fixed_gid_ok'] = (same_length and n == 29 and header and
                                  int.from_bytes(P[4:8], 'little') != 0)
        result['accepted'] = bool(header and changed and result['fixed_gid_ok'])
        return result
    if pid == 0x043f:
        result['fixed_gid_ok'] = (same_length and n == 25 and header and
                                  int.from_bytes(P[4:8], 'little') != 0)
        result['accepted'] = bool(header and changed and result['fixed_gid_ok'])
        return result
    if pid == 0x0229:
        result['fixed_gid_ok'] = (same_length and n == 15 and header and
                                  int.from_bytes(P[2:6], 'little') != 0)
        result['accepted'] = bool(header and changed and result['fixed_gid_ok'])
        return result
    # Preserve the exact original valid_actor checks, including its short-packet
    # early return. No bytes, names, IDs or addresses leave this function.
    result['object_type_ok'] = len(P) >= 60 and P[4] <= 12
    if len(P) >= 15:
        speed = P[13] | (P[14] << 8)
        result['walk_speed_ok'] = 0 <= speed <= 2000
        # Diagnostic-only integer: populated for first/last observations, never per poll.
        result['walk_speed_value'] = speed
    if len(P) >= 60:
        name = P[-24:] if len(P) >= 90 else b''
        result['name_format_ok'] = valid_actor_name(name)
    result['accepted'] = bool(n >= 2 and same_length and changed and header
                              and result['object_type_ok'] and result['walk_speed_ok']
                              and result['name_format_ok'])
    return result


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
    ENC = (0x09fd, 0x09ff, 0x0229, 0x043f, 0x0983)
    FIXED_ENC = {0x0229: 2, 0x043f: 2, 0x0983: 2}  # fixed 15-byte packet: 2-byte clear ID only
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
        # The ring address is process/session specific. Never trust an address
        # from another launch just because /proc/<pid>/maps still maps it.
        # Discovery starts unconditionally from current-session packet evidence.
        self.ring_epoch = 0

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

    def note_enc(self, conn, off, L, pid=None):
        head = self.FIXED_ENC.get(pid, 4)
        self.spans[conn].append((off + head, off + L))   # body only; id+len are cleartext

    def copy_ok(self, pkt, P):
        if len(pkt) < 2 or len(P) != len(pkt) or P == pkt:
            return False
        pid = pkt[0] | (pkt[1] << 8)
        if pid == 0x0983:
            # Partial ciphertext observed in 'type'; verify full plaintext from RX ring.
            return len(pkt) == 29 and P[:2] == pkt[:2] and int.from_bytes(P[4:8], 'little') != 0
        if pid == 0x043f:
            # Status ID/GID and payload must come from verified client plaintext.
            return len(pkt) == 25 and P[:2] == pkt[:2] and int.from_bytes(P[4:8], 'little') != 0
        if pid == 0x0229:
            # Only the two-byte ID is clear. GID and status flags are encrypted;
            # equality with ciphertext GID would reject authentic plaintext.
            # Field bit patterns are not sufficient proof of decryption.
            return len(pkt) == 15 and P[:2] == pkt[:2] and int.from_bytes(P[2:6], 'little') != 0
        return P[:4] == pkt[:4] and valid_actor(P)

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
        e['preimage_ring_base'] = base
        e['preimage_ring_epoch'] = getattr(self, 'ring_epoch', 0)
        for i, it in enumerate(e['items']):
            if it[0] != 'E':
                continue
            a = self.slot(e['d'], it[3], e['cstart'], base)
            if pre is not None and pre[1] == base and 0 <= a - base and a - base + len(it[2]) <= len(pre[0]):
                e['B'][i] = pre[0][a - base:a - base + len(it[2])]
                e.setdefault('Bsafe_items', set()).add(i)
                e['Bsafe'] = True
            else:
                e['B'][i] = self.read(a, len(it[2]))

    def _ring_mapping_allowed(self, base, end):
        """Require page-aligned ring base inside anonymous writable memory.

        Wine/Proton allocates legitimate RX rings in anonymous RWX mappings;
        rejecting executable pages loses all actor/NPC plaintext. A coincidental
        header inside the PE code range is instead excluded by base alignment
        and file-backed mapping rules, before the usual plaintext validation.
        """
        if base % 0x1000:
            self.stats['ring-rejected-unsafe-mapping'] += 1
            return False
        try:
            with open(f'/proc/{self.pid}/maps', encoding='utf-8') as maps:
                for line in maps:
                    fields = line.split()
                    lo, hi = (int(v, 16) for v in fields[0].split('-'))
                    if lo <= base < hi:
                        perms = fields[1]
                        path = fields[5] if len(fields) > 5 else ''
                        if not (perms.startswith('rw') and 'p' in perms
                                and not path and end <= hi):
                            self.stats['ring-rejected-unsafe-mapping'] += 1
                            return False
                        return True
        except (OSError, ValueError, IndexError):
            self.stats['ring-mapping-unavailable'] += 1
            return False
        self.stats['ring-mapping-unavailable'] += 1
        return False

    # ---- finding the ring -------------------------------------------------------------------
    def start_quick_discover(self, conn, C, items, cstart):
        """Kick a background quick_discover for a clean-start chunk, if none is running."""
        if self.base is not None or self.quick_busy:
            return
        if time.monotonic() < getattr(self, 'next_quick', 0.0):
            return
        if not any(it[0] == 'E' for it in items):
            return
        self.quick_busy = True
        # 0x0229 has only a 2-byte clear header; its payload starts at +2.
        # Mask *all* encrypted body bytes during quick ring discovery.
        candidates = [(it[3] - cstart, it[2]) for it in items if it[0] == 'E'
                      and it[3] >= cstart and it[3] - cstart + len(it[2]) <= len(C)]
        rel = [(it[3] - cstart + self.FIXED_ENC.get(it[1], 4),
                it[3] - cstart + len(it[2])) for it in items if it[0] == 'E']
        threading.Thread(target=self.quick_discover, args=(conn, C, rel, candidates),
                         name='actor-quick', daemon=True).start()

    def quick_discover(self, conn, C, enc_rel, candidates=()):
        """Read-only ring search against this session's chunk at +0x40.

        Large chunks use 64 matching clear bytes. For isolated encrypted actors,
        require a plausible decrypted actor at the predicted position instead;
        matching a 4-byte ciphertext header by itself is NOT sufficient.
        """
        try:
            mask = bytearray(len(C))
            for a, b in enc_rel:
                a, b = max(0, min(len(C), a)), max(0, min(len(C), b))
                if b > a:
                    mask[a:b] = b'\1' * (b - a)
            clear = len(C) - sum(mask)
            if clear < 64 and not candidates:
                return False
            self.stats['quick-attempts'] += 1
            # Search inside each writable mapping, not just at mapping+0x40.
            # A packet at offset `off` identifies the ring at hit-off-HDR.
            # Use an actual validated plaintext actor as anchor so that a
            # coincidental clear header never establishes the ring.
            anchor = next(((off, pkt) for off, pkt in candidates if len(pkt) >= 15), None)
            if anchor is None:
                return False
            off, pkt = anchor
            header = pkt[:self.FIXED_ENC.get(int.from_bytes(pkt[:2], 'little'), 4)]
            window = 0x100000  # bounded 1MiB reads; no giant allocation per mapping
            for lo, hi, _ in regions(self.pid, max_size=MAX_REGION):
                if self.base is not None:
                    return False
                if hi - lo < self.HDR + len(C):
                    continue
                pos = lo
                while pos < hi:
                    n = min(window, hi - pos)
                    block = self.read(pos, n)
                    if not block:
                        pos += n
                        continue
                    i = block.find(header)
                    while i >= 0:
                        candidate = pos + i - self.HDR - off
                        if candidate >= lo and candidate + self.HDR + len(C) <= hi:
                            slot = candidate + self.HDR
                            R = self.read(slot, len(C))
                            if (len(R) == len(C) and
                                    all(m or r == c for r, c, m in zip(R, C, mask)) and
                                    any(self.copy_ok(p, R[o:o + len(p)]) for o, p in candidates)):
                                if not self._ring_mapping_allowed(candidate, candidate + self.HDR + len(C)):
                                    i = block.find(header, i + 1)
                                    continue
                                with self.lock:
                                    if self.base is None:
                                        self._set_ring(candidate, hi,
                                            f'quick: internal ring, clear={clear}, anchor={header.hex()}')
                                        self.stats['ring-quick-actor-verified'] += 1
                                        return True
                        i = block.find(header, i + 1)
                    pos += max(1, len(block) - len(header) + 1)
            self.stats['quick-miss'] += 1
            return False
        finally:
            self.quick_busy = False
            self.next_quick = time.monotonic() + self.SCAN_BACKOFF
        return False

    def _set_ring(self, lo, hi, why):                  # caller holds self.lock
        self.base, self.hi = lo, hi
        self.region = (lo, hi)
        self.fails = 0
        self.ring_epoch = getattr(self, 'ring_epoch', 0) + 1
        self.stats['ring-discovered'] += 1
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
            # d is relative to `lo` only because the mapping was used as an
            # initial coordinate; infer actual ring from verified packet slot.
            slot = best[0][3]
            ringbase = slot - self.HDR - (off - cstart)
            if ringbase < best[1] or ringbase >= best[2]:
                return False
            if not self._ring_mapping_allowed(ringbase, slot + len(pkt)):
                return False
            self._set_ring(ringbase, best[2],
                           f'copy @0x{slot:x}, ctx pre{best[0][1]}/post{best[0][2]}')
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
        pid = pkt[0] | (pkt[1] << 8)
        hdr = pkt[:self.FIXED_ENC.get(pid, 4)]
        i = buf.find(hdr)
        while i != -1:
            P = buf[i:i + L]
            if len(P) == L and self.copy_ok(pkt, P):
                pre, post = self._ctx(buf, i, conn, off, L)
                sc = pre + post
                if pid not in (0x0229, 0x043f, 0x0983) and P[5:9] in near:
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
                c = [x for x in self._best(buf, bufbase, conn, pkt, off, cstart, exp_d)
                     if x[5] != stale and (pid not in (0x0229, 0x043f, 0x0983) or
                         (x[1] + x[2] >= 8 and x[4] == (self.HDR if exp_d is None else exp_d)))]
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
                self.base = self.hi = self.region = None
                self.fails = 0
                self.next_scan = 0.0
                self.stats['ring-invalidated'] += 1
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
        e['polls'] = e.get('polls', 0) + 1
        base = self.base
        if base is None:                               # no ring yet: full discovery (score rule)
            if now - e['t'] < min(delay, self.DISCOVER_WAIT):
                return None
            result = {i: self.resolve(e['conn'], e['items'][i][1], e['items'][i][2], e['items'][i][3],
                                    e['cstart'], snaps=e['snaps'], exp_d=e['d']) for i in E}
            for i in E:
                e.setdefault('reasons', {})[i] = ('ok' if result[i] else 'ring-not-found')
            return result
        closed = e['closed']                           # read once: the worker may set it any time
        if closed is None:
            fresh = True
            for i in E:
                _, pid, pkt, off = e['items'][i]
                P = self.read(self.slot(e['d'], off, e['cstart'], base), len(pkt))
                e['ev'][i].append((now * 1000, P))
                raw_valid = self.copy_ok(pkt, P)
                safe_empty_name = (i in e.get('Bsafe_items', set()) and
                                   e.get('preimage_ring_base') == base and
                                   e.get('preimage_ring_epoch') == getattr(self, 'ring_epoch', 0) and
                                   P != e['B'].get(i) and
                                   fresh_empty_name_actor(pkt, P))
                valid = (raw_valid or safe_empty_name) and P != e['B'].get(i)
                # Diagnostic details are computed ONCE at decision time, not on
                # every 5ms poll. The samples already live in e['ev'][i].
                if valid:
                    e.setdefault('first_valid_ms', {}).setdefault(i, round((now - e['t']) * 1000, 2))
                fresh &= valid
            if e['tfinal'] is None and (fresh or now - e['t'] >= delay):
                e['tfinal'] = now                      # evidence complete as of this read
            if e['tfinal'] is None or now - e['tfinal'] < settle_wait:
                return None
            cut = e['tfinal'] * 1000 + 1
            # The worker may have recorded a new receive during the read above.
            # Never treat bytes observed after that receive as the old slot.
            if e['closed'] is not None:
                cut = min(cut, e['closed'] - 1)
        else:
            cut = closed - 1                           # reads after the next chunk arrived: unsafe
        out = {}
        for i in E:
            _, pid, pkt, off = e['items'][i]
            ev = [(T, P) for T, P in e['ev'][i] if T < cut]
            # Preserve the first/last actual live slot reads independently of
            # evidence cutoff; compute diagnostics only after polling is over.
            samples = e['ev'][i]
            for key, sample in (('first_read', samples[0] if samples else None),
                                ('last_read', samples[-1] if samples else None)):
                if sample is None:
                    continue
                T, P = sample
                details = copy_validation(pkt, P)
                e.setdefault(key, {})[i] = {
                    'ms': round(T - e['t'] * 1000, 2),
                    'bytes_read': len(P),
                    'header_match': details['header_match'],
                    'copy_ok': details['accepted'],
                    'different_from_before': P != e['B'][i] if i in e['B'] else None,
                    'verified': details['accepted'] and P != e['B'].get(i),
                    'validation': details,
                }
            rel = e['d'] + off - e['cstart']
            for data, _sbase, ts in list(e['snaps']):
                if 0 <= rel and rel + len(pkt) <= len(data):
                    ev.append((ts, data[rel:rel + len(pkt)]))
            ev.sort(key=lambda x: x[0])
            # Diagnose rejected names by category, without logging raw name data.
            if pid in (0x09ff, 0x09fd) and samples:
                last = samples[-1][1]
                details = copy_validation(pkt, last)
                if (details['length_match'] and details['header_match'] and
                        details['object_type_ok'] and details['walk_speed_ok'] and
                        not details['name_format_ok']):
                    e.setdefault('name_rejection', {})[i] = actor_name_rejection(last[-24:])
            # Summarize validated/rejected evidence without recording packet
            # bytes. This differentiates bad structure from bad provenance.
            e.setdefault('evidence_validations', {})[i] = {
                'observations': len(ev),
                'structurally_valid': sum(self.copy_ok(pkt, P) for _, P in ev),
                'snapshots_usable': sum(0 <= rel and rel + len(pkt) <= len(data)
                                        for data, _, _ in e['snaps']),
            }
            V = next((P for T, P in reversed(ev) if self.copy_ok(pkt, P)), None)
            # A valid candidate may be rejected later by provenance or
            # context scoring. Count this separately from true timeouts.
            e.setdefault('candidate_seen', {})[i] = V is not None
            # Boolean-only failure taxonomy; no actor GID, name or packet bytes.
            e.setdefault('failure_evidence', {})[i] = {
                'slot_observations': len(samples),
                'usable_observations': len(ev),
                'valid_observations': e['evidence_validations'][i]['structurally_valid'],
                'preimage_present': i in e['B'],
                'preimage_safe': i in e.get('Bsafe_items', set()),
                'slot_overwritten': closed is not None,
                'candidate_valid_but_not_accepted': V is not None,
            }
            e.setdefault('snapshot_read_count', {})[i] = sum(
                0 <= rel and rel + len(pkt) <= len(data)
                for data, _base, _ts in e['snaps'])
            B = e['B'].get(i)
            # Only live reads of the predicted slot can use this exception.
            # Snapshots and scored copies stay strictly name-validated; a read
            # at or after the next recv is excluded by the existing cutoff.
            empty_name = None
            if (i in e.get('Bsafe_items', set()) and
                    e.get('preimage_ring_base') == base and
                    e.get('preimage_ring_epoch') == getattr(self, 'ring_epoch', 0) and
                    B is not None):
                empty_name = next((P for T, P in reversed(samples)
                                   if T < cut and P != B and fresh_empty_name_actor(pkt, P)), None)
            # Prefer ordinary validated copies over the exceptional path.
            if V is None and empty_name is not None:
                with self.lock:
                    out[i] = self._accept(empty_name, 'fresh-empty-name', True)
                e.setdefault('reasons', {})[i] = ('ok-empty-name-fresh' if out[i]
                                                   else 'duplicate-rejected')
                continue
            # A capture made BEFORE recv processing gives independent evidence of a
            # transition from the pre-decrypt bytes. If the pre-image is unavailable,
            # don't upgrade a plausible-looking cached ring slot to verified plaintext.
            if (V is not None and i in e['B'] and V != B and
                    (pid not in (0x0229, 0x043f, 0x0983) or i in e.get('Bsafe_items', set()))):
                with self.lock:
                    out[i] = self._accept(V, 'fresh', True)
                e.setdefault('reasons', {})[i] = 'ok' if out[i] else 'duplicate-rejected'
                continue
            # the slot never changed: with a pre-decrypt image that's proof the copy there is stale
            out[i] = self.resolve(e['conn'], pid, pkt, off, e['cstart'], exp_d=e['d'],
                                  live=closed is None, snaps=e['snaps'],
                                  stale=B if i in e.get('Bsafe_items', set()) else None)
            e.setdefault('reasons', {})[i] = ('ok' if out[i] else
                'ring-not-found' if self.base is None else
                'overwritten-before-verification' if closed is not None and not ev else
                'correlation-mismatch' if any(self.copy_ok(pkt, P) for T, P in ev) else
                'timeout-no-valid-copy' if now - e['t'] >= delay else 'no-valid-copy')
        return out
