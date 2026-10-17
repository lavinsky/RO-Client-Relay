"""Research tools, off by default: --probe-actors (ActorProbe) and --actor-diag (ActorDiag)."""
import collections
import threading
import time

from .actor_recovery import valid_actor
from .actor_recovery import MAX_REGION, ProcessMemory, regions


class ActorProbe:
    """--probe-actors: find where the client keeps the DECRYPTED body of 09fd/09ff.

    The wire stream is cleartext except those bodies, so for each one we (1) re-read the client's
    own recv buffer (the iovec address recvmsg filled) at several delays to see if it is decrypted
    IN PLACE, and (2) occasionally scan rw memory for the packet's cleartext id+len header and test
    every hit: same length, body parses as a valid actor, and the bytes right after it equal the
    next cleartext packet. Read-only via /proc/<pid>/mem; prints [probe] lines."""
    DELAYS = (0, 0.02, 0.06, 0.15)
    valid = staticmethod(valid_actor)

    def __init__(self, pid):
        self.pid = pid
        self.mem = ProcessMemory(pid)
        self.chunks = collections.defaultdict(lambda: collections.deque(maxlen=64))  # conn -> (start, ptr, n, t)
        self.coff = collections.Counter()              # conn -> stream offset of next chunk
        self.n = 0
        self.stream = {}                               # conn -> [stream offset of bytes[0], recent bytes]
        self.scan_lock = threading.Lock()
        self.hot = set()                               # rw regions that held decrypted actor packets

    def read(self, a, n):
        return self.mem.read(a, n)

    def note_chunk(self, conn, n, ptr, C=b''):
        self.chunks[conn].append((self.coff[conn], ptr, n, time.time()))
        self.coff[conn] += n
        sb0, sb = self.stream.get(conn, (0, b''))
        sb += C
        if len(sb) > 0x10000:
            cut = len(sb) - 0x10000
            sb0, sb = sb0 + cut, sb[cut:]
        self.stream[conn] = [sb0, sb]

    def on_packet(self, conn, pid, off, pkt):
        """WireFilter.on_packet callback."""
        if pid not in (0x09fd, 0x09ff):
            return
        loc = next(((ptr + off - st, t) for st, ptr, n, t in self.chunks[conn] if st <= off and off + len(pkt) <= st + n), None)
        self.n += 1
        sb0, sb = self.stream.get(conn, (0, b''))
        i = off - sb0
        ctx = (sb[max(0, i - 32):max(0, i)], sb[i + len(pkt):i + len(pkt) + 32])   # wire bytes around it
        threading.Thread(target=self._probe, args=(self.n, pid, pkt, loc, ctx), daemon=True).start()

    def _probe(self, k, pid, pkt, loc, ctx=(b'', b'')):
        with self.scan_lock:
            if not self.hot:                           # first packet: full scan learns hot regions
                self._scan(pkt)
        t0 = loc[1] if loc else time.time()
        for d in self.DELAYS:
            time.sleep(max(0, t0 + d - time.time()))
            c = self._candidates(pkt, ctx)
            strong = [x for x in c if x[1] >= 8 or x[2] >= 8 or x[3]]
            print(f"[probe] #{k} 0x{pid:04x} +{int(d*1000)}ms {len(c)} valid, strong: " +
                  (' '.join(f"{hex(a)}(pre{p_},post{q},{'IDctx' if idm else '-'},{nm!r})" for a, p_, q, idm, nm in strong[:6]) or 'none'))

    def _candidates(self, pkt, ctx):
        out = []
        for lo, hi in sorted(self.hot):
            blk = self.read(lo, hi - lo)
            i = blk.find(pkt[:4])
            while i != -1:
                P = blk[i:i + len(pkt)]
                if len(P) == len(pkt) and P != pkt and valid_actor(P):
                    pre, post = blk[max(0, i - len(ctx[0])):i], blk[i + len(pkt):i + len(pkt) + len(ctx[1])]
                    np = next((j for j in range(len(pre)) if pre[len(pre) - 1 - j] != ctx[0][len(ctx[0]) - 1 - j]), len(pre))
                    nn = next((j for j in range(len(post)) if post[j] != ctx[1][j]), len(post))
                    idm = P[5:9] in ctx[0] + ctx[1]
                    out.append((lo + i, np, nn, idm, P[-24:].split(bytes(1))[0]))
                i = blk.find(pkt[:4], i + 1)
        return out

    def _scan(self, pkt):
        hdr = pkt[:4]
        for lo, hi, _ in regions(self.pid, max_size=MAX_REGION):
            blk = self.read(lo, hi - lo)
            i = blk.find(hdr)
            while i != -1:
                P = blk[i:i + len(pkt)]
                if len(P) == len(pkt) and P != pkt and valid_actor(P):
                    self.hot.add((lo, hi))
                    break
                i = blk.find(hdr, i + 1)
        print(f"[probe] hot regions: {' '.join(f'{lo:#x}-{hi:#x}' for lo, hi in sorted(self.hot))}")


class ActorDiag:
    """--actor-diag: timing study of where/when the decrypted 09fd/09ff copy shows up in the ring.

    For each encrypted packet, polls the expected ring slot (base + learned delta + offset in
    chunk) every 5 ms for 1.5 s and prints when a valid decrypted copy appears / is overwritten,
    relative to the chunk's arrival, the next recv on that connection and the next RINGSNAP.
    Never found at the slot -> scans the whole ring region and reports where copies are.
    Read-only via ActorDecrypt.read (/proc/<pid>/mem)."""

    def __init__(self, dec):
        self.dec = dec
        self.next_recv = {}                            # conn -> time of the latest recv
        self.snap_t = {}                               # sock -> time of the latest RINGSNAP

    def on_packet(self, conn, sock, pid, pkt, off, cstart, left, t0):
        threading.Thread(target=self._run, args=(conn, sock, pid, pkt, off, cstart, left, t0),
                         daemon=True).start()

    def _run(self, conn, sock, pid, pkt, off, cstart, left, t0):
        dec, L = self.dec, len(pkt)
        r = dec.region                                 # one read: the ring may be dropped meanwhile
        if r is None:
            return
        base, hi = r
        d0 = dec.chain.get(conn, (dec.HDR, 0))[0]
        loc = base + d0 + (off - cstart)
        r0 = self.next_recv.get(conn, 0); s0 = self.snap_t.get(sock, 0)
        first = gone = None; body = None; trace = []
        last = dec.read(loc, L)
        while time.time() - t0 < 1.5:
            P = dec.read(loc, L)
            if P != last:
                trace.append((int((time.time() - t0) * 1000), P[:4].hex()))
                last = P
            ok = P[:4] == pkt[:4] and P != pkt and valid_actor(P)
            if ok and first is None:
                first, body = time.time(), P
            elif first is not None and gone is None and P != body:
                gone = time.time()
            time.sleep(0.005)
        ms = lambda t: f'+{int((t - t0) * 1000)}ms' if t else '-'
        nr = self.next_recv.get(conn, 0); ns = self.snap_t.get(sock, 0)
        msg = (f'[diag] 0x{pid:04x} off={off - cstart} left={left} d0=0x{d0:x} found={ms(first)} '
               f'gone={ms(gone)} next_recv={ms(nr if nr != r0 and nr > t0 else 0)} '
               f'snap={ms(ns if ns != s0 and ns > t0 else 0)} changes={trace[:6]}')
        if first is None:
            blk = dec.read(base, hi - base)
            hits, i = [], blk.find(pkt[:4])
            while i != -1 and len(hits) < 8:
                P = blk[i:i + L]
                if len(P) == L and P != pkt and valid_actor(P):
                    hits.append(f'0x{i:x}' + ('*' if P[5:9] == pkt[5:9] else ''))
                i = blk.find(pkt[:4], i + 1)
            msg += f' region-copies={hits}'
        print(msg)


def scramble_probe_config(opts):
    """Optional read-only entry probe; operational configuration never imports this."""
    pe, pa = getattr(opts, 'probe_entry', ''), getattr(opts, 'probe_at', '')
    if pe or pa:
        lo = hi = None
        if getattr(opts, 'scramble_range', ''):
            lo, hi = (int(x, 16) for x in opts.scramble_range.split('-'))
        ids = [int(x, 16) for x in getattr(opts, 'probe_ids', '0437,0438').split(',') if x.strip()]
        cfg = {'reg': 'auto', 'pid': int(opts.scramble_id, 16), 'body': None, 'dry': False,
               'idoff': 0, 'lo': lo, 'hi': hi, 'persist': False, 'probe': True, 'entry': True,
               'ids': ids}
        if pa:
            cfg['pc'] = int(pa, 16)
            where = f"0x{cfg['pc']:x}"
        else:
            cfg['off'] = int(pe, 16)
            where = f"gepard+0x{cfg['off']:x}"
        gate = f' gated to a 0437/0438 copy into 0x{lo:x}-0x{hi:x}' if lo is not None else ' (first call)'
        print(f'[*] --probe-entry: one-shot capture of args at {where}{gate}, read-only')
        return cfg


def arm_trace(capture):
    """Rastreio com Stalker: teste de sobrevivência (--trace-test), uaRO->gepard (--trace-walk)
    ou uaRO->uaRO (--trace-internal). Faixa do código uaRO 0x401000..0x1717000."""
    from .frida_bridge import trace_msg
    w, t = getattr(capture.opts, 'trace_walk', 0), getattr(capture.opts, 'trace_test', 0)
    ti = getattr(capture.opts, 'trace_internal', 0)
    if ti:
        print(f'[*] --trace-internal: Stalker por {ti}ms registrando chamadas uaRO->uaRO (ARRISCADO)')
        capture.post(trace_msg(ti, 0x401000, 0x1717000, interno=True))
    elif w:
        print(f'[*] --trace-walk: Stalker por {w}ms registrando chamadas uaRO->gepard (ARRISCADO)')
        capture.post(trace_msg(w, 0x401000, 0x1717000))
    elif t:
        print(f'[*] --trace-test: Stalker por {t}ms (teste de sobrevivencia, ARRISCADO)')
        capture.post(trace_msg(t))
