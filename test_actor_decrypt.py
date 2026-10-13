"""Offline test for ActorDecrypt: picks the verified decrypted copy of an encrypted 09ff out of a
synthetic recv ring that also holds stale copies; drops it when unverifiable.
Covers the 'score' rule (cleartext context), the 'fresh' rule (slot changed after arrival),
the chained ring layout for chunks that continue a partial packet, and the closed-socket cutoff
(a read taken after the next chunk arrived must never be used)."""
import importlib.util, os, random, struct, collections, threading
HERE = os.path.dirname(os.path.abspath(__file__))
sp = importlib.util.spec_from_file_location('g', os.path.join(HERE, 'relay_capture_linux.py'))
g = importlib.util.module_from_spec(sp); sp.loader.exec_module(g)
random.seed(1)

def actor(name, aid):
    body = bytes([5]) + aid + aid + struct.pack('<H', 200) + bytes(114 - 15 - 24) + name.ljust(24, b'\0')
    return b'\xff\x09' + struct.pack('<H', 114) + body

def enc(p):
    return p[:4] + bytes(random.randrange(256) for _ in p[4:])

L = {0x09ff: -1, 0x0080: 7, 0x007f: 6}
pre = b''.join(b'\x7f\x00' + bytes([i, 0x22, 0x33, 0x44]) for i in range(5))           # 5x 007f tick
post = b''.join(b'\x80\x00' + bytes([0xaa, i, 0xcc, 0xdd, 1]) for i in range(4))     # 4x 0080
real, stale = actor(b'Picky', b'\x01\x02\x03\x04'), actor(b'Drops', b'\x09\x08\x07\x06')
wire_chunk = pre + enc(real) + post

def new_dec():
    d = g.ActorDecrypt.__new__(g.ActorDecrypt)
    d.mem = None; d.pid = 0
    d.base, d.hi = 0x1000, 0x1000 + 0x4000
    d.chain = {}; d.stream = {}; d.spans = collections.defaultdict(lambda: collections.deque(maxlen=256))
    d.fed = {}; d.fails = 0; d.coff = collections.Counter(); d.stats = collections.Counter()
    d.on_ring = None; d.lock = threading.Lock(); d.quick_busy = False
    return d

d = new_dec()
w = g.WireFilter(L, set())
cstart, dd = d.note_chunk('c', wire_chunk)
assert dd == 0x40
items = w.push_items('c', wire_chunk, g.ActorDecrypt.ENC)
E = [it for it in items if it[0] == 'E']
for it in E:
    d.note_enc('c', it[3], len(it[2]))
assert [it[0] for it in items] == ['B', 'E', 'B'], items

# ---- score rule: stale copies (wrong context) + the real decrypted chunk at +0x40
ring = bytearray(0x4000)
ring[0x900:0x900 + 114] = stale; ring[0x8f0:0x900] = b'\x7f\x00' + bytes(14)
ring[0xa00:0xa00 + 114] = real                          # same header, no context
dec_chunk = pre + real + post
ring[0x40:0x40 + len(dec_chunk)] = dec_chunk
d.read = lambda a, n: bytes(ring[:n])
P = d.resolve('c', 0x09ff, E[0][2], E[0][3], cstart, snap=(bytes(ring), d.base))
print('picked:', P and P[-24:].rstrip(b'\0'), dict(d.stats))
assert P == real

ring2 = bytearray(0x4000); ring2[0x900:0x900 + 114] = stale; ring2[0xa00:0xa00 + 114] = real
d.read = lambda a, n: bytes(ring2[:n])                  # live fallback sees only context-less copies
P2 = d.resolve('c', 0x09ff, E[0][2], E[0][3], cstart, snap=(bytes(ring2), d.base))
print('no-context ring ->', P2, dict(d.stats))
assert P2 is None
# short chunk, packet alone (no cleartext context): accepted at the predicted slot
real3 = actor(b'Poring', b'\x05\x05\x05\x05'); c3 = enc(real3)
cs3, d3 = d.note_chunk('c', c3); it3 = [i for i in w.push_items('c', c3, g.ActorDecrypt.ENC) if i[0] == 'E'][0]
d.note_enc('c', it3[3], len(it3[2]))
ring3 = bytearray(0x4000); ring3[0x40:0x40 + 114] = real3; ring3[0x900:0x900 + 114] = stale
P3 = d.resolve('c', 0x09ff, it3[2], it3[3], cs3, snap=(bytes(ring3), d.base), exp_d=d3)
print('alone at ring+0x40 ->', P3 and P3[-24:].rstrip(b'\0'))
assert P3 == real3
ring4 = bytearray(0x4000); ring4[0x200:0x200 + 114] = real3                # wrong position, no ctx
d.read = lambda a, n: bytes(ring4[:n])
assert d.resolve('c', 0x09ff, it3[2], it3[3], cs3, snap=(bytes(ring4), d.base), exp_d=d3) is None

# ---- settle(): live ring that the test mutates over (simulated) time
class Ring:
    def __init__(self): self.b = bytearray(0x4000)
    def read(self, a, n): a -= 0x1000; return bytes(self.b[a:a + n])

def entry(dec, w, conn, C, t):
    R = dec.read.__self__
    st = w.conns.get(conn); left = len(st['buf']) if st else 0
    cs, dlt = dec.note_chunk(conn, C, left)
    its = w.push_items(conn, C, g.ActorDecrypt.ENC)
    for it in its:
        if it[0] == 'E':
            dec.note_enc(conn, it[3], len(it[2]))
    e = {'sock': 's', 'conn': conn, 'items': its, 'cstart': cs, 'd': dlt, 't': t, 'snaps': [],
         'closed': None, 'B': {}, 'tfinal': None, 'ev': collections.defaultdict(list), 'res': None}
    dec.before(e, (bytes(R.b), 0x1000))                 # agent's image taken inside recvmsg
    return e

def run(dec, e, t0, t1, step=0.005, hook=None):
    t = t0
    while t <= t1:
        if hook: hook(t)
        r = dec.settle(e, t, 0.15)
        if r is not None:
            return r, t
        t += step
    return None, t

# fresh rule: lone 09ff, slot holds a stale copy with the same header, decrypt lands at +6ms
d = new_dec(); w = g.WireFilter(L, set()); R = Ring(); d.read = R.read
R.b[0x40:0x40 + 114] = stale                                  # previous lone 09ff, still there
lone = actor(b'Fabre', b'\x11\x12\x13\x14')
e = entry(d, w, 'k', enc(lone), 0.0)
def land(t):
    if t >= 0.006: R.b[0x40:0x40 + 114] = lone
r, t = run(d, e, 0.0, 1.0, hook=land)
print('fresh lone ->', r and r[0][-24:].rstrip(b'\0'), f'settled at +{t*1000:.0f}ms', dict(d.stats))
assert r == {0: lone} and d.stats['ok-fresh'] == 1 and t < 0.1

# never decrypted / slot never changes from a stale copy, no context -> drop
d = new_dec(); w = g.WireFilter(L, set()); R = Ring(); d.read = R.read
R.b[0x40:0x40 + 114] = stale; d.fed[stale] = 0                # stale was fed long ago
e = entry(d, w, 'k', enc(lone), 0.0)
r, t = run(d, e, 0.0, 1.0)
print('stale-only ->', r, dict(d.stats))
assert r == {0: None}
# same, but the stale copy was never fed (its own packet was dropped): still provably stale
d = new_dec(); w = g.WireFilter(L, set()); R = Ring(); d.read = R.read
R.b[0x40:0x40 + 114] = stale
e = entry(d, w, 'k', enc(lone), 0.0)
r, t = run(d, e, 0.0, 1.0)
print('stale-only, never fed ->', r)
assert r == {0: None}

# closed cutoff: the next chunk (another lone 09ff) arrives at +3ms (before our decrypt was seen);
# its copy lands in the same slot. Must use the snapshot taken before it, never the later read.
d = new_dec(); w = g.WireFilter(L, set()); R = Ring(); d.read = R.read
R.b[0x40:0x40 + 114] = stale
nxt = actor(b'Lunatic', b'\x21\x22\x23\x24')
e = entry(d, w, 'k', enc(lone), 0.0)
R.b[0x40:0x40 + 114] = lone                                    # decrypted (after the B read)
e['snaps'].append((bytes(R.b[:0x1000]), 0x1000, 2.0))         # agent snapshot at next recvmsg entry
e['closed'] = 3.0                                              # next RECV, agent ts 3ms
R.b[0x40:0x40 + 114] = nxt                                     # next chunk's copy now in the slot
r, t = run(d, e, 0.004, 1.0)
print('closed + snapshot ->', r and r[0][-24:].rstrip(b'\0'))
assert r == {0: lone}
d = new_dec(); w = g.WireFilter(L, set()); R = Ring(); d.read = R.read
R.b[0x40:0x40 + 114] = stale; d.fed[stale] = 0
e = entry(d, w, 'k', enc(lone), 0.0)
e['closed'] = 3.0; R.b[0x40:0x40 + 114] = nxt                  # no snapshot; only the next copy
r, t = run(d, e, 0.004, 1.0)
print('closed, no snapshot ->', r, '(must not take the next chunk\'s copy)')
assert r == {0: None}

# chained layout: a 2048-byte chunk ends mid-09ff; the next chunk (continuing it) is appended
# after it in the ring (d = 0x40 + 2048), not at +0x40
d = new_dec(); w = g.WireFilter(L, set()); R = Ring(); d.read = R.read
filler = b''.join(b'\x80\x00' + bytes([0xaa, i & 0xff, 0xcc, 0xdd, 1]) for i in range(290))   # 2030 bytes
a1, a2 = actor(b'Rocker', b'\x31\x32\x33\x34'), actor(b'Willow', b'\x41\x42\x43\x44')
stream = filler + enc(a1) + enc(a2) + post
c1, c2 = stream[:2048], stream[2048:]
e1 = entry(d, w, 'k', c1, 0.0)
assert not any(it[0] == 'E' for it in e1['items'])
dec1 = filler + a1 + a2 + post
R.b[0x40:0x40 + 2048] = dec1[:2048]
e2 = entry(d, w, 'k', c2, 0.1)
assert e2['d'] == 0x40 + 2048, hex(e2['d'])
R.b[0x40 + 2048:0x40 + 2048 + len(c2)] = dec1[2048:]          # appended after the previous chunk
r, t = run(d, e2, 0.1, 1.0)
got = [r[i] for i, it in enumerate(e2['items']) if it[0] == 'E']
print('chained (left>0) ->', [p[-24:].rstrip(b'\0') for p in got if p], dict(d.stats))
assert got == [a1, a2]
print('ALL PASS')
