"""0229 must not gain trust from a header or expected ring position alone."""
import collections
import threading
from _boot import g
from relay.actors import ActorDecrypt, copy_validation


def dec():
    d = ActorDecrypt.__new__(ActorDecrypt)
    d.base = 0x1000
    d.hi = 0x4000
    d.stream = {'c': [0, b'\xaa' * 20 + b'\x29\x02' + b'\xee' * 13 + b'\xbb' * 20]}
    d.spans = collections.defaultdict(list)
    d.spans['c'] = [(22, 35)]
    d.fed = {}
    d.stats = collections.Counter()
    d.fails = 0
    d.lock = threading.Lock()
    return d


d = dec()
wire = b'\x29\x02' + b'\xee' * 13
plain = b'\x29\x02' + b'\x78\x56\x34\x12' + b'\x00' * 9
assert d.copy_ok(wire, plain)
assert copy_validation(wire, plain)['accepted']
assert d.copy_ok(wire, b'\x29\x02' + b'\x78\x56\x34\x12' + b'\xff' * 9)
assert not d.copy_ok(wire, b'\x29\x02' + b'\x00' * 13)
# No adjacent context: expected slot must not be enough for resolve().
d._ctx = lambda *args: (0, 0)
d.read = lambda addr, n: plain if n == 15 else b'\x00' * n
d._best = lambda buf, base, conn, pkt, off, cstart, exp_d=None: [
    (16, 0, 0, d.base + 0x40 + off, 0x40, plain)]
assert d.resolve('c', 0x0229, wire, 0, 0, exp_d=0x40, live=True) is None
print('0229 provenance gate PASS')
