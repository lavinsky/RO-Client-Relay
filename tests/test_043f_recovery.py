"""043F status packets require ring provenance and cannot pass ciphertext unchanged."""
import collections
import threading
from _boot import g
from relay.actors import ActorDecrypt, copy_validation
from relay.packets import WireFilter


def fake_dec():
    d = ActorDecrypt.__new__(ActorDecrypt)
    d.base = 0x1000
    d.hi = 0x5000
    d.region = (0x1000, 0x5000)
    d.stream = {}
    d.spans = collections.defaultdict(list)
    d.fed = {}
    d.stats = collections.Counter()
    d.fails = 0
    d.lock = threading.Lock()
    return d


wire = b'\x3f\x04' + bytes(range(23))
plain = b'\x3f\x04' + b'\x7b\x00' + b'\x78\x56\x34\x12' + bytes([1]) + (9999).to_bytes(4, 'little') + b'\x00' * 12
assert len(plain) == 25
d = fake_dec()
assert 0x043f in d.ENC and d.FIXED_ENC[0x043f] == 2
assert d.copy_ok(wire, plain)
assert copy_validation(wire, plain)['accepted']
assert not d.copy_ok(wire, wire)
assert not d.copy_ok(wire, plain[:-1])
assert not d.copy_ok(wire, b'\x3f\x04' + b'\x00' * 23)
assert not d.copy_ok(wire, b'\x29\x02' + plain[2:])
assert WireFilter({0x043f: 25}, set()).push_items('c', wire, enc=d.ENC) == [('E', 0x043f, wire, 0)]
d._best = lambda *args: [(16, 0, 0, 0x1040, 0x40, plain)]
d.read = lambda address, n: plain if n == 25 else b'\x00' * n
assert d.resolve('c', 0x043f, wire, 0, 0, exp_d=0x40) is None
print('043f recovery checks PASS')
