"""Offline routing and status recovery tests for 0983."""
import collections
import threading
from _boot import g
from relay.actors import ActorDecrypt, copy_validation
from relay.packets import WireFilter
d=ActorDecrypt.__new__(ActorDecrypt)
d.base=0x1000;d.hi=0x5000;d.region=(0x1000,0x5000)
d.stream={};d.spans=collections.defaultdict(list)
d.fed={};d.stats=collections.Counter();d.fails=0;d.lock=threading.Lock()
wire=b'\x83\x09'+bytes(range(27))
plain=b'\x83\x09'+(824).to_bytes(2,'little')+(0x20f073).to_bytes(4,'little')+bytes([1])+(9999).to_bytes(4,'little')+bytes(16)
assert len(plain)==29
assert 0x0983 in d.ENC and d.FIXED_ENC[0x0983]==2
assert d.copy_ok(wire,plain) and copy_validation(wire,plain)['accepted']
assert not d.copy_ok(wire,wire)
assert not d.copy_ok(wire,plain[:-1])
assert not d.copy_ok(wire,b'\x83\x09'+b'\x00'*27)
assert not d.copy_ok(wire,b'\x3f\x04'+plain[2:])
assert WireFilter({0x0983:29},set()).push_items('c',wire,enc=d.ENC)==[('E',0x0983,wire,0)]
d._best=lambda *a:[(16,0,0,0x1040,0x40,plain)]
d.read=lambda a,n: plain if n==29 else b'\x00'*n
assert d.resolve('c',0x0983,wire,0,0,exp_d=0x40) is None
print('0983 recovery PASS')
