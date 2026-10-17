"""Regression: a raw four-byte account ID is not a packet on map -> char return."""
from _boot import g

L = {0x006b: -1, 0x0087: 12}
aid = bytes.fromhex('63ef2000')
char = bytes.fromhex('6b000800') + b'ABCD'
map_pkt = bytes.fromhex('8700') + bytes(10)

w = g.WireFilter(L, set())
w.observe_socket(111, 'server:6121')
assert w.push(111, aid + char) == aid + char   # login -> char is unchanged
w.observe_socket(222, 'server:5121')
assert w.push(222, map_pkt) == map_pkt
w.observe_socket(333, 'server:6121')
assert w.push(333, aid[:1]) == b''
assert w.push(333, aid[1:] + char) == char  # map -> char only
assert not w.conns[333]['raw']
assert w.push(333, char) == char
print('char return AID handling PASS')
