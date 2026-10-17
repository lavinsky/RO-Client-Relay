"""Offline test: Relay deframes the consumer's inbound 'S' frames into whole packets, even when a
frame is split across two reads."""
import threading
from _boot import g

r = g.Relay.__new__(g.Relay)                                     # no socket/thread; exercise deframing only
r.fmt, r._in, r.lock = 'xkore1', b'', threading.Lock()
got = []
r.on_inbound = lambda payload, typ: got.append((typ, payload.hex()))
frame = lambda typ, p: typ.encode() + len(p).to_bytes(2, 'little') + p
msg = frame('S', bytes.fromhex('3704d935960607')) + frame('S', bytes.fromhex('38040a000d00d9359606'))
r._inbound(msg[:5]); r._inbound(msg[5:])                         # split mid-frame: reassembly must hold
assert got == [('S', '3704d935960607'), ('S', '38040a000d00d9359606')], got
print('relay deframing ok')
