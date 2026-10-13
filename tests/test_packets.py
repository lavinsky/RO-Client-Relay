"""Offline test for relay/packets.py: the WireFilter tokenizer (packet boundaries, encrypted-body
items, drop list, unknown-id passthrough, bare account id, partial packets across chunks) and
MoveTracker (decodes the server 0087 move destination and cross-checks it against a 035f walk).
Uses exact bytes from a live capture for the move case (035f (298,122), 0087 confirmed (298,122))."""
from _boot import g

# 0087 from the live log: 8700 884b9a1e (tick) 4b0824a87a88 (MoveData2)
PKT0087 = bytes.fromhex('8700884b9a1e4b0824a87a88')
assert g.unpack_pos2(PKT0087[6:12]) == (300, 130, 298, 122), g.unpack_pos2(PKT0087[6:12])

logged = []
class FakeLog:
    def write(self, m): logged.append(m)

mt = g.MoveTracker(FakeLog())

# no walk seen yet -> 0087 logs but can't confirm
mt.on_recv_packet(0, 0x0087, 0, PKT0087)
assert logged[-1]['match'] is False and logged[-1]['req'] is None
assert mt.stats['no-request'] == 1

# recovered 035f walk (298,122) then the 0087 -> MATCH
mt.on_walk(298, 122, 1)
rec = mt.on_recv_packet(0, 0x0087, 0, PKT0087)
assert rec['match'] and rec['dst'] == [298, 122] and rec['req'] == [298, 122], rec
assert mt.stats['match'] == 1
assert mt.last_walk is None                         # consumed: one 0087 confirms one walk

# a walk that doesn't match the next confirmation -> MISMATCH
mt.on_walk(1, 2, 0)
mt.on_recv_packet(0, 0x0087, 0, PKT0087)
assert mt.stats['mismatch'] == 1 and logged[-1]['match'] is False

# non-move packets and short packets are ignored
before = len(logged)
mt.on_recv_packet(0, 0x0086, 0, PKT0087)            # 0086 (other actor) is not our move
mt.on_recv_packet(0, 0x0087, 0, PKT0087[:8])        # too short
assert len(logged) == before
print('move cross-check ok:', dict(mt.stats))

# pack_move builds the 3-byte 035f body; round-trips with the standard unpacking
assert g.pack_move(105, 256, 0) == bytes.fromhex('1a5000'), g.pack_move(105, 256, 0).hex()
def unpack3(b): return ((b[0] << 2) | (b[1] >> 6), ((b[1] & 0x3f) << 4) | (b[2] >> 4), b[2] & 0xf)
for xy in [(105, 256, 0), (298, 122, 1), (0, 0, 0), (1023, 1023, 15), (200, 200, 7)]:
    assert unpack3(g.pack_move(*xy)) == xy, (xy, g.pack_move(*xy).hex())
print('pack_move round-trip ok')

# --- WireFilter: splitting the server->client stream into packets --------------------------------
L = {0x0073: 5, 0x0087: 12, 0x008c: -1, 0x09ff: -1}   # two fixed, two variable (length in bytes 2-3)
p73 = b'\x73\x00' + bytes([1, 2, 3])                   # len 5
p87 = b'\x87\x00' + bytes(range(10))                   # len 12
var8c = b'\x8c\x00' + (8).to_bytes(2, 'little') + b'abcd'   # VAR, total len 8
enc9ff = b'\xff\x09' + (10).to_bytes(2, 'little') + bytes([9, 9, 9, 9, 9, 9])   # VAR len 10

# clean fixed + variable stream: one contiguous 'B' block
w = g.WireFilter(L, set())
assert w.push_items('c', p73 + var8c + p87) == [('B', p73 + var8c + p87)]

# encrypted id (in the enc set) comes out as a separate 'E' item with its stream offset
w = g.WireFilter(L, set())
items = w.push_items('e', p73 + enc9ff + p87, enc={0x09ff})
assert items == [('B', p73), ('E', 0x09ff, enc9ff, len(p73)), ('B', p87)], items

# drop list: that id is omitted whole, the stream stays aligned
w = g.WireFilter(L, {0x0073})
assert w.push_items('d', p73 + p87) == [('B', p87)]

# bare account id (4-byte unknown at the very start) is passed through, then normal tokenizing
w = g.WireFilter(L, set())
acct = bytes([0x11, 0x22, 0x33, 0x44])                 # id 0x2211 unknown; 4 bytes at stream start
assert w.push_items('a', acct + p87) == [('B', acct + p87)]

# an unknown id mid-stream switches that connection to raw passthrough (fail open)
w = g.WireFilter(L, set())
unk = bytes([0xaa, 0xbb, 0, 0])                        # id 0xbbaa not in the table
out = w.push_items('u', p87 + unk)
assert out == [('B', p87 + unk)], out                  # p87 tokenized, then everything raw
assert w.push_items('u', p73) == [('B', p73)]          # connection stays raw afterwards

# a packet split across two chunks is carried and reassembled
w = g.WireFilter(L, set())
assert w.push_items('s', p87[:7]) == [] and w.carried('s') == 7
assert w.push_items('s', p87[7:]) == [('B', p87)] and w.carried('s') == 0
print('WireFilter ok')
print('ALL PASS')
