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

# Production defaults must remove Gepard control before an XKore consumer tokenizes the RO
# stream. Its selected kRO table lacks 4754/5395: an unknown switch discards the whole buffer,
# including an adjacent 0AC4 login response or 02EB initial position. Debug exclusions hide
# that warning; they do not filter bytes. Use synthetic bodies, including false packet headers.
from types import SimpleNamespace
from unittest.mock import patch
from relay.cli import build_feed, parse_args, parse_ids
from relay.packets import packet_len
from _boot import DATA

defaults = parse_args([])
assert not hasattr(defaults, 'noskipids')  # filtro legado removido
drop = parse_ids(defaults.drop_ids)
assert {0x4754, 0x5395, 0x09fd, 0x09ff} <= drop, drop
assert parse_ids(parse_args(['--drop-ids', '09fd,09ff']).drop_ids) == {0x09fd, 0x09ff}
lengths = g.load_lengths(DATA + '/uaro_recvpackets.txt')
login = b'\xc4\x0a\x08\x00test'
position = b'\xeb\x02' + bytes(4) + g.pack_move(76, 358) + bytes(4)
control = b'\x54\x47\x10\x00' + p87
sync = b'\x95\x53\x08\x00' + b'\xff\x09\xff\xff'
stream = control + login + sync + position + enc9ff + p87
opts = SimpleNamespace(relay='127.0.0.1:2350', relay_format='xkore1',
                       recvpackets='', feed_dump=None)
with patch('relay.cli.Relay'), patch('relay.cli.read_lengths', return_value=lengths):
    _, production_wire = build_feed(opts, drop)
assert production_wire.push('login', stream) == login + position + p87

partitions = [(stream[:cut], stream[cut:]) for cut in range(len(stream) + 1)]
partitions.append(tuple(stream[i:i + 1] for i in range(len(stream))))
for case, chunks in enumerate(partitions):
    w = g.WireFilter(lengths, drop)
    items = []
    for chunk in chunks:
        items += w.push_items('map', chunk, enc={0x09ff})
    clear = b''.join(it[1] for it in items if it[0] == 'B')
    assert clear == login + position + p87, (case, items)
    enc_off = len(control + login + sync + position)
    assert [it for it in items if it[0] == 'E'] == [('E', 0x09ff, enc9ff, enc_off)]
    # Model the consumer's selected table: every forwarded byte must belong to a known,
    # complete RO packet, without relying on its unknown-message recovery.
    consumer_lengths = {p: n for p, n in lengths.items() if p not in (0x4754, 0x5395)}
    pos, received = 0, []
    while pos < len(clear):
        n = packet_len(consumer_lengths, clear, pos)
        assert n and pos + n <= len(clear), (case, pos, n)
        received.append(int.from_bytes(clear[pos:pos + 2], 'little'))
        pos += n
    assert received == [0x0ac4, 0x02eb, 0x0087]
    assert w.carried('map') == 0 and not w.conns['map']['raw']
print('Gepard control filtered; login, initial position and actor recovery offsets preserved')

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

# Fixed-size encrypted 0229 must be held intact across TCP fragments.
w229 = g.WireFilter({0x0229: 15, 0x0087: 12}, set())
p229 = bytes.fromhex('290263ef2000010203040506070809')
assert w229.push_items('p229', p229[:7], enc={0x0229}) == []
assert w229.push_items('p229', p229[7:], enc={0x0229}) == [('E', 0x0229, p229, 0)]
