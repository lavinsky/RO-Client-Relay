"""Offline test for MoveTracker (relay/packets.py): decodes the server 0087 move destination and
cross-checks it against the recovered 035f walk. Uses the exact bytes from a live capture, where
035f recovered (298,122) and the following 0087 confirmed dst (298,122)."""
import importlib.util, os
HERE = os.path.dirname(os.path.abspath(__file__))
sp = importlib.util.spec_from_file_location('g', os.path.join(HERE, 'relay_capture_linux.py'))
g = importlib.util.module_from_spec(sp); sp.loader.exec_module(g)

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
print('ALL PASS')
