"""Log the server's move confirmation, and cross-check it against a walk request when one is known.

The server answers each walk with 0087 (ZC_NOTIFY_PLAYERMOVE, server->client, cleartext), whose
packed MoveData2 holds the real source and destination; MoveTracker decodes it on every 0087 and
logs a MOVE-CHECK line. The client's own request (035f, CZ_REQUEST_MOVE) is NOT recovered in live
captures - SendWatch drops it (SendWatch.DROP) - so live MOVE-CHECKs carry no request ('no-request')
and the 0087 destination is the walk destination. on_walk() is kept for callers that do know the
request (tests, offline replays): the next 0087 is then compared to it ('match' / 'mismatch')."""
import collections

MOVE_ID = 0x0087                                   # ZC_NOTIFY_PLAYERMOVE (own-character move)


def pack_move(x, y, d=0):
    """The 3-byte packed body of a client move (035f) for destination (x, y) and direction d."""
    return bytes(((x >> 2) & 0xff,
                  ((x & 3) << 6) | ((y >> 4) & 0x3f),
                  ((y & 0xf) << 4) | (d & 0xf)))


def unpack_pos2(b):
    """(src_x, src_y, dst_x, dst_y) from the 6-byte MoveData2 (the RO WBUFPOS2 packing)."""
    sx = (b[0] << 2) | (b[1] >> 6)
    sy = ((b[1] & 0x3f) << 4) | (b[2] >> 4)
    dx = ((b[2] & 0x0f) << 6) | (b[3] >> 2)
    dy = ((b[3] & 0x03) << 8) | b[4]
    return sx, sy, dx, dy


class MoveTracker:
    """Records recovered 035f walks and checks them against 0087 move confirmations."""

    def __init__(self, log=None):
        self.log = log
        self.last_walk = None                      # (x, y) of the most recent recovered 035f
        self.stats = collections.Counter()

    def on_walk(self, x, y, d=0):
        """A recovered 035f walk request (from SendWatch)."""
        self.last_walk = (x, y)

    def on_recv_packet(self, conn, pid, off, pkt):
        """WireFilter.on_packet hook: on a 0087, decode its destination and compare to the walk."""
        if pid != MOVE_ID or len(pkt) < 12:
            return
        sx, sy, dx, dy = unpack_pos2(pkt[6:12])
        req = self.last_walk
        state = 'match' if req == (dx, dy) else ('mismatch' if req else 'no-request')
        self.stats[state] += 1
        rec = {'tag': 'MOVE-CHECK', 'id': '0087', 'src': [sx, sy], 'dst': [dx, dy],
               'req': list(req) if req else None, 'match': req == (dx, dy)}
        if self.log:
            self.log.write(rec)
        self.last_walk = None                      # each 0087 confirms at most one walk
        return rec
