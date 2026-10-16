"""Packet semantics: the length table, the per-connection tokenizer (WireFilter), and the move
packing/decoding (035f body, 0087 confirmation)."""
import collections

VAR = -1                                           # length table: variable length, read from bytes 2-3
NEED_MORE = 0                                      # packet_len(): the length isn't readable yet
MOVE_ID = 0x0087                                   # ZC_NOTIFY_PLAYERMOVE (own-character move)


def load_lengths(path):
    """{packet id: length} from an the consumer recvpackets.txt ('<hex id> <len> ...' per line).
    Lengths that can't frame a packet (0, 1, < -1) are skipped, so the id counts as unknown
    instead of stalling a tokenizer on a zero-length packet. Raises OSError if unreadable."""
    lengths = {}
    with open(path) as f:
        for line in f:
            p = line.split()
            if len(p) < 2:
                continue
            try:
                pid, L = int(p[0], 16), int(p[1])
            except ValueError:
                continue
            if L == VAR or L >= 2:
                lengths[pid] = L
    return lengths


def packet_len(lengths, buf, pos):
    """Length of the packet starting at buf[pos] (needs pos + 2 <= len(buf)).
    None = unknown id or impossible length; NEED_MORE = a variable length isn't in buf yet."""
    pid = buf[pos] | (buf[pos + 1] << 8)
    L = lengths.get(pid)
    if L == VAR:
        if pos + 4 > len(buf):
            return NEED_MORE
        L = buf[pos + 2] | (buf[pos + 3] << 8)
        return L if L >= 4 else None
    return L if L is not None and L >= 2 else None


class WireFilter:
    """Per-connection packet tokenizer for --wire mode (the default).

    uaRO's server->client stream is CLEARTEXT on the wire except the bodies of a few packets
    (09fd actor_moved, 09ff actor_exists: they are encrypted; id+length stay clear). So we
    feed the wire bytes and only cut out those garbage-bodied packets (plus --drop-ids), whole,
    so the consumer's tokenizer stays aligned. Keyed by TCP connection (agent's local port), so a
    partial packet left on a closed connection never bleeds into the next one. The first
    4 bytes of a connection with an unknown id are the bare account ID the char server sends
    before received_characters - passed through for the consumer. Any other unknown id switches
    that connection to pass-through (fail open: the consumer resyncs better than we would)."""

    def __init__(self, lengths, drop):
        self.L, self.drop = lengths, drop
        self.conns = {}                                # conn -> {'buf', 'start', 'raw', 'off'}
        self.on_packet = None                          # callback(conn, pid, stream_offset, packet)

    def carried(self, conn):
        """Bytes of a partial packet waiting for the next chunk of this connection."""
        st = self.conns.get(conn)
        return len(st['buf']) if st else 0

    def push(self, conn, data):
        """Bytes to feed for this chunk (encrypted-body packets dropped)."""
        return b''.join(it[1] for it in self.push_items(conn, data) if it[0] == 'B')

    def push_items(self, conn, data, enc=()):
        """Ordered feed items for this chunk: ('B', bytes) to feed as is, or ('E', pid, packet,
        stream_offset) for a packet in `enc` (encrypted body) the caller must fill in from
        the client's decrypted copy (ActorDecrypt) or drop."""
        st = self.conns.setdefault(conn, {'buf': b'', 'start': True, 'raw': False, 'off': 0})
        if st['raw']:
            return [('B', data)]
        buf, out, pos, items = st['buf'] + data, bytearray(), 0, []
        while pos + 2 <= len(buf):
            L = packet_len(self.L, buf, pos)
            if L == NEED_MORE:
                break
            if L is None:
                if st['start'] and pos == 0:
                    if len(buf) < 4:
                        break
                    out += buf[:4]; pos = 4; st['start'] = False   # bare account ID
                    continue
                pid = buf[pos] | (buf[pos + 1] << 8)
                print(f'[wire] conn {conn}: unknown id 0x{pid:04x} - passing this connection through raw')
                st['raw'] = True
                out += buf[pos:]; pos = len(buf)
                break
            if pos + L > len(buf):
                break
            st['start'] = False
            pid = buf[pos] | (buf[pos + 1] << 8)
            pkt = buf[pos:pos + L]
            if self.on_packet:
                self.on_packet(conn, pid, st['off'] + pos, pkt)
            if pid in enc:
                if out:
                    items.append(('B', bytes(out))); out = bytearray()
                items.append(('E', pid, pkt, st['off'] + pos))
            elif pid not in self.drop:
                out += pkt
            pos += L
        st['off'] += pos
        st['buf'] = buf[pos:]
        if out:
            items.append(('B', bytes(out)))
        return items


def pack_move(x, y, d=0):
    """The 3-byte packed body of a client move (035f) for destination (x, y) and direction d."""
    return bytes(((x >> 2) & 0xff,
                  ((x & 3) << 6) | ((y >> 4) & 0x3f),
                  ((y & 0xf) << 4) | (d & 0xf)))


def unpack_move(body3):
    """Inverse of pack_move: (x, y, d) from the 3-byte packed body of a client move (035f)."""
    b = bytes(body3)
    if len(b) < 3:
        raise ValueError('035f body needs 3 bytes')
    return (b[0] << 2) | (b[1] >> 6), ((b[1] & 0x3f) << 4) | (b[2] >> 4), b[2] & 0xf


def unpack_pos2(b):
    """(src_x, src_y, dst_x, dst_y) from the 6-byte MoveData2 (the RO WBUFPOS2 packing)."""
    sx = (b[0] << 2) | (b[1] >> 6)
    sy = ((b[1] & 0x3f) << 4) | (b[2] >> 4)
    dx = ((b[2] & 0x0f) << 6) | (b[3] >> 2)
    dy = ((b[3] & 0x03) << 8) | b[4]
    return sx, sy, dx, dy


class MoveTracker:
    """Decodes the server's 0087 move confirmation and, when a walk request is known (tests/offline
    replays set it via on_walk), cross-checks it. In live captures the client's own 035f is not
    recovered, so MOVE-CHECKs carry no request and the 0087 destination is the walk destination."""

    def __init__(self, log=None):
        self.log = log
        self.last_walk = None                      # (x, y) of the most recent recovered 035f
        self.stats = collections.Counter()

    def on_walk(self, x, y, d=0):
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
