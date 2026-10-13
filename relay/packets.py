"""Packet boundaries: the length table and the per-connection tokenizer (WireFilter)."""
VAR = -1                                           # length table: variable length, read from bytes 2-3
NEED_MORE = 0                                      # packet_len(): the length isn't readable yet


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
