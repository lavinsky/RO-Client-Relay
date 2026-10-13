"""The feed to the consumer: XKore framing and a self-healing TCP connection."""
import select
import socket
import threading
import time

from .packets import NEED_MORE, packet_len


class Relay:
    """Feeds packets to a local TCP consumer (the consumer's XKore 1 listener).

    Two framings:
    - 'xkore1' (default): each chunk is wrapped as one or more X-Kore frames
      `typ + pack("<H", len) + payload`, typ "R" = server->client, "S" = client->server.
      the consumer's Network::XKore::recv() parses exactly this. the consumer makes NO server
      connection of its own in XKore 1; what it sends back to us is read and discarded by
      default (observation only), unless an `on_inbound` handler is attached (--inject), which
      drops those 'S' packets into the client's send queue so the client transmits them.
    - 'raw': server->client bytes with no framing (for a plain stream consumer).

    Connects as a client to host:port; a background thread keeps (re)connecting and drops a
    peer that closed. While nothing listens, bytes are dropped rather than buffered unbounded.
    With a length table (`lengths`, legacy --no-wire path) server->client bytes first pass
    through a PacketAligner so the consumer only ever sees whole packets."""
    FRAME_MAX = 0xFFFF                                 # 'len' is a 16-bit field

    def __init__(self, host, port, fmt='xkore1', lengths=None, align=True, drop=None):
        self.host, self.port, self.fmt = host, port, fmt
        self.aligner = PacketAligner(lengths, drop) if (align and lengths) else None
        self.align = self.aligner is not None
        self.sock = None
        self.lock = threading.Lock()                   # guards sock, aligner, counters, dump, _in
        self.sent = self.dropped = 0
        self.dump = None                               # optional file: every framed byte sent (--feed-dump)
        self.on_inbound = None                         # callback(payload, typ) for what the consumer sends
        self._in = b''                                 # reassembly buffer for inbound frames
        threading.Thread(target=self._connect_loop, name='relay-connect', daemon=True).start()

    # ---- connection -------------------------------------------------------------------------
    def _connect_loop(self):
        while True:
            s = self.sock
            if s is None:
                self._connect()
                time.sleep(1)
                continue
            try:                                       # wake as soon as the consumer sends (or closes),
                ready = select.select([s], [], [], 1.0)[0]   # so inbound frames aren't held up to 1 s
            except (OSError, ValueError):              # closed under us by send(): drop it below
                ready = [s]
            if ready:
                self._check_dead()                     # drain the consumer->us; drop a closed peer

    def _connect(self):
        try:
            s = socket.create_connection((self.host, self.port), timeout=2)
        except OSError:
            return
        # Back to blocking: a socket left in timeout mode makes recv(MSG_DONTWAIT) raise
        # TimeoutError on an idle peer, which _check_dead would read as "closed" every 2 s.
        s.settimeout(None)
        s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        with self.lock:
            self.sock = s
            self._in = b''                             # a new consumer starts from a fresh frame boundary
            if self.aligner:
                self.aligner.reset()                   # each consumer starts from a fresh boundary
        print(f'[relay] connected to {self.host}:{self.port} ({self.fmt}{", aligned" if self.align else ""})')

    def _check_dead(self):
        s = self.sock
        if s is None:
            return
        data = b''
        try:
            while True:                                # drain the consumer->us
                d = s.recv(0x1000, socket.MSG_DONTWAIT)
                if d == b'':
                    raise ConnectionResetError('peer closed')
                data += d
        except BlockingIOError:
            if data:                                   # nothing more waiting = still alive
                self._inbound(data)                    # inject it, or discard if no handler
            return
        except OSError:
            print('[relay] connection dropped; will reconnect')
        self._drop_sock(s)

    def _inbound(self, data):
        """The consumer's reply bytes. With no on_inbound handler they are discarded (observation
        only, the original behaviour). With one, whole frames are handed over as (payload, typ):
        xkore1 deframes typ+len+payload ('S' = a client->server packet to inject); raw hands the
        bytes over as one 'S' payload."""
        if self.on_inbound is None:
            return
        with self.lock:                                # _deframe mutates _in; run the handler outside
            self._in += data
            frames = self._deframe()
        for payload, typ in frames:
            try:
                self.on_inbound(payload, typ)
            except Exception as e:
                print(f'[relay] inbound handler: {type(e).__name__}: {e}')

    def _deframe(self):
        """Whole frames consumed from self._in as [(payload, typ)]; a partial frame stays buffered."""
        if self.fmt != 'xkore1':
            d, self._in = self._in, b''
            return [(d, 'S')] if d else []
        out, buf, pos = [], self._in, 0
        while pos + 3 <= len(buf):
            typ, ln = chr(buf[pos]), buf[pos + 1] | buf[pos + 2] << 8
            if pos + 3 + ln > len(buf):
                break                                  # rest of this frame hasn't arrived yet
            out.append((bytes(buf[pos + 3:pos + 3 + ln]), typ))
            pos += 3 + ln
        self._in = buf[pos:]
        return out

    def _drop_sock(self, s):
        try:
            s.close()
        except OSError:
            pass
        with self.lock:
            if self.sock is s:
                self.sock = None

    # ---- feeding ----------------------------------------------------------------------------
    def feed(self, data):
        """Server->client bytes ("R"). Through the aligner when there is one."""
        if self.aligner:
            with self.lock:
                if self.sock is None:                  # nothing listening: drop, re-align later
                    self.aligner.reset()
                    self.dropped += len(data)
                    return
                data = self.aligner.push(data)
        if data:
            self.send(data)

    def feed_send(self, packet):
        """One complete client->server packet as an "S" frame (xkore1 only). Each is already a
        whole packet, so unlike "R" no stream alignment is needed."""
        if self.fmt == 'xkore1' and packet:
            self.send(packet, typ='S')

    def frame(self, data, typ='R'):
        if self.fmt != 'xkore1':
            return data
        tb = typ.encode()
        return b''.join(tb + len(c).to_bytes(2, 'little') + c
                        for c in (data[i:i + self.FRAME_MAX] for i in range(0, len(data), self.FRAME_MAX)))

    def send(self, data, typ='R'):
        data = self.frame(data, typ)
        with self.lock:
            s = self.sock
            if s is None:
                self.dropped += len(data)
                return
            try:
                s.sendall(data)
            except OSError as e:
                print(f'[relay] consumer gone ({e}); will reconnect')
                self.dropped += len(data)
                try:
                    s.close()
                except OSError:
                    pass
                self.sock = None
                return
            self.sent += len(data)
            if self.dump:                              # exact framed bytes the consumer got, for offline replay
                self.dump.write(data)
                self.dump.flush()


class PacketAligner:
    """Legacy (--no-wire): cuts an unaligned server->client byte stream at packet boundaries.

    Holds bytes until it finds an offset from which several packets in a row tokenize, then
    emits only whole packets (minus `drop` ids) and keeps the trailing partial one. An unknown
    id makes it hunt for the next boundary. Not thread-safe: Relay calls it under its lock."""
    ACC_MAX = 0x40000                                  # cap the buffer while hunting a boundary

    def __init__(self, lengths, drop=None):
        self.lengths = lengths
        self.drop = set(drop or ())
        self.reset()

    def reset(self):
        self.acc = b''
        self.aligned = False

    def find_alignment(self, buf, need=4, scan=0x4000):
        """Smallest offset from which >= `need` consecutive packets tokenize, else None."""
        for off in range(min(len(buf), scan)):
            n, pos = 0, off
            while n < need and pos + 2 <= len(buf):
                L = packet_len(self.lengths, buf, pos)
                if L == NEED_MORE:
                    return None                        # need more data to judge this candidate
                if L is None:
                    break
                if pos + L > len(buf):
                    return None
                pos += L
                n += 1
            if n >= need:
                return off
        return None

    def push(self, data):
        """Bytes ready to emit after adding `data`."""
        self.acc += data
        if not self.aligned:
            if len(self.acc) > self.ACC_MAX:
                self.acc = self.acc[-self.ACC_MAX:]
            off = self.find_alignment(self.acc)
            if off is None:
                return b''
            self.acc = self.acc[off:]
            self.aligned = True
        emit, pos, buf = bytearray(), 0, self.acc
        while pos + 2 <= len(buf):
            L = packet_len(self.lengths, buf, pos)
            if L == NEED_MORE:
                break
            if L is None:                              # unknown id -> re-sync past it
                off = self.find_alignment(buf[pos:])
                if off is None:
                    self.aligned = False               # keep hunting (capped) on the next push
                    break
                pos += off
                continue
            if pos + L > len(buf):
                break
            pid = buf[pos] | (buf[pos + 1] << 8)
            if pid not in self.drop:                   # drop whole packet (stays byte-aligned)
                emit += buf[pos:pos + L]
            pos += L
        self.acc = buf[pos:]
        return bytes(emit)
