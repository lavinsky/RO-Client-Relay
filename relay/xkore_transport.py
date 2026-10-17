"""The feed to the consumer: XKore framing and a self-healing TCP connection."""
import select
import socket
import threading
import time

from .packet_pipeline import NEED_MORE, packet_len


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
    Optionally, with a length table (`lengths`) server->client bytes first pass through a
    PacketAligner so the consumer only ever sees whole packets (not used by the default wiring,
    which feeds pre-tokenized wire bytes; kept for a raw/aligned stream consumer)."""
    FRAME_MAX = 0xFFFF                                 # 'len' is a 16-bit field

    def __init__(self, host, port, fmt='xkore1', lengths=None, align=True, drop=None,
                 on_connect=None, on_disconnect=None, autostart=True):
        self.host, self.port, self.fmt = host, port, fmt
        self.aligner = PacketAligner(lengths, drop) if (align and lengths) else None
        self.align = self.aligner is not None
        self.sock = None
        self.lock = threading.RLock()                   # guards sock, aligner, counters, dump, _in
        self.sent = self.dropped = 0
        self.dump = None                               # optional file: every framed byte sent (--feed-dump)
        self.on_inbound = None                         # callback(payload, typ) for what the consumer sends
        self.on_connect = on_connect                   # callback() before accepting every session
        self.on_disconnect = on_disconnect             # callback() once per disconnected session
        self.generation = 0
        self._in = b''                                 # reassembly buffer for inbound frames
        self._inbound_paused = False
        self._wake_read, self._wake_write = socket.socketpair()
        self._wake_read.setblocking(False)
        self._wake_write.setblocking(False)
        self._thread = None
        if autostart:
            self.start()

    def __del__(self):
        for name in ('_wake_read', '_wake_write'):
            wake = getattr(self, name, None)
            if wake is not None:
                wake.close()

    def start(self):
        """Start the connector once, after the owner wires session callbacks."""
        with self.lock:
            if self._thread is None:
                self._thread = threading.Thread(target=self._connect_loop, name='relay-connect', daemon=True)
                self._thread.start()

    # ---- connection -------------------------------------------------------------------------
    def _connect_loop(self):
        while True:
            s = self.sock
            if s is None:
                self._connect()
                if self.sock is None:
                    time.sleep(1)
                continue
            if self._inbound_paused:
                self._wait_capacity(s)
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
            self._in = b''
            self._inbound_paused = False
            if self.aligner:
                self.aligner.reset()
            self.generation += 1
            # Keep the new socket unavailable until session state has been reset.
            if self.on_connect is not None:
                try:
                    self.on_connect()
                except Exception as e:
                    print(f'[relay] on_connect error: {e}')
                    s.close()
                    return
            self.sock = s
        print(f'[relay] connected to {self.host}:{self.port} ({self.fmt}{", aligned" if self.align else ""})')

    def _check_dead(self):
        s = self.sock
        if s is None:
            return
        if self._inbound_paused:
            return
        try:
            data = s.recv(0x1000, socket.MSG_DONTWAIT)
            if not data:
                raise ConnectionResetError('peer closed')
            # Observe an already queued EOF before dispatching this chunk.
            try:
                if s.recv(1, socket.MSG_DONTWAIT | socket.MSG_PEEK) == b'':
                    raise ConnectionResetError('peer closed')
            except BlockingIOError:
                pass
            self._inbound(data, s)
            return
        except BlockingIOError:
            return
        except OSError:
            print('[relay] connection dropped; will reconnect')
        self._drop_sock(s)

    def resume_inbound(self):
        """Notify capacity availability without acquiring transport/command locks."""
        try:
            self._wake_write.send(b'\x00')
        except (BlockingIOError, OSError):
            pass  # A queued wakeup already guarantees a retry.

    def _wait_capacity(self, source):
        """Wait for actual readiness or peer shutdown, including EOF behind unread bytes."""
        descriptor = source.fileno()
        poller = select.poll()
        closed = select.POLLRDHUP | select.POLLHUP | select.POLLERR | select.POLLNVAL
        try:
            poller.register(source, closed)
            poller.register(self._wake_read, select.POLLIN)
            events = dict(poller.poll())
        except (OSError, ValueError):
            self._drop_sock(source)
            return
        if events.get(descriptor, 0) & closed:
            self._drop_sock(source)
            return
        if self._wake_read.fileno() in events:
            try:
                while self._wake_read.recv(4096):
                    pass
            except BlockingIOError:
                pass
            self._inbound(b'', source)

    def _inbound(self, data, source=None):
        """Deliver frames transactionally; False retains the complete frame for retry.

        The socket reader stops while paused. At most one maximum-size partial frame
        plus one 4096-byte read is retained; TCP applies pressure to the producer.
        """
        if self.on_inbound is None:
            return
        with self.lock:
            if source is not None and self.sock is not source:
                return
            self._in += data
            generation = getattr(self, 'generation', 0)
            self._inbound_paused = False
            while self._in:
                if self.fmt == 'xkore1':
                    if len(self._in) < 3:
                        break
                    typ = chr(self._in[0])
                    length = int.from_bytes(self._in[1:3], 'little')
                    size = 3 + length
                    if len(self._in) < size:
                        break
                    payload = self._in[3:size]
                else:
                    payload, typ, size = self._in, 'S', len(self._in)
                try:
                    accepted = self.on_inbound(payload, typ)
                except Exception as e:
                    print(f'[relay] inbound handler: {type(e).__name__}: {e}')
                    accepted = None
                if generation != getattr(self, 'generation', 0) or (source is not None and self.sock is not source):
                    break
                if accepted is False:
                    self._inbound_paused = True
                    break
                self._in = self._in[size:]

    def _drop_sock(self, s):
        with self.lock:
            if self.sock is not s:
                return
            self.sock = None
            self._in = b''
            self._inbound_paused = False
            self.resume_inbound()
            if self.aligner:
                self.aligner.reset()
            try:
                s.close()
            except OSError:
                pass
            if self.on_disconnect is not None:
                try:
                    self.on_disconnect()
                except Exception as e:
                    print(f'[relay] on_disconnect error: {e}')

    # ---- feeding ----------------------------------------------------------------------------
    def feed(self, data, generation=None):
        """Feed server bytes only to the session that produced them, when supplied."""
        with self.lock:
            if generation is not None and generation != self.generation:
                self.dropped += len(data)
                return
            if self.aligner:
                if self.sock is None:
                    self.aligner.reset()
                    self.dropped += len(data)
                    return
                data = self.aligner.push(data)
            if data:
                self.send(data, generation=generation)

    def feed_send(self, packet, generation=None):
        """One complete client->server packet as an "S" frame (xkore1 only). Each is already a
        whole packet, so unlike "R" no stream alignment is needed."""
        if self.fmt == 'xkore1' and packet:
            self.send(packet, typ='S', generation=generation)

    def frame(self, data, typ='R'):
        if self.fmt != 'xkore1':
            return data
        tb = typ.encode()
        return b''.join(tb + len(c).to_bytes(2, 'little') + c
                        for c in (data[i:i + self.FRAME_MAX] for i in range(0, len(data), self.FRAME_MAX)))

    def send(self, data, typ='R', generation=None):
        data = self.frame(data, typ)
        with self.lock:
            s = self.sock
            if s is None or (generation is not None and generation != self.generation):
                self.dropped += len(data)
                return
            try:
                s.sendall(data)
            except OSError as e:
                print(f'[relay] consumer gone ({e}); will reconnect')
                self.dropped += len(data)
                self._drop_sock(s)
                return
            self.sent += len(data)
            if self.dump:                              # exact framed bytes the consumer got, for offline replay
                self.dump.write(data)
                self.dump.flush()


class PacketAligner:
    """Cuts an unaligned server->client byte stream at packet boundaries (optional; for a raw
    consumer fed through Relay with a length table).

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
