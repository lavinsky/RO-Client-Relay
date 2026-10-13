"""Send injection: write crafted client->server packets into the client's send queue.

The write-side companion to sendwatch.py, which only *reads* the queue. SendInjector frames a
packet and writes it into the same send-queue block the client builds its 0437/0438 packets in,
so the client transmits it on its next flush. Intended use: a client-trust test against your own
emulator - does the client forward bytes that were planted from outside its own code path?

Locating the block is shared with SendWatch (sendwatch.send_queue_range): the recv-ring heap
block ActorDecrypt verifies, an explicit --send-queue lo-hi, or the per-session fallback. The
writer is memory.ProcessMemoryWriter (/proc/<pid>/mem, no game pause).

Guard rails, because this is the only part of the tool that writes to the game:
  - dry_run defaults to True: by default inject() frames, checks and logs but writes nothing.
  - every write is bounds-checked to land wholly inside the resolved queue block; a packet that
    would fall outside is refused, never clamped.
  - frame() validates the id against the length table, so only well-formed packets are built.
"""
import collections

from .packets import VAR, packet_len


class InjectError(Exception):
    """A packet could not be framed or a target address was out of bounds."""


class SendInjector:
    """Plant a framed client->server packet in the client's send queue.

    queue_range: callable returning (lo, hi, source) for the queue block, or None if not known
                 yet (pass Capture.update_send_watch's resolver, or a lambda over send_queue_range).
    lengths:     the packet.load_lengths table, for framing/validation.
    writer:      memory.ProcessMemoryWriter for this pid.
    """

    def __init__(self, writer, queue_range, lengths, log=None, dry_run=True):
        self.writer, self.queue_range, self.L = writer, queue_range, lengths
        self.log, self.dry_run = log, dry_run
        self.stats = collections.Counter()
        self.next_slot = None                          # sequential queue tail (buf+len), hex str
        self.slots = {}                                # pid -> (addr, length) the client last built it at

    def frame(self, pid, body=b''):
        """A whole packet for id `pid`: [id little-endian][body], sized by the length table.
        Fixed-length id: body is padded with zeros / refused if longer than the slot allows.
        VAR id: [id][total-length little-endian][body]. Unknown id -> InjectError."""
        head = bytes((pid & 0xff, (pid >> 8) & 0xff))
        L = self.L.get(pid)
        if L is None:
            raise InjectError(f'unknown packet id 0x{pid:04x} (not in the length table)')
        if L == VAR:
            total = 4 + len(body)
            return head + bytes((total & 0xff, (total >> 8) & 0xff)) + body
        if len(body) > L - 2:
            raise InjectError(f'0x{pid:04x} body is {len(body)} bytes, max {L - 2} for a {L}-byte packet')
        return head + body + bytes(L - 2 - len(body))  # zero-pad to the fixed length

    def _resolve(self, at):
        """(target_addr, lo, hi) for a write, or raise InjectError. at=None -> block base (lo)."""
        r = self.queue_range()
        if r is None:
            raise InjectError('send-queue block not known yet (no recv ring found; try --send-queue lo-hi)')
        lo, hi = r[0], r[1]
        target = lo if at is None else at
        return target, lo, hi

    def inject(self, packet, at=None):
        """Write `packet` (bytes, e.g. from frame()) into the send queue at absolute address `at`
        (default: block base). Bytes written, or 0 when dropped (dry-run or a failed write).
        Raises InjectError on an unknown block or an out-of-bounds target."""
        target, lo, hi = self._resolve(at)
        if target < lo or target + len(packet) > hi:
            self.stats['out-of-bounds'] += 1
            raise InjectError(f'0x{target:x}+{len(packet)} is outside the queue block '
                              f'0x{lo:x}-0x{hi:x}')
        pid = packet[0] | packet[1] << 8 if len(packet) >= 2 else -1
        if self.dry_run:
            self.stats[f'dry-{pid:04x}'] += 1
            self._log('INJECT-DRY', pid, target, packet)
            return 0
        n = self.writer.write(target, packet)
        self.stats[f'{"ok" if n == len(packet) else "short"}-{pid:04x}'] += 1
        self._log('INJECT' if n == len(packet) else 'INJECT-SHORT', pid, target, packet, n)
        return n

    def inject_id(self, pid, body=b'', at=None):
        """frame(pid, body) then inject() - for crafting a packet from an id + body."""
        return self.inject(self.frame(pid, body), at)

    def inject_stream(self, payload):
        """Inject a whole packet handed over by the consumer, as-is (no framing - it is already one
        complete client->server packet). If the client has a known slot for this id (the exact
        buf+len it last built that packet at, learned from SEND), write THERE, sized to the client's
        own length - the 'right place'. Otherwise fall back to the sequential queue tail / block
        base. Returns bytes written (0 on dry-run)."""
        pid = payload[0] | payload[1] << 8 if len(payload) >= 2 else -1
        slot = self.slots.get(pid)
        if slot is not None:
            return self._inject_slot(pid, payload, slot)
        at = int(self.next_slot, 16) if self.next_slot else None
        return self.inject(payload, at)

    def _inject_slot(self, pid, payload, slot):
        """Write `payload` at the client's own slot for this id, sized to the length the client uses
        there (pad/truncate). Bounds-checked against the memory region, not the queue block, since a
        per-id slot (e.g. 0x035f's staging slot) can live outside it."""
        addr, length = slot
        pkt = (payload[:length] + bytes(length)) [:length]   # size to the client's own length
        if not self._region_ok(addr, len(pkt)):
            self.stats['slot-unmapped'] += 1
            raise InjectError(f'0x{pid:04x} slot 0x{addr:x}+{len(pkt)} is not in a writable region')
        if self.dry_run:
            self.stats[f'dry-{pid:04x}'] += 1
            self._log('INJECT-DRY', pid, addr, pkt)
            return 0
        n = self.writer.write(addr, pkt)
        self.stats[f'{"ok" if n == len(pkt) else "short"}-{pid:04x}'] += 1
        self._log('INJECT', pid, addr, pkt, n)
        return n

    def _region_ok(self, addr, n):
        """[addr, addr+n) lies wholly inside one writable mapping of the target process."""
        from .memory import regions
        try:
            return any(lo <= addr and addr + n <= hi for lo, hi, _ in regions(self.writer.pid))
        except OSError:
            return False

    def on_send(self, m):
        """Follow the agent's SEND messages: `next_slot` tracks the sequential queue tail (buf+len)
        and `slots[id]` records the exact slot+len the client last built each id at, so a matching
        consumer packet can be placed at the client's own slot for that id."""
        buf = m.get('buf')
        if buf is None:
            return
        addr, length = int(buf, 16), m.get('len', 0)
        self.next_slot = hex(addr + length)
        C = m.get('C') or ''
        if len(C) >= 4:                                # id from the first 2 bytes (little-endian)
            self.slots[int(C[0:2], 16) | int(C[2:4], 16) << 8] = (addr, length)

    def _log(self, tag, pid, target, packet, n=None):
        if self.log is None:
            return
        rec = {'tag': tag, 'id': f'{pid:04x}', 'at': hex(target), 'len': len(packet),
               'P': packet.hex()}
        if n is not None:
            rec['written'] = n
        self.log.write(rec)
