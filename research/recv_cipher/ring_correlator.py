"""Correlate encrypted actor packets from recv with validated plaintext in the Wine recv ring.

Read-only /proc/PID/mem; no ptrace, CEserver debugger or client writes.
Never accept ID/length alone as evidence: require the actor body to validate and
unmodified neighbouring packet bytes to agree.
"""
import json
import hashlib
import os
import queue
import threading
import time

from relay.actors import valid_actor, copy_validation
from actor_adapter import ActorCoreAdapter
from relay.memory import ProcessMemory, regions, MAX_REGION
from relay.packets import load_lengths, packet_len


def actor_candidate(chunk):
    """A whole encrypted 09FD/09FF at the head, followed by clear context."""
    if len(chunk) < 16 or chunk[:2] not in (b"\xfd\x09", b"\xff\x09", b"\x29\x02"):
        return None
    length = 15 if chunk[:2] == b"\x29\x02" else int.from_bytes(chunk[2:4], "little")
    if not 15 <= length <= 1024 or len(chunk) < length + 8:
        return None
    return chunk[:length], chunk[length:length + min(32, len(chunk)-length)]


def matching_copy(buf, addr, wire, context, reasons=None):
    """Locate a *decrypted* copy with exact header and following clear bytes."""
    length = len(wire)
    header = wire[:6] if wire[:2] == b"\x29\x02" else wire[:4]
    at = buf.find(header)
    if at < 0 and reasons is not None:
        reasons['header_absent'] += 1
    while at >= 0:
        end = at + length
        if end + len(context) > len(buf):
            reason = 'outside_buffer'
        elif buf[end:end + len(context)] != context:
            reason = 'following_context_mismatch'
        elif buf[at+4:end] == wire[4:]:
            reason = 'unchanged_ciphertext'
        elif wire[:2] != b"\x29\x02" and not valid_actor(buf[at:end]):
            reason = 'invalid_actor_body'
        else:
            return addr + at, bytes(buf[at:end])
        if reasons is not None:
            reasons[reason] += 1
        at = buf.find(header, at + 1)
    return None


class RingCorrelator:
    def __init__(self, pid, emit, max_candidates=64):
        self.pid = pid
        self.emit = emit
        self.max_candidates = max_candidates
        self.pending = queue.Queue(maxsize=128)
        self.lengths = load_lengths(__import__("pathlib").Path(__file__).resolve().parents[2] / "data/uaro_recvpackets.txt")
        self.streams = {}
        self.awaiting = []
        self.resolved = set()
        self.snapshot_lock = threading.Lock()
        self.stats = __import__("collections").Counter()
        self.thread = None
        self.accepted = 0
        # Optional hint from a VERIFIED match in the SAME client process.
        # It is not proof: _search checks full plaintext and context each time.
        hint = os.environ.get('RECV_PROBE_RING_HINT', '').strip()
        self.ring = int(hint, 0) if hint else None
        self.closed = False
        self.on_verified = None
        self.memory = None
        self.diagnose = None
        self.mapping_cache = None
        self.actor_adapter = None

    def start(self):
        self.memory = ProcessMemory(self.pid)
        self.actor_adapter = ActorCoreAdapter(self.pid)
        self.actor_adapter.core.on_ring = self._production_ring_verified
        self.thread = threading.Thread(target=self._run, daemon=True, name="ring-correlator")
        self.thread.start()

    def _mapping_for_ring(self, base):
        try:
            with open(f'/proc/{self.pid}/maps') as maps:
                return next((fields for line in maps
                             if (fields := line.split()) and
                             int(fields[0].split('-')[0], 16) <= base
                             < int(fields[0].split('-')[1], 16)), None)
        except (OSError, ValueError):
            return None

    def _production_ring_verified(self, base):
        """Accept only a ring verified by the production ActorDecrypt core.

        Called by the core's background quick discovery, not the recv hook.
        """
        # Research-only gate: a plaintext recv ring must not resolve inside
        # executable code. Quick discovery can otherwise lock onto coincidental
        # actor-like bytes in a writable/executable PE mapping.
        mapping = self._mapping_for_ring(base)
        if (mapping is None or 'r' not in mapping[1] or 'w' not in mapping[1]
                or 'x' in mapping[1]
                or base + 0x4040 > int(mapping[0].split('-')[1], 16)):
            self.stats['production_quick_rejected_mapping'] += 1
            self.emit({'kind': 'ring_discovery_rejected', 'reason': 'unsafe_mapping',
                       'mapping_permissions': mapping[1] if mapping else None})
            # This callback is invoked while the core holds its discovery lock;
            # clear only the invalid speculative ring to allow later attempts.
            if self.actor_adapter is not None:
                core = self.actor_adapter.core
                if getattr(core, 'base', None) == base:
                    core.base = None
                    core.hi = None
                    core.region = None
            return
        self.ring = base
        self.stats['production_quick_discovered'] += 1
        self.emit({'kind':'ring_discovered','base':hex(base),
                   'method':'ActorDecrypt.start_quick_discover'})
        if self.on_verified is not None:
            self.on_verified(base)

    def receive(self, record):
        """Frame the TCP stream; collect targets at *any* packet offset."""
        if self.closed:
            return
        fd = record.get("fd")
        payload = record.get("payload")
        if not payload or len(payload) != 2 * record.get("bytes", 0):
            self.stats["truncated_recv"] += 1
            self.streams.pop(fd, None)
            return
        try:
            chunk = bytes.fromhex(payload)
        except ValueError:
            self.stats["invalid_hex"] += 1
            self.streams.pop(fd, None)
            return
        stream = self.streams.setdefault(fd, bytearray())
        carried = len(stream)
        if self.actor_adapter is not None:
            cstart, d = self.actor_adapter.note_chunk(fd, chunk, carried)
        else:
            cstart, d = 0, 0x40
        stream.extend(chunk)
        offset = 0
        discovery_items = []
        while len(stream) - offset >= 2:
            pid = stream[offset] | (stream[offset + 1] << 8)
            size = packet_len(self.lengths, stream, offset)
            if size is None:
                self.stats["unknown_id"] += 1
                stream.clear()
                break
            if not size or len(stream) - offset < size:
                break
            if pid in (0x09fd, 0x09ff, 0x0229) and len(stream)-offset < size+8:
                break  # retain complete packet until following context arrives
            self.stats["framed_total"] += 1
            if (self.actor_adapter is not None and carried == 0
                    and pid in self.actor_adapter.core.ENC
                    and offset + size <= len(chunk)):
                # Match the tuple layout used in production wire_feed:
                # (kind, packet_id, bytes, absolute_stream_offset).
                discovery_items.append(('E', pid, bytes(stream[offset:offset+size]), cstart+offset))
            if pid in (0x09fd, 0x09ff, 0x0229):
                self.stats[f"wire_{pid:04X}"] += 1
                if self.accepted < self.max_candidates and len(stream)-offset >= size+8:
                    self.accepted += 1
                    packet = bytes(stream[offset:offset+size])
                    absolute_off = (self.actor_adapter.core.coff[fd] - len(stream) + offset
                                    if self.actor_adapter is not None else offset)
                    if self.actor_adapter is not None:
                        self.actor_adapter.note_packet(fd, absolute_off, packet)
                    item = {"chunk": bytes(stream[offset:offset+size+min(32,len(stream)-offset-size)]),
                            "length": size, "off": absolute_off, "cstart": cstart, "d": d,
                            "event_ms": record.get("ms"), "recv_seq": record.get("recv_seq"),
                            "fd": fd, "tid": record.get("tid"),
                            "queued_monotonic": time.monotonic()}
                    item['candidate_id'] = self.accepted
                    self.emit({'kind':'ring_candidate', 'candidate_id':item['candidate_id'],
                               'recv_seq':item['recv_seq'], 'fd':fd, 'tid':item['tid'],
                               'event_ms':item['event_ms'], 'packet_id':f'{pid:04x}',
                               'slot_offset':d + absolute_off - cstart, 'length':size})
                    with self.snapshot_lock:
                        self.awaiting.append(item)
                    try:
                        self.pending.put_nowait(item)
                    except queue.Full:
                        self.stats["queue_drops"] += 1
                else:
                    self.stats["candidate_no_context_or_cap"] += 1
            offset += size
        if discovery_items and self.ring is None and self.actor_adapter is not None:
            self.actor_adapter.core.start_quick_discover(
                fd, chunk, discovery_items, cstart)
            self.stats['production_quick_requested'] += 1
        if offset:
            del stream[:offset]

    def _slot_diagnostic(self, item, data, base, source):
        """Metadata-only diagnosis; never record actor payload, name or GID.

        The predicted location is derived from the same chunk/offset arithmetic
        as production. Snapshot bytes are only observations, never acceptance.
        """
        core = self.actor_adapter.core if self.actor_adapter is not None else None
        if core is None or base is None:
            return {'source': source, 'state': 'no_ring_base'}
        offset = item['d'] + item['off'] - item['cstart']
        size = item['length']
        out = {'source': source, 'offset': offset, 'size': size}
        if offset < 0 or offset + size > len(data):
            out['state'] = 'outside_capture'
            return out
        current = bytes(data[offset:offset+size]); wire = item['chunk'][:size]
        checks = copy_validation(wire, current)
        out.update(state='candidate_structurally_valid' if checks['accepted'] else 'invalid_or_stale',
                   sha256_prefix=hashlib.sha256(current).hexdigest()[:16],
                   matches_wire=current == wire,
                   header_ok=checks['header_match'],
                   name_ok=checks['name_format_ok'],
                   walk_speed_ok=checks['walk_speed_ok'],
                   object_type_ok=checks['object_type_ok'],
                   changed=checks['body_changed'])
        return out

    def _alternative_offsets(self, item, data):
        """Inspect SAME snapshot for plausible actor copies at other offsets.

        Diagnostic only: structural validity does not prove packet provenance.
        A short candidate list avoids exposing actor contents and heavy scans.
        """
        wire = item['chunk'][:item['length']]
        header = wire[:2] if wire[:2] in (b'\x29\x02', b'\x3f\x04', b'\x83\x09') else wire[:4]
        expected = item['d'] + item['off'] - item['cstart']
        positions = []
        pos = data.find(header)
        total_headers = 0
        valid_count = 0
        while pos >= 0:
            total_headers += 1
            if pos + len(wire) <= len(data) and copy_validation(wire, bytes(data[pos:pos+len(wire)]))['accepted']:
                valid_count += 1
                if len(positions) < 8:
                    positions.append({'offset':pos,'delta':pos-expected})
            pos = data.find(header,pos+1)
        return {'expected_offset':expected,'header_hits':total_headers,
                'structurally_valid_at_other_offsets':valid_count,
                'candidate_offsets':positions}

    def snapshot(self, record, data):
        """Capture the previous decrypted ring at the next recv entry, before overwrite."""
        if not data or record.get('fd') not in self.streams:
            return
        try:
            base = int(record['base'], 16)
        except (KeyError, TypeError, ValueError):
            self.stats['invalid_snapshot_base'] += 1
            return
        with self.snapshot_lock:
            waiting = list(self.awaiting)
        for item in waiting:
            cid = item['candidate_id']
            if item['fd'] != record['fd'] or cid in self.resolved:
                continue
            candidate = actor_candidate(item['chunk'])
            if candidate is None:
                continue
            wire, context = candidate
            result = (self.actor_adapter.find(data, base, item) if self.actor_adapter is not None
                      else matching_copy(data, base, wire, context, self.diagnose))
            if result is None:
                if item.get('slot_diag_count', 0) < 3:
                    item['slot_diag_count'] = item.get('slot_diag_count', 0) + 1
                    self.emit({'kind':'ring_slot_snapshot_diagnostic', 'candidate_id':cid,
                               'snapshot_seq':record.get('seq'),
                               'detail':self._slot_diagnostic(item, data, base, 'before_next_recv'),
                               'alternative_offsets':self._alternative_offsets(item, data)})
                continue
            slot, plain = result
            with self.snapshot_lock:
                if cid in self.resolved:
                    continue
                self.resolved.add(cid)
                self.awaiting = [x for x in self.awaiting if x['candidate_id'] != cid]
            self.stats['snapshot_matched'] += 1
            self.emit({'kind':'ring_snapshot_match','candidate_id':cid,'fd':item['fd'],
                       'packet_id':wire[:2].hex(),'length':len(wire),
                       'slot':hex(slot),'ring_base':hex(base),
                       'wire':wire.hex(),'plaintext':plain.hex(),
                       'snapshot_seq':record.get('seq')})

    def replay_frames(self, frames):
        """After collection, reconcile pending candidates against bounded 1 ms ring copies."""
        with self.snapshot_lock:
            waiting = list(self.awaiting)
        for item in waiting:
            cid = item['candidate_id']
            with self.snapshot_lock:
                if cid in self.resolved:
                    continue
            candidate = actor_candidate(item['chunk'])
            if candidate is None:
                continue
            wire, context = candidate
            for base, sampled_at, data in frames:
                if sampled_at < item.get("queued_monotonic", 0):
                    continue
                result = (self.actor_adapter.find(data, base, item) if self.actor_adapter is not None
                      else matching_copy(data, base, wire, context, self.diagnose))
                if result is None:
                    continue
                slot, plain = result
                with self.snapshot_lock:
                    if cid in self.resolved:
                        break
                    self.resolved.add(cid)
                    self.awaiting = [x for x in self.awaiting if x['candidate_id'] != cid]
                self.stats['replay_matched'] += 1
                self.emit({'kind': 'ring_replay_match', 'candidate_id': cid,
                           'fd': item['fd'], 'packet_id': wire[:2].hex(),
                           'length': len(wire), 'slot': hex(slot),
                           'ring_base': hex(base), 'wire': wire.hex(),
                           'plaintext': plain.hex(), 'sample_monotonic': sampled_at})
                break

    def _probe_region(self, region, wire, context, size, item=None):
        lo, hi, _ = region
        if hi - lo < 0x40 + len(wire) + len(context):
            return None
        buf = self.memory.read(lo, min(size, hi - lo))
        if item is not None and self.actor_adapter is not None:
            return self.actor_adapter.find(buf, lo, item)
        return matching_copy(buf, lo, wire, context, self.diagnose)

    def _search(self, wire, context, item=None):
        # Existing ring base is only a *hint*, and must be reverified every time.
        if self.ring is not None:
            r = self.memory.read(self.ring, 0x20000)
            found = (self.actor_adapter.find(r, self.ring, item)
                     if item is not None and self.actor_adapter is not None
                     else matching_copy(r, self.ring, wire, context, self.diagnose))
            if found:
                return found, self.ring, "verified_ring_hint"
            # A missed copy normally means the ring was overwritten, not moved.
            # Do not block this single-threaded worker with a 2s full-memory scan
            # per packet. Revalidate the hint on the next candidate; never accept
            # an unverified copy. Ring re-discovery remains available when no hint
            # has been established at startup.
            return None, self.ring, "known_ring_miss"
        # Ring discovery is driven by the full recv chunk in receive(), using
        # the production core's asynchronous start_quick_discover. Never scan
        # all writable mappings synchronously on the correlation worker.
        return None, None, 'production_quick_pending'

    def _analyze(self, item):
        """Check current slot quickly; snapshots asynchronously resolve overwritten copies.

        Do not sleep 110 ms per candidate: dense actor bursts may arrive in less
        time than one polling window. Never perform a full-region scan while a
        verified ring hint is available.
        """
        cid = item['candidate_id']
        with self.snapshot_lock:
            if cid in self.resolved:
                return
        wire, context = actor_candidate(item['chunk'])
        if wire is None:
            return
        queued = item.get('queued_monotonic', time.monotonic())
        wait_ms = round((time.monotonic() - queued) * 1000, 1)
        # On a known ring one bounded read is cheap and deterministic. A missed
        # read must not invalidate the ring or trigger synchronous scanning.
        found, base, method = self._search(wire, context, item)
        if not found:
            if base is not None:
                offset = item['d'] + item['off'] - item['cstart']
                if 0 <= offset < 0x20000 and self.memory is not None:
                    live = self.memory.read(base + offset, item['length'])
                    # The helper takes a slice starting at the predicted offset.
                    diag = self._slot_diagnostic(dict(item, d=0, off=0, cstart=0),
                                                 live, base, 'after_recv')
                    self.emit({'kind':'ring_slot_live_diagnostic','candidate_id':cid,
                               'detail':diag})
            self.emit({'kind':'ring_miss','candidate_id':cid,'fd':item['fd'],
                       'packet_id':wire[:2].hex(),'length':len(wire),
                       'method':method,'worker_queue_delay_ms':wait_ms})
            return
        slot, plain = found
        with self.snapshot_lock:
            if cid in self.resolved:
                return
            self.resolved.add(cid)
            self.awaiting = [x for x in self.awaiting if x['candidate_id'] != cid]
        self.ring = base
        if slot - base == 0x40 and self.on_verified is not None:
            self.on_verified(base)
        self.emit({'kind':'ring_match','candidate_id':cid,'fd':item['fd'],
                   'packet_id':wire[:2].hex(),'length':len(wire),
                   'ring_base':hex(base),'slot':hex(slot),'method':method,
                   'worker_queue_delay_ms':wait_ms,
                   'wire':wire.hex(),'plaintext':plain.hex()})

    def _run(self):
        while True:
            item = self.pending.get()
            if item is None:
                self.pending.task_done()
                break
            try:
                self._analyze(item)
            except Exception as e:
                self.emit({"kind": "ring_error", "error": str(e)[:200]})
            finally:
                self.pending.task_done()

    def stop(self):
        self.closed = True
        if self.thread:
            # Preserve queued captures before returning. No new hooks are installed.
            self.pending.put(None)
            self.thread.join(timeout=12)
        self.emit({"kind":"ring_coverage", "stats":dict(self.stats), "remaining_bytes":sum(len(x) for x in self.streams.values())})
        if self.thread is not None and self.thread.is_alive():
            self.emit({"kind":"ring_worker_timeout", "detail":"worker still running"})
        elif self.memory is not None:
            os.close(self.memory.fd)
        if self.actor_adapter is not None:
            self.actor_adapter.close()
