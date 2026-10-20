"""Offline verification for bounded wire->ring correlation."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from ring_correlator import actor_candidate, matching_copy, RingCorrelator
from relay.packets import load_lengths


def make_pair():
    wire = bytearray(b"\xfd\x09\x72\x00" + b"\x83" * 110)
    clear = bytearray(wire)
    clear[4] = 1
    clear[13:15] = (150).to_bytes(2, "little")
    clear[-24:] = b"Nearby Player\x00" + b"\x00" * 10
    context = bytes.fromhex("d70163781f0007f100000000000000")
    return bytes(wire), bytes(clear), context


def test_accepts_verified_changed_body():
    wire, plain, tail = make_pair()
    assert actor_candidate(wire + tail) == (wire, tail)
    assert matching_copy(b"z" * 64 + plain + tail, 0x100000, wire, tail) == (0x100040, plain)


def test_rejects_false_positives():
    wire, plain, tail = make_pair()
    assert matching_copy(b"z" * 64 + wire + tail, 0, wire, tail) is None
    assert matching_copy(b"z" * 64 + plain + b"x" * len(tail), 0, wire, tail) is None
    corrupted = bytearray(plain)
    corrupted[13:15] = (65535).to_bytes(2, "little")
    assert matching_copy(b"z" * 64 + corrupted + tail, 0, wire, tail) is None
    assert actor_candidate(wire) is None
    assert actor_candidate(b"\xfd\x09\x03\x00" + b"a" * 20) is None


def test_stream_detects_interior_and_fragmented():
    probe = RingCorrelator(pid=0, emit=lambda event: None, max_candidates=10)
    packet = b'\x29\x02' + b'A' * 13
    plain = b'\x80\x00' + b'B' * 5
    tail = b'\x80\x00' + b'C' * 5
    stream = plain + packet + tail + tail
    for seg in (stream[:12], stream[12:23], stream[23:]):
        probe.receive({'kind':'recv','fd':194,'bytes':len(seg),'payload':seg.hex()})
    assert probe.stats['wire_0229'] == 1, probe.stats
    item = probe.pending.get_nowait()
    assert item['chunk'].startswith(packet), item
    assert len(item['chunk']) >= 23


def test_slot_diagnostic_distinguishes_valid_and_wrong_header():
    probe = RingCorrelator(pid=0, emit=lambda event: None)
    wire, plain, context = make_pair()
    item = {'chunk': wire + context, 'length': len(wire),
            'd': 0x40, 'off': 0, 'cstart': 0}
    probe.actor_adapter = type('Adapter', (), {'core': object()})()
    good = probe._slot_diagnostic(item, b'z' * 0x40 + plain + context,
                                  0x100000, 'test')
    assert good['state'] == 'candidate_structurally_valid', good
    bad = probe._slot_diagnostic(item, b'z' * 0x40 + b'x' * len(plain),
                                 0x100000, 'test')
    assert bad['state'] == 'invalid_or_stale' and not bad['header_ok'], bad
    assert 'plaintext' not in good and 'gid' not in good and 'name' not in good


def test_production_quick_discovery_receives_full_chunk():
    events = []
    probe = RingCorrelator(pid=0, emit=events.append, max_candidates=10)
    calls = []
    class Core:
        ENC = (0x09fd, 0x09ff, 0x0229, 0x043f, 0x0983)
        coff = {42: 0}
        def start_quick_discover(self, fd, chunk, items, start):
            calls.append((fd, chunk, items, start))
    class Adapter:
        core = Core()
        def note_chunk(self, fd, chunk, carried):
            self.core.coff[fd] += len(chunk)
            return 0, 0x40
        def note_packet(self, fd, off, packet):
            pass
    probe.actor_adapter = Adapter()
    wire, _, context = make_pair()
    tail = b'\x80\x00\x00\x00\x00\x00\x00\x00'
    chunk = wire + context + tail
    probe.receive({'fd':42,'bytes':len(chunk),'payload':chunk.hex()})
    assert len(calls) == 1, calls
    fd, source, items, start = calls[0]
    assert (fd, source, start) == (42, chunk, 0)
    assert items == [('E', 0x09fd, wire, 0)], items
    assert probe._search(wire, context)[2] == 'production_quick_pending'
    probe.on_verified = lambda base: events.append({'kind':'verified_callback','base':base})
    probe._mapping_for_ring = lambda base: ['12340000-12400000', 'rw-p']
    probe._production_ring_verified(0x12340000)
    assert probe.ring == 0x12340000
    assert any(e.get('kind') == 'verified_callback' for e in events)



def test_quick_discovery_rejects_executable_mapping():
    events = []
    probe = RingCorrelator(pid=0, emit=events.append)
    class Core:
        base = 0x66b20d
        hi = 0x1607000
        region = (base, hi)
    core = Core()
    probe.actor_adapter = type('Adapter', (), {'core':core})()
    probe._mapping_for_ring = lambda base: ['00401000-01607000', 'rwxp']
    probe._production_ring_verified(core.base)
    assert probe.ring is None
    assert core.base is None
    assert any(e.get('kind') == 'ring_discovery_rejected' for e in events)

def test_snapshot_match_and_no_duplicate():
    events = []
    probe = RingCorrelator(pid=0, emit=events.append, max_candidates=10)
    wire, plain, context = make_pair()
    probe.receive({'kind': 'recv', 'fd': 42, 'bytes': len(wire + context),
                   'payload': (wire + context).hex()})
    assert len(probe.awaiting) == 1
    record = {'fd': 42, 'base': '0x100000', 'seq': 1}
    probe.snapshot({'fd': 43, 'base': '0x100000', 'seq': 0}, b'z' * 64 + plain + context)
    assert not [e for e in events if e['kind'].endswith('_match')]
    probe.snapshot(record, b'z' * 64 + plain + b'x' * len(context))
    assert not [e for e in events if e['kind'].endswith('_match')]
    events.clear()
    probe.snapshot(record, b'z' * 64 + plain + context)
    assert len(events) == 1, events
    assert events[0]['kind'] == 'ring_snapshot_match'
    assert events[0]['plaintext'] == plain.hex()
    assert events[0]['candidate_id'] == 1
    probe.snapshot(record, b'z' * 64 + plain + context)
    assert len(events) == 1, 'snapshot duplicated an already resolved packet'
    assert not probe.awaiting


def test_snapshot_rejects_unchanged_wire():
    events = []
    probe = RingCorrelator(pid=0, emit=events.append)
    wire, plain, context = make_pair()
    probe.receive({'kind': 'recv', 'fd': 5, 'bytes': len(wire + context),
                   'payload': (wire + context).hex()})
    probe.snapshot({'fd': 5, 'base': '0x100000'}, b'z' * 64 + wire + context)
    assert not [e for e in events if e['kind'].endswith('_match')]
    assert len(probe.awaiting) == 1


def test_snapshot_invalid_metadata_is_safe():
    events = []
    probe = RingCorrelator(pid=0, emit=events.append)
    wire, plain, context = make_pair()
    probe.receive({'kind': 'recv', 'fd': 42, 'bytes': len(wire + context),
                   'payload': (wire + context).hex()})
    probe.snapshot({'fd': 42, 'base': 'not-an-address'}, b'z' * 64 + plain + context)
    assert probe.stats['invalid_snapshot_base'] == 1
    assert not [e for e in events if e['kind'].endswith('_match')] and len(probe.awaiting) == 1


def test_replay_resolves_only_later_valid_frame():
    import time
    events = []
    probe = RingCorrelator(pid=0, emit=events.append)
    wire, plain, context = make_pair()
    before = time.monotonic() - 1
    probe.receive({'kind':'recv', 'fd':42, 'bytes':len(wire+context),
                   'payload':(wire+context).hex()})
    after = time.monotonic() + 1
    valid = b'z'*64 + plain + context
    probe.replay_frames([(0x100000, before, valid)])
    assert not [e for e in events if e['kind'].endswith('_match')] and len(probe.awaiting) == 1
    probe.replay_frames([(0x100000, after, valid)])
    events = [e for e in events if e['kind'] != 'ring_candidate']
    assert len(events) == 1 and events[0]['kind'] == 'ring_replay_match'
    assert events[0]['candidate_id'] == 1
    probe.replay_frames([(0x100000, after, valid)])
    assert len(events) == 1


def test_miss_reason_classification():
    from collections import Counter
    wire, plain, context = make_pair()
    cases = [(b'z'*256, 'header_absent'),
             (b'z'*64 + wire + context, 'unchanged_ciphertext'),
             (b'z'*64 + plain + b'x'*len(context), 'following_context_mismatch')]
    for data, reason in cases:
        reasons = Counter()
        assert matching_copy(data, 0, wire, context, reasons) is None
        assert reasons[reason] > 0, (reason, reasons)


def test_actor_core_adapter_real_scoring():
    from actor_adapter import ActorCoreAdapter
    wire, plain, context = make_pair()
    adapter = ActorCoreAdapter(__import__("os").getpid())
    try:
        start, delta = adapter.note_chunk(194, wire + context, 0)
        adapter.note_packet(194, 0, wire)
        item = {'chunk': wire + context, 'length': len(wire), 'fd':194,
                'off':0, 'cstart':start, 'd':delta}
        assert adapter.find(b'X' * 64 + plain + context, 0x100000, item) == (0x100040, plain)
        assert adapter.find(b'X' * 64 + wire + context, 0x100000, item) is None
    finally:
        adapter.close()


def test_actor_core_0229_two_byte_header():
    from actor_adapter import ActorCoreAdapter
    wire = b'\x29\x02' + b'\x12\x34\x56\x78' + b'C' * 9
    plain = wire[:6] + b'P' * 9
    tail = b'\x80\x00' + b'Z' * 5
    adapter = ActorCoreAdapter(__import__("os").getpid())
    try:
        start, delta = adapter.note_chunk(194, wire + tail, 0)
        adapter.note_packet(194, 0, wire)
        item = {'chunk': wire + tail, 'length':len(wire), 'fd':194,
                'off':0, 'cstart':start, 'd':delta}
        assert adapter.find(b'X' * 64 + plain + tail, 0x100000, item) == (0x100040, plain)
    finally:
        adapter.close()


if __name__ == "__main__":
    test_accepts_verified_changed_body()
    test_rejects_false_positives()
    test_stream_detects_interior_and_fragmented()
    test_slot_diagnostic_distinguishes_valid_and_wrong_header()
    test_production_quick_discovery_receives_full_chunk()
    test_snapshot_match_and_no_duplicate()
    test_snapshot_rejects_unchanged_wire()
    test_snapshot_invalid_metadata_is_safe()
    test_replay_resolves_only_later_valid_frame()
    test_miss_reason_classification()
    test_actor_core_adapter_real_scoring()
    test_actor_core_0229_two_byte_header()
    print("ring-correlator offline tests: PASS")

test_quick_discovery_rejects_executable_mapping()
