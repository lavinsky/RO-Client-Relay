"""Offline test for SendInjector (relay/inject.py): frames packets from the length table, refuses
unknown ids and out-of-bounds targets, respects dry_run, and writes a whole packet into a backing
'memory' (a temp file stands in for /proc/<pid>/mem; os.pwrite behaves the same on both)."""
import importlib.util, os, tempfile, threading
HERE = os.path.dirname(os.path.abspath(__file__))
sp = importlib.util.spec_from_file_location('g', os.path.join(HERE, 'relay_capture_linux.py'))
g = importlib.util.module_from_spec(sp); sp.loader.exec_module(g)

LENGTHS = {0x0437: 7, 0x0438: 10, 0x008c: -1}                # a fixed-len and a variable-len (-1) id

# --- framing ------------------------------------------------------------------------------------
inj = g.SendInjector(None, lambda: None, LENGTHS)
assert inj.frame(0x0437, bytes.fromhex('d935960607')) == bytes.fromhex('3704d935960607'), 'fixed'
assert inj.frame(0x0437) == bytes.fromhex('37040000000000'), 'fixed, zero-padded'
assert inj.frame(0x008c, b'hi') == bytes.fromhex('8c00') + bytes((6, 0)) + b'hi', 'variable: id+len+body'
for bad, why in [(lambda: inj.frame(0x9999), 'unknown id'),
                 (lambda: inj.frame(0x0437, b'too-long-body'), 'body over the fixed length')]:
    try:
        bad(); assert False, f'expected InjectError: {why}'
    except g.InjectError:
        pass
print('framing ok')

# --- bounds + dry_run (no writer touched) -------------------------------------------------------
LO, HI = 0x1000, 0x1100
dry = g.SendInjector(None, lambda: (LO, HI, 'test'), LENGTHS, dry_run=True)
assert dry.inject(dry.frame(0x0437), at=LO) == 0 and dry.stats['dry-0437'] == 1, 'dry-run writes nothing'
for at in (LO - 1, HI - 3):                                  # before the block / packet overruns the end
    try:
        dry.inject(dry.frame(0x0437), at=at); assert False, 'expected out-of-bounds InjectError'
    except g.InjectError:
        pass
assert dry.stats['out-of-bounds'] == 2
print('bounds + dry-run ok')

# --- a real write through ProcessMemoryWriter ---------------------------------------------------
fd, path = tempfile.mkstemp()
try:
    os.write(fd, b'\0' * (HI + 0x10)); os.close(fd)
    w = g.ProcessMemoryWriter.__new__(g.ProcessMemoryWriter)  # skip /proc/<pid>/mem; point at the temp file
    w.pid, w.fd = -1, os.open(path, os.O_RDWR)
    live = g.SendInjector(w, lambda: (LO, HI, 'test'), LENGTHS, dry_run=False)
    pkt = live.frame(0x0438, bytes.fromhex('0a000d00d9359606'))   # lv 10 Soul Strike, as in test_send_watch
    assert live.inject(pkt, at=LO + 0x20) == len(pkt), 'full packet written'
    assert os.pread(w.fd, len(pkt), LO + 0x20) == pkt, 'bytes land at the target'
    assert live.stats['ok-0438'] == 1
    os.close(w.fd)
finally:
    os.unlink(path)
print('live write ok')

# --- on_send tracks the live tail slot, inject_stream writes there ------------------------------
fd, path = tempfile.mkstemp()
try:
    os.write(fd, b'\0' * (HI + 0x10)); os.close(fd)
    w = g.ProcessMemoryWriter.__new__(g.ProcessMemoryWriter)
    w.pid, w.fd = -1, os.open(path, os.O_RDWR)
    s = g.SendInjector(w, lambda: (LO, HI, 'test'), LENGTHS, dry_run=False)
    s.on_send({'buf': hex(LO + 0x40), 'len': 7})                 # agent reports a queue send
    assert s.next_slot == hex(LO + 0x47), s.next_slot            # tail = buf + len
    raw = bytes.fromhex('3704d935960607')                        # a whole packet from the consumer, unframed
    assert s.inject_stream(raw) == len(raw)                      # no framing done; written as-is
    assert os.pread(w.fd, len(raw), LO + 0x47) == raw, 'lands at the tracked tail slot'
    os.close(w.fd)
finally:
    os.unlink(path)
print('slot tracking + inject_stream ok')

# --- per-id slot placement: inject at the client's OWN slot for that id, sized to its len --------
fd, path = tempfile.mkstemp()
try:
    os.write(fd, b'\0' * 0x2000); os.close(fd)
    w = g.ProcessMemoryWriter.__new__(g.ProcessMemoryWriter)
    w.pid, w.fd = -1, os.open(path, os.O_RDWR)
    s = g.SendInjector(w, lambda: (0, 0x2000, 'test'), LENGTHS, dry_run=False)
    s._region_ok = lambda addr, n: True                          # /proc/-1/maps doesn't exist offline
    s.on_send({'buf': hex(0x800), 'len': 5, 'C': '5f032c3d8d'})  # client built 0x035f here, len 5
    assert s.slots[0x035f] == (0x800, 5), s.slots
    s.on_send({'buf': hex(0x900), 'len': 7, 'C': '3704d9359606'})# and 0x0437 here, len 7 (seq tail too)
    assert s.next_slot == hex(0x907)
    # a consumer 0x035f (even a longer one) lands at the client's 0x035f slot, truncated to len 5
    assert s.inject_stream(bytes.fromhex('5f03aabbccdd99')) == 5
    assert os.pread(w.fd, 5, 0x800) == bytes.fromhex('5f03aabbcc'), 'at the per-id slot, sized to 5'
    assert s.stats['ok-035f'] == 1
    # an id with no known slot falls back to the sequential tail (next_slot = 0x907)
    assert s.inject_stream(bytes.fromhex('1c0b')) == 2 and os.pread(w.fd, 2, 0x907) == b'\x1c\x0b'
    os.close(w.fd)
finally:
    os.unlink(path)
print('per-id slot placement ok')

# --- Relay deframes the consumer's inbound 'S' frames into whole packets -------------------------
r = g.Relay.__new__(g.Relay)                                     # no socket/thread; exercise deframing only
r.fmt, r._in, r.lock = 'xkore1', b'', threading.Lock()
got = []
r.on_inbound = lambda payload, typ: got.append((typ, payload.hex()))
frame = lambda typ, p: typ.encode() + len(p).to_bytes(2, 'little') + p
msg = frame('S', bytes.fromhex('3704d935960607')) + frame('S', bytes.fromhex('38040a000d00d9359606'))
r._inbound(msg[:5]); r._inbound(msg[5:])                         # split mid-frame: reassembly must hold
assert got == [('S', '3704d935960607'), ('S', '38040a000d00d9359606')], got
print('relay deframing ok')
print('all inject tests passed')
