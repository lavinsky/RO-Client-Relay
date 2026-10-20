"""Isolated 0229 validation regressions; no process memory or relay writes."""
import struct
from _boot import g
from research.recv_cipher.validate_0229 import assess

def packet(gid, opt1=0, opt2=0, option=0, stance=0):
    return struct.pack('<2sIHHIB', b'\x29\x02', gid, opt1, opt2, option, stance)

wire = b'\x29\x02' + bytes(range(13))
good = packet(0x12345678, 0, 16, 32)
# Different plaintext GID from the encrypted wire: must remain eligible.
assert good[2:6] != wire[2:6]
assert assess(wire, good, matched_context=True, fresh_slot=True)['deliver']
# Header alone, stale memory, ambiguous copies cannot make a packet trusted.
assert not assess(wire, good)['deliver']
assert not assess(wire, good, matched_context=True)['deliver']
assert not assess(wire, good, matched_context=True, fresh_slot=True, ambiguous=True)['deliver']
assert not assess(wire, packet(0), matched_context=True, fresh_slot=True)['deliver']
assert not assess(wire, good[:-1], matched_context=True, fresh_slot=True)['deliver']
assert not assess(wire, wire, matched_context=True, fresh_slot=True)['deliver']
assert not assess(wire, b'\xff\x09' + good[2:], matched_context=True, fresh_slot=True)['deliver']
# Unknown option bit-combinations are warnings, not arbitrary rejection.
rare = packet(0x12345678, opt1=7, opt2=0x8000, option=0xfedcba98, stance=2)
r = assess(wire, rare, matched_context=True, fresh_slot=True)
assert r['deliver'] and not r['checks']['option_reference']
assert not r['checks']['opt1_reference'] and not r['checks']['opt2_reference']
print('0229 isolated validation PASS')
