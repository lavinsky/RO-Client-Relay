"""Offline test for the --inject + --scramble-bp merge (relay/runtime.py, relay/protocol.py).

The driver turns each inbound consumer 'S' packet into a per-id scramble-set for the agent, and the
scramble / scramble-set messages carry the right fields (persist flag, one-shot clear, idoff/range).
The agent-side scrTrap substitution (substitute pre-XOR, one-shot vs persist) was validated live;
here we cover the driver wiring and the message contract the agent relies on."""
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
from relay.protocol import scramble_msg, scramble_set_msg
from relay.runtime import Capture

# --- message builders -------------------------------------------------------------------------
assert scramble_set_msg(0x0437, '854b5c0707') == {'type': 'scramble-set', 'id': 0x0437, 'body': '854b5c0707'}
assert scramble_set_msg(0x0437, None) == {'type': 'scramble-set', 'id': 0x0437, 'body': None}   # clear one id
m = scramble_msg(0x18eff2, 'ecx', 0x0437, None, False, -2, 0x24dd0000, 0x24f80000, persist=True)
assert m['persist'] is True and m['dry'] is False and m['idoff'] == -2 and m['reg'] == 'ecx'
assert m['lo'] == hex(0x24dd0000) and m['hi'] == hex(0x24f80000) and m['id'] == 0x0437
assert scramble_msg() == {'type': 'scramble'}                      # clear the whole intercept
assert scramble_msg(0x10, 'edi').get('persist') is False           # default stays one-shot
print('message builders ok')

# --- _on_inbound_scramble: inbound consumer 'S' -> scramble-set keyed by id, body = payload[2:] ---
class FakeCap:
    def __init__(self):
        self.posted = []

    def post(self, msg):
        self.posted.append(msg)

    _on_inbound_scramble = Capture._on_inbound_scramble

c = FakeCap()
c._on_inbound_scramble(bytes.fromhex('3704854b5c0707'), 'S')       # an attack 0437 from the consumer
assert c.posted == [{'type': 'scramble-set', 'id': 0x0437, 'body': '854b5c0707'}], c.posted

c.posted.clear()                                                   # non-'S' frames are ignored
c._on_inbound_scramble(bytes.fromhex('3704854b5c0707'), 'R')
assert c.posted == [], c.posted

c._on_inbound_scramble(b'\x37', 'S')                               # too short to hold an id: ignored
assert c.posted == [], c.posted

c._on_inbound_scramble(bytes.fromhex('5f03bec3fd'), 'S')           # a different id (035f walk) keys on 0x035f
assert c.posted == [{'type': 'scramble-set', 'id': 0x035f, 'body': 'bec3fd'}], c.posted
print('_on_inbound_scramble ok')

# --- _autodiscover_scramble: first encrypted send -> disarm send-watch, arm reg='auto' scramble ---
import threading
from types import SimpleNamespace
from relay.writeback import SCRAMBLE_STORE_BACK

class FakeDisc:
    def __init__(self):
        self.posted = []
        self.gepard_base = 0x76940000
        self.opts = SimpleNamespace(scramble_range='', inject_persist=True, scramble_id='0437')
        self._disc_lock = threading.Lock()
        self._scramble_armed = False
        self.sendwatch = object()                                  # truthy: a live send-watch
        self.scramble = None

    def post(self, msg):
        self.posted.append(msg)

    def _queue_range(self):
        return (0x24dd0000, 0x24f80000, 'recv ring block')

    _autodiscover_scramble = Capture._autodiscover_scramble

d = FakeDisc()
d._autodiscover_scramble({'enc': hex(0x76aceff4), 'enc_off': '0x18eff4'})   # scrambler write pc reported
# send-watch disarmed, then the exec BP armed on the store (enc - 2) with reg='auto' over the ring block
assert d.posted[0] == {'type': 'sendwatch'}, d.posted
arm = d.posted[1]
assert arm['type'] == 'scramble' and arm['reg'] == 'auto' and arm['persist'] is True
assert arm['off'] == 0x76aceff4 - 0x76940000 - SCRAMBLE_STORE_BACK == 0x18eff2
assert arm['lo'] == hex(0x24dd0000) and arm['hi'] == hex(0x24f80000)
assert d._scramble_armed is True and d.sendwatch is None and d.scramble['off'] == 0x18eff2
# idempotent: a second recovered send must not re-arm
d.posted.clear(); d._autodiscover_scramble({'enc': hex(0x76aceff4), 'enc_off': '0x18eff4'})
assert d.posted == [], d.posted
print('_autodiscover_scramble ok')
print('ALL PASS')
