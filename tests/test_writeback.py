"""Offline test for the WRITE path (relay/writeback.py + relay/protocol.py).

Covers the driver wiring and the message contract the agent relies on: the scramble / scramble-set
messages carry the right fields (persist flag, one-shot clear, idoff/range); the per-id routing
(035f -> merge, everything else -> client SendPacket); the sendcall emit; and the send-watch ->
scramble handoff of auto-discovery. The agent-side substitution was validated live."""
import _boot  # noqa: F401  (puts the repo on sys.path)
from relay.protocol import scramble_msg, scramble_set_msg, sendcall_emit_msg, sendcall_msg
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

# --- _on_inbound_sendcall: inbound 'S' -> sendcall-emit com o pacote inteiro em hex -----------
class FakeSend:
    SELECT_ID = Capture.SELECT_ID
    SKILL_ID = Capture.SKILL_ID
    ACT_ID = Capture.ACT_ID
    CAST_IDS = Capture.CAST_IDS
    SKIP_IDS = Capture.SKIP_IDS
    def __init__(self):
        self.posted = []

    def post(self, msg):
        self.posted.append(msg)

    _target_gid = Capture._target_gid
    _on_inbound_sendcall = Capture._on_inbound_sendcall

s = FakeSend()
# tagarelice do consumidor (pedido de nome 0368) NÃO é reinjetada
s._on_inbound_sendcall(bytes.fromhex('680384c18e06'), 'S')
assert s.posted == [], s.posted
# ataque 0437 (GID 854b5c07 != 0): emite 0368 do alvo ANTES do 0437
s._on_inbound_sendcall(bytes.fromhex('3704854b5c0707'), 'S')
assert s.posted == [{'type': 'sendcall-emit', 'data': '6803854b5c07'},
                    {'type': 'sendcall-emit', 'data': '3704854b5c0707'}], s.posted
s.posted.clear()
# perícia 0438 (Fire Ball nv9 no GID 84c18e06): 0368 do alvo antes do 0438
s._on_inbound_sendcall(bytes.fromhex('38040900110084c18e06'), 'S')
assert s.posted == [{'type': 'sendcall-emit', 'data': '680384c18e06'},
                    {'type': 'sendcall-emit', 'data': '38040900110084c18e06'}], s.posted
s.posted.clear()
# sentar 0437 (GID 0, ação 2): sem alvo -> sem 0368
s._on_inbound_sendcall(bytes.fromhex('37040000000002'), 'S')
assert s.posted == [{'type': 'sendcall-emit', 'data': '37040000000002'}], s.posted
s.posted.clear()
s._on_inbound_sendcall(bytes.fromhex('3704854b5c0707'), 'R')      # não-'S' é ignorado
s._on_inbound_sendcall(b'\x37', 'S')                             # curto demais: ignorado
assert s.posted == [], s.posted
print('_on_inbound_sendcall ok')

# --- sendcall_msg leva a janela de paceamento (cast_ms) para o agente --------------------------
assert sendcall_msg(0x9463b0, 'uaRO.exe', cast_ms=800) == \
    {'type': 'sendcall', 'rva': 0x9463b0, 'module': 'uaRO.exe', 'castMs': 800}
assert sendcall_msg(None) == {'type': 'sendcall'}                # desarmar não leva campos
# o paceamento em si é feito no dreno do agente (relay_hook_linux.js), validado ao vivo
print('sendcall_msg com cast_ms ok')

# --- _on_inbound_split: roteia por id (035f -> merge, demais acoes -> SendPacket) --------------
class FakeSplit:
    WALK_ID = Capture.WALK_ID
    SELECT_ID = Capture.SELECT_ID
    SKILL_ID = Capture.SKILL_ID
    ACT_ID = Capture.ACT_ID
    CAST_IDS = Capture.CAST_IDS
    SKIP_IDS = Capture.SKIP_IDS
    def __init__(self):
        self.posted = []

    def post(self, msg):
        self.posted.append(msg)

    _target_gid = Capture._target_gid
    _on_inbound_split = Capture._on_inbound_split
    _on_inbound_scramble = Capture._on_inbound_scramble
    _on_inbound_sendcall = Capture._on_inbound_sendcall

assert FakeSplit.WALK_ID == 0x035f
sp = FakeSplit()
sp._on_inbound_split(bytes.fromhex('5f03bec3fd'), 'S')            # 035f (andar) -> merge pre-XOR
assert sp.posted == [{'type': 'scramble-set', 'id': 0x035f, 'body': 'bec3fd'}], sp.posted
sp.posted.clear()
sp._on_inbound_split(bytes.fromhex('3704854b5c0707'), 'S')       # 0437 (ataque) -> 0368 alvo + SendPacket
assert sp.posted == [{'type': 'sendcall-emit', 'data': '6803854b5c07'},
                     {'type': 'sendcall-emit', 'data': '3704854b5c0707'}], sp.posted
sp.posted.clear()
sp._on_inbound_split(bytes.fromhex('380405000600'), 'S')         # 0438 curto (sem GID) -> SendPacket direto
assert sp.posted == [{'type': 'sendcall-emit', 'data': '380405000600'}], sp.posted
sp.posted.clear()
sp._on_inbound_split(bytes.fromhex('3704854b5c0707'), 'R')       # não-'S' ignorado em ambas as rotas
assert sp.posted == [], sp.posted
print('_on_inbound_split ok')

assert sendcall_msg(0x9463b0, 'uaRO.exe')['rva'] == 0x9463b0 and sendcall_msg(0x9463b0)['type'] == 'sendcall'

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
