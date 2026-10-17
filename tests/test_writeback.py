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
    _emit_target_select = Capture._emit_target_select
    _on_inbound_sendcall = Capture._on_inbound_sendcall

from types import SimpleNamespace
s = FakeSend()
# tagarelice do consumidor (pedido de nome 0368) NÃO é reinjetada
s._on_inbound_sendcall(bytes.fromhex('680384c18e06'), 'S')
assert s.posted == [], s.posted
# DEFAULT (--target-select off): ação com alvo NÃO emite 0368 (ele quebra a ação; o 0437/0438 já
# carrega o GID). Observado live: sem o 0368 o ataque/perícia funciona.
# ataque 0437 (GID 854b5c07 != 0): só o 0437
s._on_inbound_sendcall(bytes.fromhex('3704854b5c0707'), 'S')
assert s.posted == [{'type': 'sendcall-emit', 'data': '3704854b5c0707'}], s.posted
s.posted.clear()
# perícia 0438 (Fire Ball nv9 no GID 84c18e06): só o 0438
s._on_inbound_sendcall(bytes.fromhex('38040900110084c18e06'), 'S')
assert s.posted == [{'type': 'sendcall-emit', 'data': '38040900110084c18e06'}], s.posted
s.posted.clear()
# sentar 0437 (GID 0, ação 2): sem alvo -> sem 0368 de qualquer forma
s._on_inbound_sendcall(bytes.fromhex('37040000000002'), 'S')
assert s.posted == [{'type': 'sendcall-emit', 'data': '37040000000002'}], s.posted
s.posted.clear()
s._on_inbound_sendcall(bytes.fromhex('3704854b5c0707'), 'R')      # não-'S' é ignorado
s._on_inbound_sendcall(b'\x37', 'S')                             # curto demais: ignorado
assert s.posted == [], s.posted

# --target-select ON: reativa o clique-mímico (emite 0368 do alvo antes da ação) com dedup por GID:
# ataque/perícia repetidos no MESMO alvo NÃO reemitem o 0368 (anti-flood); só quando o GID muda.
d = FakeSend(); d.opts = SimpleNamespace(target_select=True)
d._on_inbound_sendcall(bytes.fromhex('3704854b5c0707'), 'S')      # 1º ataque no alvo A: 0368 + 0437
assert d.posted == [{'type': 'sendcall-emit', 'data': '6803854b5c07'},
                    {'type': 'sendcall-emit', 'data': '3704854b5c0707'}], d.posted
d.posted.clear()
d._on_inbound_sendcall(bytes.fromhex('3704854b5c0707'), 'S')      # mesmo alvo A: só o 0437, sem 0368
assert d.posted == [{'type': 'sendcall-emit', 'data': '3704854b5c0707'}], d.posted
d.posted.clear()
d._on_inbound_sendcall(bytes.fromhex('380409001100aabbccdd'), 'S')  # alvo B (muda GID): 0368 + 0438
assert d.posted == [{'type': 'sendcall-emit', 'data': '6803aabbccdd'},
                    {'type': 'sendcall-emit', 'data': '380409001100aabbccdd'}], d.posted
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
    _emit_target_select = Capture._emit_target_select
    _on_inbound_split = Capture._on_inbound_split
    _on_inbound_scramble = Capture._on_inbound_scramble
    _on_inbound_sendcall = Capture._on_inbound_sendcall

assert FakeSplit.WALK_ID == 0x035f
sp = FakeSplit()
sp._on_inbound_split(bytes.fromhex('5f03bec3fd'), 'S')            # 035f (andar) -> merge pre-XOR
assert sp.posted == [{'type': 'scramble-set', 'id': 0x035f, 'body': 'bec3fd'}], sp.posted
sp.posted.clear()
sp._on_inbound_split(bytes.fromhex('3704854b5c0707'), 'S')       # 0437 (ataque) -> SendPacket (sem 0368 por padrão)
assert sp.posted == [{'type': 'sendcall-emit', 'data': '3704854b5c0707'}], sp.posted
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
# --- PoC move-dispatch: unpack_move (inverso de pack_move) + roteamento 035f -> dispatch + drop ---
from types import SimpleNamespace
from relay.packets import pack_move, unpack_move
from relay.protocol import move_dispatch_msg
for (x, y, dr) in [(0, 0, 0), (1023, 1023, 15), (150, 187, 3), (5, 700, 8), (513, 2, 1)]:
    assert unpack_move(pack_move(x, y, dr)) == (x, y, dr), (x, y, dr)
assert move_dispatch_msg(150, 187) == {'type': 'native-dispatch', 'recipe': 'walk-035f', 'args': {'x': 150, 'y': 187}}
assert move_dispatch_msg(arm=True, dispatcher='0xd473b0', site='0x4dcba0') == \
    {'type': 'native-dispatch', 'arm': True, 'recipe': 'walk-035f', 'dispatcher': 0xd473b0, 'site': 0x4dcba0}
assert move_dispatch_msg(disarm=True) == {'type': 'native-dispatch', 'disarm': True}


class FakeMove:
    WALK_ID = Capture.WALK_ID
    def __init__(self, move_dispatch=True):
        self.posted, self.scrambled, self.sendcalled = [], [], []
        self.opts = SimpleNamespace(move_dispatch=move_dispatch, inject_call=False)

    def post(self, msg):
        self.posted.append(msg)

    def _on_inbound_scramble(self, payload, typ):
        self.scrambled.append(payload)

    def _on_inbound_sendcall(self, payload, typ):
        self.sendcalled.append(payload)

    post_move_dispatch = Capture.post_move_dispatch
    _on_inbound_split = Capture._on_inbound_split


mv = FakeMove()
mv._on_inbound_split(b'\x5f\x03' + pack_move(150, 187, 3), 'S')
assert mv.posted == [move_dispatch_msg(150, 187)] and mv.scrambled == [] and mv.sendcalled == [], mv.posted
mv.posted.clear()
mv._on_inbound_split(b'\x5f\x03\x00', 'S')                          # curto: dropado, nada postado
mv._on_inbound_split(b'\x5f\x03' + pack_move(1, 2), 'R')            # nao-'S': ignorado
assert mv.posted == [] and mv.scrambled == [], mv.posted
off = FakeMove(move_dispatch=False)                                  # sem a flag: caminho antigo (merge)
off._on_inbound_split(b'\x5f\x03' + pack_move(150, 187), 'S')
assert off.posted == [] and len(off.scrambled) == 1
print('move-dispatch routing ok')


class FakeAct(FakeMove):
    def __init__(self, action_merge, armed=True):
        FakeMove.__init__(self, move_dispatch=False)
        self.opts = SimpleNamespace(move_dispatch=False, inject_call=True, action_merge=action_merge)
        self._scramble_armed = armed
    ACTION_MERGE_IDS = Capture.ACTION_MERGE_IDS


acts = [b'\x37\x04' + b'\x01\x02\x03\x04\x07', b'\x38\x04' + b'\x05\x00\x1c\x00\x01\x02\x03\x04']
on = FakeAct(True)
for a in acts:
    on._on_inbound_split(a, 'S')
assert on.scrambled == acts and on.sendcalled == [], (on.scrambled, on.sendcalled)
off = FakeAct(False)
for a in acts:
    off._on_inbound_split(a, 'S')
assert off.sendcalled == acts and off.scrambled == [], (off.scrambled, off.sendcalled)
un = FakeAct(True, armed=False)                                      # flag sem scramble armado: SendPacket
un._on_inbound_split(acts[0], 'S')
assert un.sendcalled == [acts[0]] and un.scrambled == []
# end-to-end real: 0437/0438 com a flag geram scramble_set_msg e nao sendcall_emit_msg
real = FakeAct(True)
real.opts.action_merge = True
real._on_inbound_scramble = lambda p, t: Capture._on_inbound_scramble(real, p, t)
real._on_inbound_split(acts[0], 'S'); real._on_inbound_split(acts[1], 'S')
assert real.posted == [scramble_set_msg(0x437, acts[0][2:].hex()), scramble_set_msg(0x438, acts[1][2:].hex())], real.posted
assert not any(m == sendcall_emit_msg(a.hex()) for m in real.posted for a in acts)
print('action-merge routing ok')


# --- --target-select na via MERGE (--action-merge): 0368 (seleção) é emitido ANTES do 0437 --------
class FakeMergeSel(FakeMove):
    SELECT_ID = Capture.SELECT_ID
    SKILL_ID = Capture.SKILL_ID
    ACT_ID = Capture.ACT_ID
    ACTION_MERGE_IDS = Capture.ACTION_MERGE_IDS

    def __init__(self, target_select):
        FakeMove.__init__(self, move_dispatch=False)
        self.opts = SimpleNamespace(move_dispatch=False, inject_call=True, action_merge=True,
                                    target_select=target_select)
        self._scramble_armed = True

    _target_gid = Capture._target_gid
    _emit_target_select = Capture._emit_target_select
    _on_inbound_scramble = Capture._on_inbound_scramble   # real: posta scramble-set (não o stub)
    _on_inbound_split = Capture._on_inbound_split


atk = bytes.fromhex('3704aabbccdd07')                      # ataque 0437 no GID aabbccdd (merge)
on = FakeMergeSel(target_select=True)
on._on_inbound_split(atk, 'S')
assert on.posted == [sendcall_emit_msg('6803aabbccdd'),    # 0368 seleção primeiro...
                     scramble_set_msg(0x0437, 'aabbccdd07')], on.posted   # ...depois o 0437 no merge
on.posted.clear()
on._on_inbound_split(atk, 'S')                             # mesmo alvo: 0368 não repete (dedup por GID)
assert on.posted == [scramble_set_msg(0x0437, 'aabbccdd07')], on.posted
# default (--target-select OFF): a via merge NÃO emite 0368 — comportamento atual inalterado
off = FakeMergeSel(target_select=False)
off._on_inbound_split(atk, 'S')
assert off.posted == [scramble_set_msg(0x0437, 'aabbccdd07')], off.posted
print('action-merge target-select ok')


# --- egress queue (--egress-queue): FIFO serializado, nada se atropela ---------------------------
import queue as _q           # noqa: E402
import threading as _t       # noqa: E402
import time as _tm           # noqa: E402


class FakeEgress(FakeMove):
    def __init__(self):
        FakeMove.__init__(self, move_dispatch=True)
        self.opts = SimpleNamespace(move_dispatch=True, inject_call=True, action_merge=True)
        self._scramble_armed = True
        self.dispatched = []
        self._egress_interval = 0.0
        self._egress_action_gap = 0.0
        self._egress_max_age = 10.0                        # alto: nada expira no teste de ordem
        self._egress_q = _q.Queue()

    ACTION_MERGE_IDS = Capture.ACTION_MERGE_IDS
    _egress_enqueue = Capture._egress_enqueue
    _egress_drain = Capture._egress_drain

    def _on_inbound_split(self, payload, typ):             # registra só a ORDEM de despacho
        self.dispatched.append(payload)


eg = FakeEgress()
frames = [b'\x5f\x03' + pack_move(10, 20),                  # 035f andar
          b'\x37\x04\x01\x02\x03\x04\x07',                  # 0437 ataque (ação)
          b'\x5f\x03' + pack_move(11, 21)]                  # 035f andar
eg._egress_enqueue(b'\x86\x00recv', 'R')                    # quadro 'R' (recv espelhado): NÃO entra na fila
eg._egress_enqueue(b'\x5f', 'S')                            # 'S' curto demais p/ ter id: ignorado
for f in frames:
    eg._egress_enqueue(f, 'S')
_t.Thread(target=eg._egress_drain, daemon=True).start()
for _ in range(200):
    if len(eg.dispatched) == len(frames):
        break
    _tm.sleep(0.005)
assert eg.dispatched == frames, eg.dispatched               # ordem de chegada preservada, um por vez
print('egress-queue FIFO ok')

# descarte por idade (--egress-max-age-ms): um quadro que esperou demais é dropado, o fresco passa
st = FakeEgress()
st._egress_max_age = 0.8
old = b'\x5f\x03' + pack_move(1, 1)                         # andar p/ coord velha (deve ser dropado)
new = b'\x5f\x03' + pack_move(9, 9)
st._egress_q.put((_tm.monotonic() - 2.0, old, 'S'))         # chegou há 2s > 0.8s
st._egress_q.put((_tm.monotonic(), new, 'S'))
_t.Thread(target=st._egress_drain, daemon=True).start()
for _ in range(200):
    if st.dispatched:
        break
    _tm.sleep(0.005)
_tm.sleep(0.02)
assert st.dispatched == [new], st.dispatched                # só o fresco despachou; o velho foi dropado
print('egress-queue stale-drop ok')

print('ALL PASS')
