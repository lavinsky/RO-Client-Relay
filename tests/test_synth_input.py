"""Offline test for the integrated synthetic-input actuator (relay/synth_input.py).

Covers the logic that used to live in the external action_trigger.py sidecar, now a relay module
fired directly from writeback._on_inbound_scramble: keymap routing by packet id, per-id debounce,
ignoring ids with no mapped key, and build_actuator honouring --synth-input (OFF by default). The
real uinput/ydotool keystroke is NOT exercised here (it is a live seat0 side-effect); focuser/sender
are injected fakes and we assert what WOULD be sent."""
import threading
import time
from types import SimpleNamespace

import _boot  # noqa: F401  (puts the repo on sys.path)
from relay.synth_input import KEYCODES, SynthActuator, build_actuator

# --- keycodes: '9' é a fileira de cima (KEY_9=10), NÃO o numpad; F-keys e INSERT corretos ---------
assert KEYCODES['9'] == 10 and KEYCODES['0'] == 11 and KEYCODES['1'] == 2
assert KEYCODES['INSERT'] == 110 and KEYCODES['F1'] == 59 and KEYCODES['F2'] == 60
print('keycodes ok')


# --- SynthActuator: enfileira (pid, tecla) por id mapeado; drena síncrono p/ o teste --------------
class FakeSink:
    """focuser/sender injetáveis: registram (sem tocar no seat0). Drenam a fila na mesma thread."""
    def __init__(self, keymap, **kw):
        self.focused, self.sent = [], []
        self.act = SynthActuator(keymap, focuser=self.focus, sender=self.send, **kw)
        self.act._started = True        # evita que on_armed suba o worker real (ele correria com drain())

    def focus(self, wid, dry):
        self.focused.append((wid, dry))

    def send(self, key, dry, hold_ms):
        self.sent.append((key, dry, hold_ms))

    def drain(self):                                       # processa o que on_armed enfileirou
        while not self.act._q.empty():
            pid, key = self.act._q.get_nowait()
            wid = self.act._resolve_wid()
            if wid is None:
                continue
            self.act._focus(wid, self.act._dry)
            self.act._send(key, self.act._dry, self.act._hold_ms)


KEYMAP = {0x0437: 'INSERT', 0x0438: '9', 0x0af4: 'F2'}

# id mapeado -> enfileira a tecla certa; wid explícito evita autodetecção (sem wmctrl no offline)
f = FakeSink(KEYMAP, wid='0xDEAD', debounce_ms=0, hold_ms=120)
f.act.on_armed(0x0437)
f.act.on_armed(0x0438)
f.act.on_armed(0x0af4)
f.drain()
assert f.sent == [('INSERT', False, 120), ('9', False, 120), ('F2', False, 120)], f.sent
assert f.focused == [('0xDEAD', False)] * 3, f.focused
print('keymap routing ok')

# id SEM tecla mapeada (ex.: 035f andar) é ignorado: nada enfileirado
f = FakeSink(KEYMAP, wid='0xDEAD', debounce_ms=0)
f.act.on_armed(0x035f)
f.act.on_armed(0x0094)
f.drain()
assert f.sent == [] and f.focused == [], (f.sent, f.focused)
print('unmapped id ignored ok')

# debounce: dois armes colados do MESMO id -> um disparo; ids diferentes não se bloqueiam
f = FakeSink(KEYMAP, wid='0xDEAD', debounce_ms=500)
f.act.on_armed(0x0437)
f.act.on_armed(0x0437)                                     # dentro da janela: suprimido
f.act.on_armed(0x0438)                                     # outro id: passa
f.drain()
assert f.sent == [('INSERT', False, 120), ('9', False, 120)], f.sent
print('debounce ok')

# debounce expira: após a janela, o mesmo id dispara de novo
f = FakeSink(KEYMAP, wid='0xDEAD', debounce_ms=20)
f.act.on_armed(0x0437)
time.sleep(0.03)
f.act.on_armed(0x0437)
f.drain()
assert f.sent == [('INSERT', False, 120), ('INSERT', False, 120)], f.sent
print('debounce expiry ok')

# --dry propaga ao sender (não injeta de verdade)
f = FakeSink(KEYMAP, wid='0xDEAD', debounce_ms=0, dry=True)
f.act.on_armed(0x0438)
f.drain()
assert f.sent == [('9', True, 120)], f.sent
print('dry ok')

# wid não encontrado (sem --synth-wid e sem janela): nenhum keystroke, sem exceção
f = FakeSink(KEYMAP, wid=None, debounce_ms=0)
f.act._wid_resolved, f.act._wid = True, None               # simula autodetecção que falhou
f.act.on_armed(0x0437)
f.drain()
assert f.sent == [] and f.focused == [], (f.sent, f.focused)
print('no-window no-op ok')


# --- build_actuator: honra --synth-input e o keymap/flags da CLI ----------------------------------
assert build_actuator(SimpleNamespace(synth_input=False)) is None       # OFF por padrão
assert build_actuator(SimpleNamespace()) is None                        # sem o atributo: OFF

opts = SimpleNamespace(synth_input=True, synth_wid='0xBEEF', synth_key_0437='INSERT',
                       synth_key_0438='9', synth_key_0af4='F2', synth_debounce_ms=500, synth_dry=True)
act = build_actuator(opts)
assert isinstance(act, SynthActuator)
assert act._keymap == {0x0437: 'INSERT', 0x0438: '9', 0x0af4: 'F2'}, act._keymap
assert act._wid_explicit == '0xBEEF' and act._dry is True and act._debounce == 0.5
print('build_actuator ok')


# --- _on_inbound_scramble chama synth.on_armed no arme (fiação em writeback) ----------------------
from relay.runtime import Capture


class FakeArm:
    def __init__(self):
        self.posted, self.armed = [], []
        self.synth = SimpleNamespace(on_armed=self.armed.append)

    def post(self, msg):
        self.posted.append(msg)

    _on_inbound_scramble = Capture._on_inbound_scramble


a = FakeArm()
a._on_inbound_scramble(bytes.fromhex('3704854b5c0707'), 'S')             # ataque 0437
assert a.posted == [{'type': 'scramble-set', 'id': 0x0437, 'body': '854b5c0707'}], a.posted
assert a.armed == [0x0437], a.armed                                     # atuador acionado com o id
a.armed.clear()
a._on_inbound_scramble(bytes.fromhex('3704854b5c0707'), 'R')            # não-'S': nem arma nem dispara
assert a.armed == [], a.armed
print('_on_inbound_scramble -> synth.on_armed ok')

# sem atuador (synth=None): _on_inbound_scramble não quebra
n = FakeArm(); n.synth = None
n._on_inbound_scramble(bytes.fromhex('5f03bec3fd'), 'S')
assert n.posted == [{'type': 'scramble-set', 'id': 0x035f, 'body': 'bec3fd'}], n.posted
print('no-actuator path ok')

# o worker real não deve estourar se chamado sem janela (daemon, dry): fumaça
smoke = SynthActuator({0x0437: 'INSERT'}, wid='0xDEAD', debounce_ms=0, dry=True,
                      focuser=lambda w, d: None, sender=lambda k, d, h: None)
smoke.start()
smoke.on_armed(0x0437)
for _ in range(100):
    if not smoke._q.empty():
        time.sleep(0.005)
    else:
        break
assert smoke._q.empty()
print('worker smoke ok')

print('ALL PASS')
