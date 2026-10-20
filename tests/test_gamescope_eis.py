"""Pure offline checks for the Gamescope EIS backend; never injects into seat0."""
import os
import socket
import stat
import tempfile
from types import SimpleNamespace
from unittest.mock import patch

import _boot
from relay.gamescope_eis import GamescopeEIS, GamescopeEISError, resolve_socket
from relay.synth_input import build_actuator


with tempfile.TemporaryDirectory() as d:
    with socket.socket(socket.AF_UNIX) as sock:
        target = os.path.join(d, 'gamescope-eis.sock')
        sock.bind(target)
        os.environ['XDG_RUNTIME_DIR'] = d
        assert resolve_socket('gamescope-eis.sock') == target
        locator = os.path.join(d, 'locator')
        with open(locator, 'w', encoding='utf-8') as fd:
            fd.write('gamescope-eis.sock\n')
        os.chmod(locator, 0o600)
        assert resolve_socket(path_file=locator) == target
        os.chmod(locator, 0o644)
        try:
            resolve_socket(path_file=locator)
            raise AssertionError('accepted public locator')
        except GamescopeEISError:
            pass
        try:
            resolve_socket()
            raise AssertionError('accepted missing Gamescope socket')
        except GamescopeEISError:
            pass
        try:
            resolve_socket(path='x', path_file=locator)
            raise AssertionError('accepted ambiguous socket')
        except GamescopeEISError:
            pass
print('EIS socket isolation and permissions OK')


class FakeAPI:
    def __init__(self):
        self.events = []
    def dispatch(self, ctx):
        pass
    def key(self, device, code, pressed):
        self.events.append(('key', device, code, pressed))
    def now(self, ctx):
        return 123
    def frame(self, device, when):
        self.events.append(('frame', device, when))
    def device_unref(self, device):
        pass
    def unref(self, ctx):
        pass


# Emulate already-established EIS device; verify press/frame/hold/release/frame.
g = GamescopeEIS(socket='anything')
fake = FakeAPI()
g.api = fake
g.ctx, g.dev, g.ready = 1, 2, True
g._drain_events = lambda: None
assert g.send_key(110, hold_ms=0) == 0
assert fake.events == [('key', 2, 110, True), ('frame', 2, 123),
                       ('key', 2, 110, False), ('frame', 2, 123)]
g.close()
print('EIS press + release framing OK')


opts = SimpleNamespace(synth_input=True, synth_backend='gamescope-eis', synth_dry=True,
                       synth_eis_socket='', synth_eis_socket_file='', synth_debounce_ms=0,
                       synth_wid='0xDEAD', synth_key_0437='INSERT',
                       synth_key_0438='9', synth_key_0af4='F2')
with patch('relay.synth_input.find_wid', side_effect=AssertionError('host discovery')), \
     patch('relay.synth_input.focus', side_effect=AssertionError('host focus')), \
     patch('relay.synth_input.send_key', side_effect=AssertionError('ydotool call')):
    act = build_actuator(opts)
    assert act._wid_explicit == 'gamescope-eis'
    act._focus('gamescope-eis', True)
    assert act._send('9', True, 120) == 0  # DRY, no EIS socket, no host interaction
print('Gamescope backend dry-run isolated from KDE and ydotool OK')
