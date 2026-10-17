"""Agent readiness acknowledgements trigger natural action carriers through uinput.

XTEST input was filtered in the documented client. Window management uses
xdotool only for synchronous activation; ydotool/ydotoold delivers key events.
This affects the desktop seat and requires an explicitly authorized live round.
The observed 120ms key duration is preserved. No opcode debounce or cooldown.
"""
import os
import queue
import subprocess
import threading
import time

from .event_log import event

# Linux input-event-codes (subconjunto usado aqui).
KEYCODES = {
    'INSERT': 110, 'DELETE': 111, 'HOME': 102, 'END': 107,
    'SPACE': 57, 'ENTER': 28, 'ESC': 1, 'TAB': 15,
}
for _i in range(1, 13):  # F1..F12 = 59..70
    KEYCODES['F%d' % _i] = 58 + _i
for _i, _c in enumerate('1234567890'):  # dígitos 1..0 = 2..11 ('9' da fileira de cima = 10, NÃO numpad)
    KEYCODES[_c] = 2 + _i

DEFAULT_SOCKET = '/run/user/%d/.ydotool_socket' % os.getuid()
WINDOW_MATCH = ('world of your dream', 'uaro', 'gepard shield', 'steam_app_')


def _run(cmd, dry, env=None):
    event('[synth] ' + ' '.join(cmd), verbose=True)
    if dry:
        return 0, '', ''
    p = subprocess.run(cmd, capture_output=True, text=True, env=env)
    if p.stdout.strip():
        print(p.stdout.rstrip(), flush=True)
    if p.returncode != 0 and p.stderr.strip():
        print('    ! ' + p.stderr.rstrip(), flush=True)
    return p.returncode, p.stdout, p.stderr


def list_windows():
    env = dict(os.environ)
    env.setdefault('DISPLAY', ':0')
    p = subprocess.run(['wmctrl', '-lx'], capture_output=True, text=True, env=env)
    return p.stdout


def find_wid(explicit):
    if explicit:
        return explicit
    out = list_windows()
    for line in out.splitlines():
        low = line.lower()
        if any(m in low for m in WINDOW_MATCH):
            return line.split()[0]
    return None


def focus(wid, dry):
    env = dict(os.environ)
    env.setdefault('DISPLAY', ':0')
    # Gerência de janela (não é XTEST input): ativa/levanta a janela XWayland do cliente.
    rc, _, _ = _run(['xdotool', 'windowactivate', '--sync', wid], dry, env)
    if rc:
        raise RuntimeError('window activation failed')


def ydotool_env():
    env = dict(os.environ)
    env.setdefault('YDOTOOL_SOCKET', DEFAULT_SOCKET)
    return env


def send_key(name, dry, hold_ms=120, cancelled=lambda: False):
    code = KEYCODES.get(name.upper())
    if code is None:
        raise ValueError('tecla desconhecida: %s (conhecidas: %s)' % (name, ','.join(sorted(KEYCODES))))
    env = ydotool_env()
    sock = env['YDOTOOL_SOCKET']
    if not dry and not os.path.exists(sock):
        raise RuntimeError('socket ydotoold ausente: %s — inicie o ydotoold (ver cabeçalho)' % sock)
    # OBSERVADO (2026-10-16): press+release colados (0 ms) NÃO registram no cliente uaRO; é preciso
    # SEGURAR a tecla ~120 ms. Então: press, hold_ms, release (duas chamadas ydotool via uinput).
    if cancelled():
        return 0
    rc, _, _ = _run(['ydotool', 'key', '%d:1' % code], dry, env)
    if rc:
        raise RuntimeError('key press failed')
    try:
        if not dry:
            # Required input duration observed in client; never a command rate limit.
            time.sleep(hold_ms / 1000.0)
    finally:
        rc, _, _ = _run(['ydotool', 'key', '%d:0' % code], dry, env)
    if rc:
        raise RuntimeError('key release failed')
    return rc


# ---- atuador integrado ----------------------------------------------------------------------
class SynthActuator:
    """Event-driven carrier input. Each agent armed ACK generates exactly one key.

    The worker keeps input duration off the Frida/event thread. Session reset
    cancels queued keys; a key already pressed is always released.
    """
    def __init__(self, keymap, wid=None, dry=False, hold_ms=120, focuser=None, sender=None):
        self._keymap = {int(k): v for k, v in keymap.items()}
        self._wid_explicit = wid or None
        self._wid = None
        self._wid_resolved = False
        self._dry, self._hold_ms = bool(dry), int(hold_ms)
        self._focus, self._send = focuser or focus, sender
        self._q = queue.Queue(maxsize=64)
        self._lock = threading.Lock()
        self._started = False
        self._state = (0, True)
        self._revision = 0
        self.on_error = None
        self.on_finished = None

    def start(self):
        with self._lock:
            if self._started:
                return
            self._started = True
        threading.Thread(target=self._worker, name='synth-actuator', daemon=True).start()

    def reset(self, epoch, active):
        self._revision += 1
        self._state = (epoch, active)
        self._wid_resolved = False
        while True:
            try:
                self._q.get_nowait()
            except queue.Empty:
                break

    def _resolve_wid(self):
        if not self._wid_resolved:
            self._wid = find_wid(self._wid_explicit)
            self._wid_resolved = True
        return self._wid

    def on_armed(self, pid, epoch=None, token=None):
        key = self._keymap.get(int(pid))
        epoch = self._state[0] if epoch is None else epoch
        if key is None or self._state != (epoch, True):
            return False
        if not self._started:
            self.start()
        item = (int(pid), key, epoch, token, self._revision)
        try:
            self._q.put_nowait(item)
        except queue.Full:
            self._failure(item, RuntimeError('input capacity exhausted'))
            return False
        return True

    def _failure(self, item, error):
        pid, key, epoch, token, revision = item
        event('[synth] carrier failed: ' + type(error).__name__, level='error')
        if self.on_error:
            self.on_error({'tag': 'SCRAMBLE', 'hit': 'error', 'id': pid,
                           'epoch': epoch, 'token': token, 'e': type(error).__name__})

    def _worker(self):
        while True:
            item = self._q.get()
            pid, key, epoch, token, revision = item
            cancelled = lambda: self._state != (epoch, True) or revision != self._revision
            if cancelled():
                continue
            try:
                wid = self._resolve_wid()
                if wid is None:
                    raise RuntimeError('client window not found')
                began = time.monotonic_ns()
                self._focus(wid, self._dry)
                focused = time.monotonic_ns()
                if cancelled():
                    continue
                if self._send:
                    rc = self._send(key, self._dry, self._hold_ms)
                else:
                    rc = send_key(key, self._dry, self._hold_ms, cancelled)
                if rc:
                    raise RuntimeError('input failed')
                event('[synth] token=%s focus_ms=%.3f key_ms=%.3f' %
                      (token, (focused-began)/1e6, (time.monotonic_ns()-focused)/1e6), verbose=True)
            except Exception as e:
                self._failure(item, e)
            finally:
                if self.on_finished:
                    self.on_finished({'tag': 'INPUT', 'hit': 'released', 'id': pid,
                                      'epoch': epoch, 'token': token})


# ids de ação que o atuador mapeia (ataque / perícia em alvo / perícia no chão).
ACT_0437, SKILL_0438, GROUND_0AF4 = 0x0437, 0x0438, 0x0af4


def build_actuator(opts):
    """Constrói o SynthActuator a partir das opções da CLI, ou None se --synth-input estiver OFF."""
    if not getattr(opts, 'synth_input', False):
        return None
    keymap = {
        ACT_0437: getattr(opts, 'synth_key_0437', 'INSERT'),
        SKILL_0438: getattr(opts, 'synth_key_0438', '9'),
        GROUND_0AF4: getattr(opts, 'synth_key_0af4', 'F2'),
    }
    dry = bool(getattr(opts, 'synth_dry', False))
    act = SynthActuator(keymap, wid=getattr(opts, 'synth_wid', '') or None,
                        dry=dry)
    act.start()
    shown = {('0x%04x' % k): v for k, v in keymap.items()}
    print('[*] --synth-input: atuador de tecla integrado ao relay (uinput/ydotool, passa no Gepard); '
          'keymap=%s%s' % (shown, ' DRY' if dry else ''))
    return act
