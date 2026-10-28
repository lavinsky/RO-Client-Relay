"""Atuador de entrada sintética — módulo do relay (antes: sidecar action_trigger.py).

Quando o relay ARMA uma ação do consumidor no merge (0437/0438/0af4 -> corpo guardado em scr.bodies
no ponto `_on_inbound_scramble`), este atuador injeta a tecla que faz o CLIENTE montar o carrier
natural daquele id; o store do scrambler selecionado pelo client profile então reescreve o corpo
e a ação executa. Antes isso vivia num 2º processo (research/action_0437_0438/action_trigger.py) que
TAIL-ava o stdout do relay à procura da linha "[inject] inbound id=0x…"; agora é acionado DIRETO no
ponto de arme (writeback._on_inbound_scramble -> SynthActuator.on_armed), sem log/pipe intermediário.

Backend (memória `synthetic-movement-uaro-hybrid-input`): o Gepard FILTRA XTEST (xdotool/Xvfb como
*input*), mas aceita eventos de **uinput** (ydotool/ydotoold), que chegam ao Wine como hardware. Logo:
usa-se gerência de janela (wmctrl/xdotool) só para **focar** a janela do cliente, e o keystroke é
injetado por `ydotool` (uinput). O evento é global ao seat0 — a janela precisa estar focada e isso
atrapalha o uso real do desktop; o isolamento limpo (gamescope headless + uinput próprio) é o passo
seguinte (ISOLATION_SPIKE.md).

OFF por padrão (--synth-input). Pré-req ao vivo: `ydotoold` rodando com acesso a /dev/uinput e socket
acessível ao usuário; janela do cliente focável. NÃO autoriza nada por si: a janela/alvo precisam
estar no escopo autorizado do responsável (servidor próprio). O efeito colateral é input real no seat0.

    sudo ydotoold -p /run/user/1000/.ydotool_socket -o 1000:1000 -P 0600 &
"""
import os
import queue
import shlex
import subprocess
import threading
import time

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
    print('  $ ' + ' '.join(shlex.quote(c) for c in cmd), flush=True)
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
    rc1, _, _ = _run(['wmctrl', '-i', '-a', wid], dry, env)
    rc2, _, _ = _run(['xdotool', 'windowactivate', wid], dry, env)
    # A failed focus must NOT be followed by a global seat0 key event.
    if rc1 or rc2:
        raise RuntimeError('não foi possível focar janela do cliente (%d/%d)' % (rc1, rc2))
    if not dry:
        time.sleep(0.25)


def ydotool_env():
    env = dict(os.environ)
    env.setdefault('YDOTOOL_SOCKET', DEFAULT_SOCKET)
    return env


def send_key(name, dry, hold_ms=120):
    code = KEYCODES.get(name.upper())
    if code is None:
        raise ValueError('tecla desconhecida: %s (conhecidas: %s)' % (name, ','.join(sorted(KEYCODES))))
    env = ydotool_env()
    sock = env['YDOTOOL_SOCKET']
    if not dry and not os.path.exists(sock):
        raise RuntimeError('socket ydotoold ausente: %s — inicie o ydotoold (ver cabeçalho)' % sock)
    # OBSERVADO (2026-10-16): press+release colados (0 ms) NÃO registram no cliente uaRO; é preciso
    # SEGURAR a tecla ~120 ms. Então: press, hold_ms, release (duas chamadas ydotool via uinput).
    rc_press, _, _ = _run(['ydotool', 'key', '%d:1' % code], dry, env)
    if not dry and rc_press == 0:
        time.sleep(hold_ms / 1000.0)
    # Always attempt release, including when the press failed.
    rc_release, _, _ = _run(['ydotool', 'key', '%d:0' % code], dry, env)
    return rc_press or rc_release


# ---- atuador integrado ----------------------------------------------------------------------
class SynthActuator:
    """Dispara a tecla sintética quando o relay arma uma ação com id mapeado.

    `on_armed(pid)` é chamado no caminho de arme (thread do worker/dreno do relay); ele NÃO bloqueia
    — aplica o debounce por id e enfileira o disparo num worker próprio (focar a janela + segurar a
    tecla leva ~0,4 s; não pode travar o relay). `focuser`/`sender` são injetáveis para teste offline."""

    def __init__(self, keymap, wid=None, debounce_ms=500, dry=False, hold_ms=120,
                 focuser=None, sender=None):
        self._keymap = {int(k): v for k, v in keymap.items()}   # {pid:int -> nome da tecla:str}
        self._wid_explicit = wid or None
        self._wid = None
        self._wid_resolved = False
        self._debounce = max(0, int(debounce_ms)) / 1000.0
        self._dry = bool(dry)
        self._hold_ms = int(hold_ms)
        self._focus = focuser or focus
        self._send = sender or send_key
        self._last_fire = {}
        self._q = queue.Queue()
        self._lock = threading.Lock()
        self._started = False

    def start(self):
        with self._lock:
            if self._started:
                return
            self._started = True
        threading.Thread(target=self._worker, name='synth-actuator', daemon=True).start()

    def _resolve_wid(self):
        if self._wid_resolved:
            return self._wid
        self._wid = find_wid(self._wid_explicit)
        # A session may start before the client window exists: retry on a
        # later action rather than caching 'not found' for the entire process.
        self._wid_resolved = self._wid is not None
        if self._wid is None:
            print('[synth] janela do cliente não encontrada (passe --synth-wid; '
                  'synth_input --list) — tecla não injetada', flush=True)
        else:
            print('[synth] janela do cliente wid=%s' % self._wid, flush=True)
        return self._wid

    def send_before_packet(self, key):
        """Synchronous barrier: focus and finish key release before sendcall is queued."""
        with self._lock:
            wid = self._resolve_wid()
            if wid is None:
                raise RuntimeError('game window unavailable')
            self._focus(wid, self._dry)
            rc = self._send(key, self._dry, self._hold_ms)
            if rc != 0:
                raise RuntimeError('synthetic key failed (exit %s)' % rc)
            print('[itemuse] input %s completed before SendPacket' % key, flush=True)

    def on_armed(self, pid):
        """Ponto de entrada do relay: se `pid` tem tecla mapeada e passou o debounce, enfileira o
        disparo. Ids sem tecla (ex.: 035f andar) são ignorados. Não bloqueia o chamador."""
        key = self._keymap.get(int(pid))
        if key is None:
            return
        now = time.monotonic()
        with self._lock:
            if now - self._last_fire.get(pid, 0.0) < self._debounce:
                return
            self._last_fire[pid] = now
        if not self._started:
            self.start()
        self._q.put((int(pid), key))

    def _worker(self):
        while True:
            pid, key = self._q.get()
            try:
                wid = self._resolve_wid()
                if wid is None:
                    continue
                print('[synth] armed id=0x%04x -> tecla %s%s'
                      % (pid, key, ' (DRY)' if self._dry else ''), flush=True)
                self._focus(wid, self._dry)
                rc = self._send(key, self._dry, self._hold_ms)
                if rc not in (None, 0):
                    raise RuntimeError('synthetic key failed (exit %s)' % rc)
            except Exception as e:
                print('[synth] erro ao injetar %s: %s: %s' % (key, type(e).__name__, e), flush=True)


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
    debounce = int(getattr(opts, 'synth_debounce_ms', 500))
    dry = bool(getattr(opts, 'synth_dry', False))
    backend = getattr(opts, 'synth_backend', 'ydotool')
    kwargs = {'wid': getattr(opts, 'synth_wid', '') or None}
    if backend == 'gamescope-eis':
        from .gamescope_eis import GamescopeEIS
        conn = GamescopeEIS(socket=getattr(opts, 'synth_eis_socket', ''),
                            socket_file=getattr(opts, 'synth_eis_socket_file', ''))
        # No wmctrl / windowactivate / KDE focus or seat0 input on this path.
        kwargs['wid'] = 'gamescope-eis'
        kwargs['focuser'] = lambda wid, dry: None

        def send_gamescope(key, dry_run, hold_ms):
            code = KEYCODES.get(key.upper())
            if code is None:
                raise ValueError('tecla desconhecida: %s' % key)
            if dry_run:
                print('[synth/eis] DRY key=%s (%d)' % (key, code), flush=True)
                return 0
            return conn.send_key(code, hold_ms)

        kwargs['sender'] = send_gamescope
    elif backend != 'ydotool':
        raise ValueError('backend sintético desconhecido: %s' % backend)
    act = SynthActuator(keymap, debounce_ms=debounce, dry=dry, **kwargs)
    act.start()
    shown = {('0x%04x' % k): v for k, v in keymap.items()}
    print('[*] --synth-input: backend=%s keymap=%s debounce=%dms%s' %
          (backend, shown, debounce, ' DRY' if dry else ''))
    return act
