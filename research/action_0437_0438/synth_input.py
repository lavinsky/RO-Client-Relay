#!/usr/bin/env python3
"""Entrada sintética que PASSA no Gepard (uinput via ydotoold), focando a janela do uaRO.

Contexto (memória do projeto `synthetic-movement-uaro-hybrid-input`): o Gepard FILTRA XTEST
(xdotool/Xvfb como *input*), mas aceita eventos vindos de **uinput** (ydotool/ydotoold), que chegam
ao Wine como hardware. Logo: usa-se gerência de janela (wmctrl/xdotool) só para **focar** a janela do
cliente, e o **keystroke/clique** é injetado por `ydotool` (uinput). O evento uinput é global ao
seat0 — por isso a janela precisa estar focada e isto atrapalha o uso real (desktop normal); o
isolamento limpo (gamescope headless + uinput próprio) é o passo seguinte (ver ISOLATION_SPIKE.md).

Pré-requisito ao vivo: `ydotoold` rodando com acesso a /dev/uinput e socket acessível ao usuário.
Exemplo (responsável, root, uma vez):
    sudo ydotoold -p /run/user/1000/.ydotool_socket -o 1000:1000 -P 0600 &
Depois exporte `YDOTOOL_SOCKET=/run/user/1000/.ydotool_socket` (este script o define se ausente).

NÃO autoriza nada por si: a janela/alvo precisam estar no escopo autorizado do responsável
(servidor próprio). Read-only quanto ao repo; o efeito colateral é input real no seat0.

Uso:
    synth_input.py --list                          # lista janelas candidatas (wmctrl -lx)
    synth_input.py key INSERT [--wid 0x05200001]   # foca a janela e aperta uma tecla
    synth_input.py key F1 --repeat 3 --delay-ms 400
    synth_input.py --dry key INSERT                # não injeta; só mostra o que faria
"""
import argparse
import os
import shlex
import subprocess
import sys
import time

# Linux input-event-codes (subconjunto usado aqui).
KEYCODES = {
    'INSERT': 110, 'DELETE': 111, 'HOME': 102, 'END': 107,
    'SPACE': 57, 'ENTER': 28, 'ESC': 1, 'TAB': 15,
}
for _i in range(1, 13):  # F1..F12 = 59..70
    KEYCODES['F%d' % _i] = 58 + _i
for _i, _c in enumerate('1234567890'):  # dígitos 1..0 = 2..11
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
    _run(['wmctrl', '-i', '-a', wid], dry, env)
    _run(['xdotool', 'windowactivate', wid], dry, env)
    if not dry:
        time.sleep(0.25)


def ydotool_env():
    env = dict(os.environ)
    env.setdefault('YDOTOOL_SOCKET', DEFAULT_SOCKET)
    return env


def send_key(name, dry, hold_ms=120):
    code = KEYCODES.get(name.upper())
    if code is None:
        raise SystemExit('tecla desconhecida: %s (conhecidas: %s)' % (name, ','.join(sorted(KEYCODES))))
    env = ydotool_env()
    sock = env['YDOTOOL_SOCKET']
    if not dry and not os.path.exists(sock):
        raise SystemExit('socket ydotoold ausente: %s — inicie o ydotoold (ver cabeçalho)' % sock)
    # OBSERVADO (2026-10-16): press+release colados (0 ms) NÃO registram no cliente uaRO; é preciso
    # SEGURAR a tecla ~120 ms. Então: press, hold_ms, release (duas chamadas ydotool via uinput).
    _run(['ydotool', 'key', '%d:1' % code], dry, env)
    if not dry:
        time.sleep(hold_ms / 1000.0)
    rc, _, _ = _run(['ydotool', 'key', '%d:0' % code], dry, env)
    return rc


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('--dry', action='store_true', help='não injeta; só imprime os comandos')
    ap.add_argument('--list', action='store_true', help='lista janelas candidatas e sai')
    ap.add_argument('--wid', help='id da janela (hex wmctrl); senão, autodetecta pelo título')
    sub = ap.add_subparsers(dest='cmd')
    pk = sub.add_parser('key', help='foca a janela e aperta uma tecla')
    pk.add_argument('name', help='nome da tecla (ex.: INSERT, F1, 1)')
    pk.add_argument('--repeat', type=int, default=1)
    pk.add_argument('--delay-ms', type=int, default=350)
    pk.add_argument('--no-focus', action='store_true', help='não foca a janela antes (assume já focada)')
    a = ap.parse_args(argv)

    if a.list:
        print(list_windows(), flush=True)
        return 0
    if a.cmd != 'key':
        ap.print_help()
        return 2

    wid = find_wid(a.wid)
    if wid is None and not a.no_focus:
        raise SystemExit('janela do cliente não encontrada (tente --list e passe --wid, ou --no-focus)')
    print('[synth] alvo wid=%s tecla=%s x%d dry=%s' % (wid, a.name, a.repeat, a.dry), flush=True)
    for i in range(a.repeat):
        if not a.no_focus:
            focus(wid, a.dry)
        send_key(a.name, a.dry)
        if i + 1 < a.repeat:
            if not a.dry:
                time.sleep(a.delay_ms / 1000.0)
    return 0


if __name__ == '__main__':
    sys.exit(main())
