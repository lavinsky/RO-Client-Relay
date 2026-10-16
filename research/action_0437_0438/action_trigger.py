#!/usr/bin/env python3
"""Gatilho mínimo (teste rápido): quando o relay ARMA uma ação do consumidor (merge), dispara o
input virtual no cliente para gerar o carrier natural que o scrambler então reescreve.

Sequência (pedida pelo responsável):
  consumidor manda 0437/0438  ->  relay loga "[inject] inbound id=0x0437 ... scramble body map"
  (o corpo fica ARMADO/seguro em scr.bodies)  ->  este watcher vê a linha e injeta a tecla
  (uinput/ydotool) na janela do cliente  ->  o cliente monta o 0437/0438 natural  ->  o store do
  scrambler (gepard+0x18eff2) substitui o corpo pelo do consumidor  ->  ação executa.

NÃO altera o relay. Só observa o stdout do relay e aciona `synth_input` (ydotool via uinput, que
passa no Gepard). Requer `ydotoold` rodando (ver synth_input.py) e a janela do cliente focável.

Uso:
    action_trigger.py --log <relay_stdout.log> [--key-0437 INSERT] [--key-0438 F1] [--key-0af4 F2]
                      [--wid 0x05200001] [--debounce-ms 500] [--once] [--dry]
"""
import argparse
import re
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import synth_input  # noqa: E402

LINE_RE = re.compile(r'\[inject\] inbound id=0x([0-9a-fA-F]{4}).* scramble body map')


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('--log', required=True, help='stdout do relay (onde aparecem as linhas [inject] inbound)')
    ap.add_argument('--key-0437', default='INSERT')
    ap.add_argument('--key-0438', default='9')   # '9' da fileira de cima (KEY_9=10), NÃO o do numpad
    ap.add_argument('--key-0af4', default='F2')
    ap.add_argument('--wid', default=None, help='id da janela do cliente; senão autodetecta')
    ap.add_argument('--debounce-ms', type=int, default=500)
    ap.add_argument('--once', action='store_true', help='dispara uma vez e sai (teste controlado)')
    ap.add_argument('--dry', action='store_true', help='não injeta; só mostra')
    ap.add_argument('--from-start', action='store_true', help='lê o log do início (senão, só novas linhas)')
    a = ap.parse_args(argv)

    keymap = {'0437': a.key_0437, '0438': a.key_0438, '0af4': a.key_0af4}
    wid = synth_input.find_wid(a.wid)
    print('[trigger] log=%s wid=%s keymap=%s debounce=%dms once=%s dry=%s'
          % (a.log, wid, keymap, a.debounce_ms, a.once, a.dry), flush=True)
    if wid is None:
        raise SystemExit('janela do cliente não encontrada (passe --wid; veja synth_input.py --list)')

    p = Path(a.log)
    for _ in range(50):
        if p.exists():
            break
        time.sleep(0.1)
    if not p.exists():
        raise SystemExit('log inexistente: %s' % a.log)

    last_fire = {}
    with p.open('r', errors='replace') as f:
        if not a.from_start:
            f.seek(0, 2)  # fim: só novas linhas
        while True:
            line = f.readline()
            if not line:
                time.sleep(0.05)
                continue
            m = LINE_RE.search(line)
            if not m:
                continue
            idhex = m.group(1).lower()
            key = keymap.get(idhex)
            if key is None:
                continue
            now = time.time()
            if now - last_fire.get(idhex, 0) < a.debounce_ms / 1000.0:
                continue
            last_fire[idhex] = now
            print('[trigger] armed id=0x%s -> synth key %s' % (idhex, key), flush=True)
            synth_input.focus(wid, a.dry)
            synth_input.send_key(key, a.dry)
            if a.once:
                print('[trigger] --once: done', flush=True)
                return 0


if __name__ == '__main__':
    sys.exit(main())
