#!/usr/bin/env python3
"""Amostrador de estado de thread INDEPENDENTE do Frida (processo separado, nunca bloqueia).

Lê `/proc/<pid>/task/<tid>/{stat,wchan,syscall}` periodicamente e classifica a execução durante/
após a chamada nativa, sem depender do callback JS que faz a chamada (ele bloqueia a engine JS na
main thread). Distingue: progredindo | repetição-userspace (possível loop) | espera/bloqueio |
término/exceção | (perda do observador é inferida pelo driver que compara com a sessão Frida).

Uso CLI (teste offline):  sample_thread.py --pid PID --tid TID --ms 30 --duration-ms 3000 --out ARQ
Como módulo:  from sample_thread import sample_series, classify
"""
import argparse
import json
import time


def _read(path):
    try:
        with open(path) as f:
            return f.read()
    except (OSError, ValueError):
        return None


def read_state(pid, tid):
    base = f"/proc/{pid}/task/{tid}"
    stat = _read(f"{base}/stat")
    if stat is None:
        return None  # thread/processo ausente
    # comm pode conter espaços/parênteses: estado é o 1º campo após o último ')'
    try:
        rest = stat[stat.rindex(')') + 2:].split()
        state = rest[0]
    except (ValueError, IndexError):
        state = '?'
    # utime/stime (ticks) do mesmo `stat`: após o comm, índices 11/12. Progresso de CPU em
    # userspace distingue loop apertado (utime cresce) de bloqueio (utime estável). NÃO é kstkeip.
    utime = stime = None
    try:
        utime = int(rest[11]); stime = int(rest[12])
    except (ValueError, IndexError):
        pass
    wchan = _read(f"{base}/wchan")
    wchan = wchan.strip() if wchan is not None else None
    syscall = _read(f"{base}/syscall")
    syscall = syscall.strip() if syscall is not None else None
    sc_nr = None
    if syscall and syscall != 'running':
        try:
            sc_nr = int(syscall.split()[0])
        except (ValueError, IndexError):
            sc_nr = None
    return {'t': time.time(), 'state': state, 'wchan': wchan,
            'syscall': syscall, 'syscall_nr': sc_nr,
            'utime': utime, 'stime': stime,
            'in_userspace': (syscall == 'running'),
            'present': True}


def sample_series(pid, tid, interval_ms=30, duration_ms=3000):
    out = []
    n = max(1, int(duration_ms / interval_ms))
    for _ in range(n):
        s = read_state(pid, tid)
        if s is None:
            out.append({'t': time.time(), 'present': False})
        else:
            out.append(s)
        time.sleep(interval_ms / 1000.0)
    return out


def classify(series):
    present = [s for s in series if s.get('present')]
    if not series:
        return 'no_samples'
    if present and any(not s.get('present') for s in series[series.index(present[0]):]):
        return 'terminated_or_exception'  # esteve presente e depois sumiu
    if not present:
        return 'absent'
    states = [s['state'] for s in present]
    wchans = set(s.get('wchan') for s in present if s.get('wchan') not in (None, '0', ''))
    sc_nrs = set(s.get('syscall_nr') for s in present if s.get('syscall_nr') is not None)
    userspace = [s for s in present if s.get('in_userspace')]
    blocked = [s for s in present if s['state'] in ('S', 'D') and s.get('syscall_nr') is not None]
    # progresso de CPU em userspace (utime cresce) vs estagnação (utime estável)
    utimes = [s.get('utime') for s in present if s.get('utime') is not None]
    cpu_advancing = len(utimes) >= 2 and utimes[-1] > utimes[0]
    # progresso: syscall ou wchan variando ao longo do tempo
    if len(sc_nrs) > 1 or len(wchans) > 1:
        return 'progressing'
    if len(userspace) >= 0.8 * len(present) and all(st == 'R' for st in states):
        # NOTA: este é também o estado NORMAL ocioso (laço de render) deste cliente.
        # Durante o ensaio, só é amostrado quando a chamada JÁ não retornou => loop apertado.
        if cpu_advancing:
            return 'spinning_userspace(utime+; confirmar_responsividade_UI)'
        return 'running_userspace_stalled(utime_flat; needs_pc)'
    if len(blocked) >= 0.8 * len(present):
        w = next(iter(wchans), None)
        kind = 'waiting_cpu_flat' if not cpu_advancing else 'waiting_cpu_adv'
        return f'waiting/blocked({kind},wchan={w},syscall_nr={next(iter(sc_nrs), None)})'
    return 'mixed/indeterminate'


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--pid', type=int, required=True)
    ap.add_argument('--tid', type=int, required=True)
    ap.add_argument('--ms', type=int, default=30)
    ap.add_argument('--duration-ms', type=int, default=3000)
    ap.add_argument('--out', default=None)
    a = ap.parse_args(argv)
    series = sample_series(a.pid, a.tid, a.ms, a.duration_ms)
    verdict = classify(series)
    result = {'pid': a.pid, 'tid': a.tid, 'interval_ms': a.ms, 'samples': len(series),
              'classification': verdict, 'series': series}
    if a.out:
        with open(a.out, 'w') as f:
            json.dump(result, f, indent=2)
    print(json.dumps({'classification': verdict, 'samples': len(series)}, indent=2))


if __name__ == '__main__':
    main()
