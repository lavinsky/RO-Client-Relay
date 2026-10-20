#!/usr/bin/env python3
"""Resume uaRO after >=3s in Linux process-stopped state (not gameplay inactivity)."""
import argparse
import os
import signal
import time
from pathlib import Path


def process_state(pid):
    try:
        raw = Path(f'/proc/{pid}/stat').read_text()
        state = raw[raw.rfind(')') + 2]
        return state, Path(f'/proc/{pid}/comm').read_text().strip()
    except (FileNotFoundError, ProcessLookupError, PermissionError):
        return None, None


def ua_pids():
    for entry in Path('/proc').iterdir():
        if entry.name.isdigit():
            state, name = process_state(int(entry.name))
            if name == 'uaRO.exe' and state is not None:
                yield int(entry.name), state


def watch(interval=0.25, threshold=3.0):
    stopped = {}
    resumed = set()
    print(f'[watchdog] uaRO SIGCONT enabled; stopped threshold={threshold:.1f}s', flush=True)
    while True:
        now = time.monotonic()
        current = dict(ua_pids())
        for pid, state in current.items():
            if state not in ('T', 't'):
                stopped.pop(pid, None)
                resumed.discard(pid)
                continue
            if pid in resumed:
                continue  # do not flood SIGCONT if some component re-stops it
            if pid not in stopped:
                stopped[pid] = now
                print(f'[watchdog] uaRO pid={pid} stopped state={state}; observing', flush=True)
            elif now - stopped[pid] >= threshold:
                elapsed = now - stopped[pid]
                try:
                    # Recheck process identity to avoid signaling an unrelated reused PID.
                    state2, name2 = process_state(pid)
                    if name2 == 'uaRO.exe' and state2 in ('T', 't'):
                        os.kill(pid, signal.SIGCONT)
                        print(f'[watchdog] SIGCONT sent pid={pid} stopped_for={elapsed:.2f}s; session cipher may require reconnect', flush=True)
                        resumed.add(pid)
                except (PermissionError, ProcessLookupError) as e:
                    print(f'[watchdog] SIGCONT failed pid={pid}: {e}', flush=True)
                    resumed.add(pid)
        for pid in list(stopped):
            if pid not in current:
                stopped.pop(pid, None)
                resumed.discard(pid)
        time.sleep(interval)


if __name__ == '__main__':
    p = argparse.ArgumentParser()
    p.add_argument('--threshold', type=float, default=3.0)
    p.add_argument('--interval', type=float, default=0.25)
    a = p.parse_args()
    if a.threshold <= 0 or a.interval <= 0:
        p.error('threshold and interval must be positive')
    watch(a.interval, a.threshold)
