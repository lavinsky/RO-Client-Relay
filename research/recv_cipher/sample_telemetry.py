"""Bounded read-only 1 ms ring sampling telemetry; never stores buffer contents."""
import hashlib
from collections import deque
import os
import threading
import time


class RingSampleTelemetry:
    def __init__(self, pid, interval_s=0.001, size=16384, capacity=512):
        self.pid = pid
        self.interval_s = interval_s
        self.size = size
        self.base = None
        self.frames = deque(maxlen=capacity)
        self.frames_lock = threading.Lock()
        self.stop_event = threading.Event()
        self.thread = None
        self.stats = {'samples': 0, 'changed': 0, 'read_errors': 0,
                      'late_ticks': 0, 'max_gap_ms': 0.0, 'base_changes': 0,
                      'stored_frames': 0, 'evicted_frames': 0}

    def set_base(self, base):
        if self.base != base:
            self.base = base
            self.stats['base_changes'] += 1

    def start(self):
        self.thread = threading.Thread(target=self._run, name='ring-1ms-telemetry', daemon=True)
        self.thread.start()

    def _run(self):
        try:
            fd = os.open(f'/proc/{self.pid}/mem', os.O_RDONLY)
        except OSError:
            self.stats['read_errors'] += 1
            return
        last_digest = None
        previous = None
        deadline = time.monotonic()
        try:
            while not self.stop_event.is_set():
                now = time.monotonic()
                if previous is not None:
                    gap = (now - previous) * 1000
                    self.stats['max_gap_ms'] = max(self.stats['max_gap_ms'], round(gap, 3))
                    if gap > self.interval_s * 1500:
                        self.stats['late_ticks'] += 1
                previous = now
                base = self.base
                if base is not None:
                    try:
                        data = os.pread(fd, self.size, base)
                        if len(data) != self.size:
                            raise OSError('short read')
                        digest = hashlib.blake2s(data, digest_size=16).digest()
                        self.stats['samples'] += 1
                        if digest != last_digest:
                            if last_digest is not None:
                                self.stats['changed'] += 1
                            with self.frames_lock:
                                if len(self.frames) == self.frames.maxlen:
                                    self.stats['evicted_frames'] += 1
                                self.frames.append((base, now, data))
                                self.stats['stored_frames'] += 1
                        last_digest = digest
                    except OSError:
                        self.stats['read_errors'] += 1
                deadline += self.interval_s
                remaining = deadline - time.monotonic()
                if remaining < 0:
                    deadline = time.monotonic()
                    remaining = 0
                self.stop_event.wait(remaining)
        finally:
            os.close(fd)

    def take_frames(self):
        with self.frames_lock:
            frames = list(self.frames)
            self.frames.clear()
        return frames

    def stop(self):
        self.stop_event.set()
        if self.thread is not None:
            self.thread.join(timeout=2)
        return dict(self.stats)
