"""Bounded client readiness, session cancellation and local monotonic timings.

There is no clock-based release or expiry. A native completion releases the next
command; a full interface reports failure instead of overwriting pending bytes.
Completion means local execution, never server acceptance.
"""
from collections import defaultdict, deque
import threading
import time


class CommandPipeline:
    CAPACITY = 64
    TERMINAL = {'SCRAMBLE': {'consumed', 'error', 'cancelled'},
                'SENDCALL': {'sent', 'error'},
                'MOVE-DISPATCH': {'dispatched', 'abort', 'error'}}

    def __init__(self, dispatch, reset, log, armed=None, clock=time.monotonic_ns):
        self.dispatch, self.reset, self.log, self.armed = dispatch, reset, log, armed
        self.clock = clock
        self.lock = threading.RLock()
        self.epoch = 0
        self.active = False
        self.pending = deque()
        self.current = None
        self.serial = 0
        self.samples = defaultdict(lambda: deque(maxlen=2048))

    def session(self, active, advance_epoch=True):
        with self.lock:
            count = len(self.pending) + bool(self.current)
            if advance_epoch:
                self.epoch += 1
            self.active = active
            self.pending.clear()
            self.current = None
            self.reset(self.epoch, active)
            self.log({'tag': 'SESSION', 'epoch': self.epoch, 'active': active, 'cancelled': count})

    def accept(self, payload, typ):
        if typ != 'S' or len(payload) < 2:
            return False
        with self.lock:
            if not self.active or len(self.pending) + bool(self.current) >= self.CAPACITY:
                self.log({'tag': 'COMMAND', 'hit': 'error', 'e': 'disconnected' if not self.active
                          else 'client readiness capacity exhausted', 'epoch': self.epoch})
                return False
            self.serial += 1
            self.pending.append({'payload': bytes(payload), 'typ': typ, 'token': self.serial,
                                 'epoch': self.epoch, 'received_ns': self.clock()})
            self._next()
            return True

    def _next(self):
        while self.active and self.current is None and self.pending:
            c = self.current = self.pending.popleft()
            c['dispatch_ns'] = self.clock()
            self.samples['ready_wait_ms'].append((c['dispatch_ns'] - c['received_ns']) / 1e6)
            try:
                # False = explicit local rejection; no native completion can arrive.
                waiting = self.dispatch(c)
            except Exception as e:
                waiting = False
                self.log({'tag': 'COMMAND', 'hit': 'error', 'token': c['token'],
                          'epoch': c['epoch'], 'e': type(e).__name__ + ': ' + str(e)})
            if waiting is False and self.current is c:
                self.current = None
            elif self.current is c:
                break

    def observe(self, m):
        with self.lock:
            c = self.current
            if c is None or m.get('epoch') != self.epoch or m.get('token') != c['token']:
                return False
            tag, hit = m.get('tag'), m.get('hit')
            now = self.clock()
            m['local_elapsed_ms'] = (now - c['received_ns']) / 1e6
            if isinstance(m.get('observed_ns'), int):
                self.samples['event_worker_wait_ms'].append((now - m['observed_ns']) / 1e6)
            begin, end, accepted = (m.get(k) for k in
                                    ('native_begin_mono_ms', 'native_end_mono_ms', 'accepted_mono_ms'))
            if isinstance(begin, (float, int)) and isinstance(end, (float, int)):
                self.samples['native_call_ms'].append(end - begin)
                if isinstance(accepted, (float, int)):
                    self.samples['agent_schedule_ms'].append(begin - accepted)
            if tag == 'SCRAMBLE' and hit == 'armed':
                c['armed_ns'] = now
                self.samples['post_to_armed_ms'].append((now - c['dispatch_ns']) / 1e6)
                if self.armed:
                    c['input_pending'] = self.armed(m) is True
            if tag == 'INPUT' and hit == 'released':
                c['input_done'] = True
            if hit in self.TERMINAL.get(tag, ()):
                self.samples['local_completion_ms'].append(m['local_elapsed_ms'])
                if 'armed_ns' in c:
                    self.samples['carrier_wait_ms'].append((now - c['armed_ns']) / 1e6)
                c['native_done'] = True
            if c.get('native_done') and (not c.get('input_pending') or c.get('input_done')):
                self.current = None
                self._next()
            return True

    def measure(self, stage, value):
        with self.lock:
            self.samples[stage].append(value)

    def summary(self):
        with self.lock:
            out = {}
            for name, values in self.samples.items():
                ordered = sorted(values)
                if ordered:
                    out[name] = {'n': len(ordered), **{label: ordered[max(0, (len(ordered)*p+99)//100-1)]
                                 for label, p in (('median', 50), ('p95', 95), ('p99', 99), ('max', 100))}}
            return out
