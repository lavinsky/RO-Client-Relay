"""Offline regression for consumer disconnect triggering native-dispatch recapture."""
import threading
from _boot import g

r = g.Relay.__new__(g.Relay)
r.lock = threading.Lock()
events = []
r.on_disconnect = lambda: events.append('invalidate')
class Socket:
    def __init__(self):
        self.closed = False
    def close(self):
        self.closed = True
s = Socket()
r.sock = s
r._drop_sock(s)
assert s.closed and r.sock is None and events == ['invalidate']
r._drop_sock(s)
assert events == ['invalidate'], events  # no duplicate when already disconnected

# Even if the callback fails, losing the socket must remain final.
s2 = Socket()
r.sock = s2
r.on_disconnect = lambda: (_ for _ in ()).throw(RuntimeError('callback failure'))
r._drop_sock(s2)
assert r.sock is None and s2.closed
print('move-dispatch lifecycle disconnect ok')
