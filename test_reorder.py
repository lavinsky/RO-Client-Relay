# Unit-test the legacy (--no-wire) reorder buffer + watchdog: LegacyPipeline.finish/_drain/run_watchdog.
import os, sys, threading, time
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
from relay.legacy import LegacyPipeline

SOCK = '1.2.3.4:5121'


class R:
    def __init__(self): self.fed = []
    def feed(self, b): self.fed.append(b)


class Log:
    def write(self, m): pass


def setup():
    relay = R()
    lp = LegacyPipeline(os.getpid(), relay, Log(), post=lambda m: None)
    lp.matcher.rings[SOCK] = [0, 0, None]      # ring "known": every RECV is held for a RINGSNAP
    return lp, relay


def arrive(lp, C):                             # RECV in arrival order -> held, ciphertext remembered
    lp.on_recv({'tag': 'RECV', 'sock': SOCK, 'len': len(C), 'C': C.hex(), 'ptr': '0x0'})
    return lp.waiting[SOCK][-1]


def finish(lp, m, P):                          # decrypted copy found (P) or lost (None -> ciphertext)
    lp.finish(m, None if P is None else (0, len(P), P))


# Scenario 1: ridx 0..3 arrive, finish OUT OF ORDER: 1,3 first; 0 later; 2 later.
lp, relay = setup()
m = [arrive(lp, b'\x7f\x00C%d' % i) for i in range(4)]
finish(lp, m[1], b'\x7f\x00P1'); finish(lp, m[3], b'\x7f\x00P3')
assert relay.fed == [], relay.fed               # head (0) missing -> nothing fed yet
finish(lp, m[0], b'\x7f\x00P0')
assert relay.fed == [b'\x7f\x00P0', b'\x7f\x00P1'], relay.fed
finish(lp, m[2], b'\x7f\x00P2')
assert relay.fed == [b'\x7f\x00P0', b'\x7f\x00P1', b'\x7f\x00P2', b'\x7f\x00P3'], relay.fed
print("test 1 (out-of-order, no drops): PASS")

# Scenario 2: head slot 0 NEVER finishes (socket closed); watchdog must flush its ciphertext.
lp, relay = setup()
lp.STUCK_AFTER = 0.0; lp.WATCHDOG_EVERY = 0.01
m = [arrive(lp, b'\x7f\x00X%d' % i) for i in range(3)]
finish(lp, m[1], b'\x7f\x00P1'); finish(lp, m[2], b'\x7f\x00P2')
assert relay.fed == [], relay.fed
threading.Thread(target=lp.run_watchdog, daemon=True).start()
time.sleep(0.2)
assert relay.fed == [b'\x7f\x00X0', b'\x7f\x00P1', b'\x7f\x00P2'], relay.fed
print("test 2 (stuck head flushed by watchdog): PASS")

# Scenario 3: late finish of a watchdog-flushed slot must NOT double-feed.
finish(lp, m[0], b'\x7f\x00P0_late')
assert relay.fed == [b'\x7f\x00X0', b'\x7f\x00P1', b'\x7f\x00P2'], relay.fed
print("test 3 (no double-feed after watchdog flush): PASS")

# Scenario 4: HTTP noise in a slot is skipped, not fed, and doesn't block the slots behind it.
lp, relay = setup()
m = [arrive(lp, b'HTTP/1.1 200'), arrive(lp, b'\x7f\x00ok')]
finish(lp, m[1], None); finish(lp, m[0], None)
assert relay.fed == [b'\x7f\x00ok'], relay.fed
print("test 4 (HTTP slot skipped): PASS")
print("ALL PASS")
