"""Research-only adapter using the production ActorDecrypt's scoring and packet rules.

No relay production changes, no actor ring cache writes. The adapter never feeds XKore.
"""
import threading
import os
from relay.actors import ActorDecrypt


class ProbeActorDecrypt(ActorDecrypt):
    def _load_cache(self):
        # The probe must verify the live ring, not trust a persisted address.
        pass

    def _set_ring(self, lo, hi, why):
        self.base, self.hi = lo, hi
        self.region = (lo, hi)
        self.fails = 0
        if self.on_ring:
            self.on_ring(lo)


class ActorCoreAdapter:
    def __init__(self, pid):
        self.core = ProbeActorDecrypt(pid)
        self.lock = threading.RLock()

    def note_chunk(self, fd, wire_chunk, carried):
        with self.lock:
            return self.core.note_chunk(fd, wire_chunk, carried)

    def note_packet(self, fd, off, packet):
        with self.lock:
            self.core.note_enc(fd, off, len(packet), int.from_bytes(packet[:2], 'little'))

    def find(self, data, base, item):
        """Return a uniquely scored valid plaintext candidate using relay._best.

        Production confidence thresholds; do not treat ID-only matches as verified.
        """
        with self.lock:
            chunk = item['chunk']
            wire = chunk[:item['length']]
            candidates = self.core._best(data, base, item['fd'], wire,
                                         item['off'], item['cstart'], item['d'])
            if not candidates:
                return None
            top = candidates[0]
            runner = candidates[1][0] if len(candidates) > 1 else 0
            if top[0] < 16 or top[0] - runner < 8:
                return None
            return top[3], top[5]

    def close(self):
        os.close(self.core.mem.fd)
