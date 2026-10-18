"""Send recovery: plaintext of the encrypted client->server packets (0437 action, 0438 skill)."""
import collections

SEND_QUEUE_FALLBACK = (0x24dd0000, 0x24f80000)     # where the block sat in every session so far


def packet_at(win, buf, base):
    """The packet bytes inside a window that starts at the aligned `base` (queue slots are unaligned)."""
    if buf is None or base is None:
        return win
    return win[2 * (int(buf, 16) - int(base, 16)):]


def plaintext_guess(w, C, buf=None, base=None):
    """The encryptor overwrites the body in place, one byte per write, from one pc (the trailing run
    of >= 2 same-pc hits). The window right before that run's first write holds the plaintext, if its
    id matches the sent packet. None when the window doesn't have that shape. Hex in, hex out."""
    if not isinstance(w, dict) or not isinstance(C, str):
        return None
    hits = w.get('hits') or []
    if not isinstance(hits, (list, tuple)) or len(hits) < 2:
        return None
    if any(not isinstance(h, dict) or not isinstance(h.get('pc'), str)
           or not isinstance(h.get('win'), str) for h in hits):
        return None
    try:
        enc = hits[-1]['pc']
        i = len(hits) - 1
        while i > 0 and hits[i - 1]['pc'] == enc:
            i -= 1
        last = packet_at(hits[-1]['win'], buf, base)
        if i == 0 or len(hits) - i < 2 or last[:4] != C[:4]:
            return None
        P = packet_at(hits[i - 1]['win'], buf, base)
    except (ValueError, TypeError, IndexError):
        # An incomplete/malformed write window is not evidence of plaintext.
        return None
    n = min(len(P), len(C))
    return P if P[:4] == C[:4] and P[:n] != C[:n] else None


class SendWatch:
    """--send-watch: plaintext of the encrypted client->server packets.

    0437 action / 0438 skill are built in the client's send queue and encrypted in place; the agent
    keeps a hardware write watchpoint on the next queue slot and sends each SEND with the window of
    writes (W). The plaintext is the window right before the encryptor's run of same-pc writes
    (plaintext_guess, same method as relay_sendbp.py --queue). Unrecovered or implausible -> the
    packet is DROPPED, never fed as ciphertext. 035f walk (encrypted on the stack) is dropped:
    the consumer has no handler for it and follows our moves from the server's cleartext 0087."""
    ENC = {0x0437: 7, 0x0438: 10}                      # id -> packet length
    DROP = {0x035f}

    def __init__(self):
        self.stats = collections.Counter()

    @staticmethod
    def plausible(pid, Q):
        if pid == 0x0437:
            return Q[6] <= 12                          # action type (0 attack, 2 sit, 3 stand, 7 attack loop)
        lv, sk = Q[2] | Q[3] << 8, Q[4] | Q[5] << 8
        return 1 <= lv <= 20 and 1 <= sk < 10000

    def resolve(self, m, P, W):
        """Bytes to feed for this send (P itself if not encrypted), or None to drop.
        On success tags `m` as SEND-PLAIN for the log."""
        pid = P[0] | P[1] << 8 if len(P) >= 2 else -1
        if pid in self.DROP:
            self.stats[f'drop-{pid:04x}'] += 1
            return None
        L = self.ENC.get(pid)
        if L is None:
            return P
        why, Q = None, None
        if len(P) != L:
            why = 'multi'                              # not one whole packet in this sendmsg
        elif W is None:
            why = 'nowin'                              # slot wasn't armed (first send, queue reset)
        else:
            G = plaintext_guess(W, m['C'], m.get('buf'), W.get('base'))
            Q = bytes.fromhex(G[:2 * L]) if G and len(G) >= 2 * L else None
            if Q is None:
                why = 'unrecovered'
            elif not self.plausible(pid, Q):
                why = 'implausible'
        if why:
            self.stats[f'{why}-{pid:04x}'] += 1
            return None
        self.stats[f'ok-{pid:04x}'] += 1
        hits = W.get('hits') or []
        m.update(tag='SEND-PLAIN', P=Q.hex(), src=m.get('buf', '?'),
                 enc=hits[-1]['pc'] if hits else None)   # scrambler write-pc (for --scramble-bp discovery)
        return Q


def send_queue_range(spec, ring=None, have_dec=True):
    """(lo, hi, source) of the memory block holding the client send queue, or None = not known yet.

    The queue sits in the same rw heap block as the recv ring that ActorDecrypt finds (and verifies
    per packet, and rediscovers if it moves), so 'auto' takes that block. An explicit 'lo-hi' (hex)
    overrides. Without ActorDecrypt (--no-decrypt-actors) 'auto' falls back to the block's address
    from earlier sessions."""
    if spec and spec != 'auto':
        lo, hi = (int(x, 16) for x in spec.split('-'))
        return lo, hi, '--send-queue'
    if ring is not None and ring[0] is not None:
        return ring[0], ring[1], 'recv ring block'
    if not have_dec:
        return SEND_QUEUE_FALLBACK + ('fallback (no --decrypt-actors)',)
    return None
