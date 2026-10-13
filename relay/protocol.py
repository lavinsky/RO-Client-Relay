"""Messages exchanged with the Frida agent (relay_hook_linux.js).

Agent -> driver. The JSON payload is the dict below; a binary attachment arrives as m['data'].
  RECV           sock 'ip:port', conn (local port = one TCP connection), len, id (text),
                 C (hex bytes read), ptr (hex iovec address), seq, ts (ms since epoch),
                 pre (hex ring base; first iovec only, when the ring is known).
                 data = ring copy taken BEFORE the client could decrypt this chunk, or None.
  RINGSNAP       sock, conn, base (hex), seq, ts.
                 data = ring copy taken at the start of a recvmsg (before the next chunk lands).
  SEND           sock, conn, len, id, C, seq, ts. On a send-queue send while the send watch
                 is on: buf (hex slot address) and, if that slot was armed,
                 W = {base: hex, n: writes seen, hits: [{pc: hex, win: 32 hex chars}]}.
  SENDWATCH-ERR  e (error text).
  GEPARD         base (hex gepard.dll base, or None) - sent once at startup, so the driver can
                 place a scramble breakpoint at base + offset (ASLR varies the base per launch).
  SCRAMBLE       hit ('dry'|'wrote'|'other'), pc, slot (hex), id, body (hex of the slot body),
                 and in dry mode regs {name: hex}. Reports what the scramble breakpoint saw/did.

Driver -> agent (script.post):
  {'type': 'ring', 'sock', 'base', 'span'?}       where the recv ring is; bytes to copy
  {'type': 'sendwatch', 'lo', 'hi', 'ports'}      arm the send-queue watch
  {'type': 'sendwatch'}                           turn it off
  {'type': 'scramble', 'off'|'pc', 'reg', 'id', 'body'?, 'dry'?}   exec breakpoint at the scrambler
  {'type': 'scramble'}                            turn it off
  {'type': 'scramble-set', 'id', 'body'}          --inject merge: substitute this id's body at the
                                                  scramble BP once (pre-XOR). body=None clears it.

Log-only tags the driver assigns (relay_log.jsonl): RECV-WIRE, RECV-RAW, RECV-HTTP,
RECV-PLAIN, RECV-LOST, SEND-PLAIN.
"""
RECV = 'RECV'
RINGSNAP = 'RINGSNAP'
SEND = 'SEND'
SENDWATCH_ERR = 'SENDWATCH-ERR'
GEPARD = 'GEPARD'
SCRAMBLE = 'SCRAMBLE'

MAP_PORT = 5121                                    # the only server whose sends are encrypted


def ring_msg(sock, base, span=None):
    m = {'type': 'ring', 'sock': sock, 'base': hex(base)}
    if span:
        m['span'] = span
    return m


def sendwatch_msg(lo=None, hi=None, ports=(MAP_PORT,)):
    """Arm the send-queue watch over [lo, hi); with lo omitted, turn it off (frees the debug regs)."""
    if lo is None:
        return {'type': 'sendwatch'}
    return {'type': 'sendwatch', 'lo': hex(lo), 'hi': hex(hi), 'ports': list(ports)}


def scramble_msg(off=None, reg='edi', pid=None, body=None, dry=True, idoff=0, lo=None, hi=None,
                 persist=False):
    """Arm (or clear, with off=None and body=None) a scramble-intercept breakpoint at gepard+off.
    body (hex) in LIVE mode is written over the slot body; dry logs only. idoff: id position relative
    to the pointer. lo/hi: only act when the pointer is in [lo, hi). persist (--inject merge): keep
    each consumer body and replace EVERY matching client action, instead of consuming it (one-shot)."""
    if off is None and body is None:
        return {'type': 'scramble'}
    m = {'type': 'scramble', 'off': off, 'reg': reg, 'dry': dry, 'idoff': idoff, 'persist': persist}
    if pid is not None:
        m['id'] = pid
    if body is not None:
        m['body'] = body
    if lo is not None:
        m['lo'], m['hi'] = hex(lo), hex(hi)
    return m


def scramble_set_msg(pid, body=None):
    """--inject merge: tell the agent to substitute `body` (hex) for packet id `pid` the next time
    the scramble BP sees it, then forget it (one-shot). body=None clears a pending substitution.
    The id itself is left as the client built it; only the body (at idoff+2) is overwritten."""
    return {'type': 'scramble-set', 'id': pid, 'body': body}


def conn_of(m):
    """The TCP connection a message belongs to (agent's local port; the server address if unknown)."""
    return m.get('conn', m['sock'])
