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
                 persist=False, probe=False, entry=False, pc=None, ids=None, anyid=False,
                 trace=0):
    """Arm (or clear, with off=None and body=None) a scramble-intercept breakpoint at gepard+off.
    body (hex) in LIVE mode is written over the slot body; dry logs only. idoff: id position relative
    to the pointer. lo/hi: only act when the pointer is in [lo, hi). persist (--inject merge): keep
    each consumer body and replace EVERY matching client action, instead of consuming it (one-shot).
    probe (--send-probe): one-shot, read-only - on the first recognised send capture the registers and
    a stack walk of return addresses (to find the client's callable send routine), then disarm."""
    if off is None and pc is None and body is None and not probe:
        return {'type': 'scramble'}
    m = {'type': 'scramble', 'reg': reg, 'dry': dry, 'idoff': idoff, 'persist': persist}
    if pc is not None:                 # absolute breakpoint address (e.g. unpacked client code in anon memory)
        m['pc'] = hex(pc)
    else:                              # offset from gepard.dll base (resolved agent-side)
        m['off'] = off
    if probe:
        m['probe'] = True
    if entry:
        m['entry'] = True          # probe a function ENTRY: capture on first hit, dump stack + arg derefs
    if ids:
        m['ids'] = list(ids)       # packet ids the probe gates on (default 0437/0438)
    if trace:
        m['trace'] = True; m['traceMax'] = int(trace)   # --scramble-trace: snapshot por byte (so envio)
    if anyid:
        m['anyid'] = True          # probe: capture the first in-range hit regardless of id (exclusive range)
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


def sendcall_msg(rva=None, module='uaRO.exe', cast_ms=800):
    """Call-based injection: arm (rva given) or disarm (rva=None) the client's SendPacket caller.
    rva is the offset from `module`'s base to SendPacket(this, len, buf); the agent resolves the base
    and captures `this` with a one-shot hardware breakpoint, then call-injects on the game thread."""
    if rva is None:
        return {'type': 'sendcall'}
    return {'type': 'sendcall', 'rva': rva, 'module': module, 'castMs': int(cast_ms)}


def trace_msg(ms=200, ualo=None, uahi=None, interno=False):
    """Rastreio com Stalker. Sem ualo/uahi: so teste de sobrevivencia (segue a thread principal por
    `ms` e desliga). Com a faixa do codigo uaRO: registra as chamadas uaRO->gepard na janela, ou,
    com interno=True, as chamadas uaRO->uaRO (para achar o manipulador de alto nivel do movimento)."""
    m = {'type': 'trace', 'ms': ms}
    if ualo is not None:
        m['ualo'], m['uahi'] = hex(ualo), hex(uahi)
    if interno:
        m['interno'] = True
    return m


def sendcall_emit_msg(data_hex):
    """Call-based injection: hand the agent one whole client->server packet (hex) to transmit via
    SendPacket. Queued and sent on the game thread; nothing here replaces a client packet."""
    return {'type': 'sendcall-emit', 'data': data_hex}


def conn_of(m):
    """The TCP connection a message belongs to (agent's local port; the server address if unknown)."""
    return m.get('conn', m['sock'])
