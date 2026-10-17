"""Frida Gadget connection, agent source loading and IPC message constructors."""
import os
import re
import subprocess
import sys
from . import ROOT


AGENT_JS = os.path.join(ROOT, 'agent', 'relay_hook_linux.js')
RESEARCH_JS = os.path.join(ROOT, 'agent', 'research_hooks.js')


def agent_source(research=False):
    """Operational hooks by default; experimental helpers require explicit opt-in."""
    with open(AGENT_JS) as f:
        source = f.read()
    if research:
        with open(RESEARCH_JS) as f:
            source += '\n' + f.read()
    return source
GADGET_PORTS = range(27052, 27100)                 # frida-gadget-32.config: 27052, pick-next on conflict


def gadget_ports():
    """[(port, pid, argv0)] for every listening frida gadget."""
    out = subprocess.run(['ss', '-Hltnp'], capture_output=True, text=True).stdout
    res = []
    for line in out.splitlines():
        m = re.search(r'127\.0\.0\.1:(\d+)\s.*pid=(\d+)', line)
        if not m or int(m.group(1)) not in GADGET_PORTS:
            continue
        port, pid = int(m.group(1)), int(m.group(2))
        try:
            with open(f'/proc/{pid}/cmdline', 'rb') as f:
                argv0 = f.read().split(b'\0')[0].decode(errors='replace')
        except OSError:
            argv0 = '?'
        res.append((port, pid, argv0))
    return res


def pick_port(name):
    ports = gadget_ports()
    for port, pid, argv0 in ports:
        print(f'[*] gadget :{port}  pid {pid}  {argv0}')
    for port, pid, argv0 in ports:
        if argv0.replace('\\', '/').lower().endswith('/' + name.lower()):
            return port
    sys.exit(f'[!] no gadget inside {name} - is the client running with the LD_PRELOAD launch option?')


def pid_of_port(port):
    return next((p for pt, p, _ in gadget_ports() if pt == port), None)


class Agent:
    """Connection to relay_hook_linux.js inside the game. `on_message(payload)` receives each
    agent message (a dict; a binary attachment is in payload['data']) on Frida's thread, so
    it must only queue it."""

    def __init__(self, port, on_message, *, research=False):
        import frida                                   # only needed at run time, not by the tests
        self._frida = frida
        self._on_message = on_message
        print(f'[*] connecting to gadget on 127.0.0.1:{port}')
        dev = frida.get_device_manager().add_remote_device(f'127.0.0.1:{port}')
        self.session = dev.attach('Gadget')
        self.session.on('detached', self._detached)
        self.script = self.session.create_script(agent_source(research))
        self.script.on('message', self._message)

    def _message(self, msg, data):
        if msg['type'] == 'send' and isinstance(msg['payload'], dict):
            if data is not None:
                msg['payload']['data'] = data
            self._on_message(msg['payload'])
        elif msg['type'] == 'error':
            print('[frida error]', msg.get('stack') or msg.get('description'))

    @staticmethod
    def _detached(reason, crash):
        print(f'[!] detached: {reason}')
        os._exit(1)

    def load(self):
        self.script.load()

    def post(self, msg):
        self.script.post(msg)

    def unload(self):
        """Disarm hardware breakpoints explicitly before unloading the Frida script.

        A JS rpc.exports.dispose function is not called automatically by Script.unload().
        Never leave cleanup to implicit script disposal: a remaining hardware breakpoint
        without its exception handler can crash the client on the next hit.
        """
        try:
            self.script.exports_sync.dispose()
        except Exception as e:
            # A detached or failed agent may not answer RPC; unloading is still required.
            # Do not log arbitrary remote exception messages (they may contain private data).
            print(f'[!] agent dispose failed: {type(e).__name__}')
        finally:
            try:
                self.script.unload()
            except self._frida.InvalidOperationError:
                pass


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


def sendcall_msg(rva=None, module='uaRO.exe'):
    """Call-based injection: arm (rva given) or disarm (rva=None) the client's SendPacket caller.
    rva is the offset from `module`'s base to SendPacket(this, len, buf); the agent resolves the base
    and captures `this` with a one-shot hardware breakpoint, then call-injects on the game thread."""
    if rva is None:
        return {'type': 'sendcall'}
    return {'type': 'sendcall', 'rva': rva, 'module': module}


def move_dispatch_msg(x=None, y=None, arm=False, disarm=False, recapture=False, dispatcher=None, site=None):
    """Native-dispatch (PoC 035f): arm the passive capture of the movement dispatcher's `this`
    (arm=True, optional dispatcher/site as hex strings), disarm, recapture (reset a stale `this`
    after a reconnect/relogin and re-arm the passive capture), or request a walk to (x, y). The
    client itself then builds, encrypts and sends its own 035f; the relay never forges a body."""
    m = {'type': 'native-dispatch'}
    if disarm:
        m['disarm'] = True
    elif recapture:
        m['recapture'] = True
    elif arm:
        m.update(arm=True, recipe='walk-035f')
        if dispatcher:
            m['dispatcher'] = int(dispatcher, 16)
        if site:
            m['site'] = int(site, 16)
    else:
        m.update(recipe='walk-035f', args={'x': int(x), 'y': int(y)})
    return m


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
