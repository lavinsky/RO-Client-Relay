"""The Frida side: find the gadget inside the game, load the agent script, talk to it."""
import fcntl
import os
import re
import subprocess
import sys

from . import ROOT

AGENT_JS = os.path.join(ROOT, 'agent', 'relay_hook_linux.js')
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


def _acquire_port_lock(port):
    """Prevent two relay processes from attaching to the same Frida Gadget port."""
    runtime = os.environ.get('XDG_RUNTIME_DIR') or f'/tmp/ro-client-relay-{os.getuid()}'
    root = os.path.join(runtime, 'ro-client-relay')
    os.makedirs(root, mode=0o700, exist_ok=True)
    path = os.path.join(root, f'frida-{int(port)}.lock')
    f = open(path, 'a+', encoding='utf-8')
    try:
        fcntl.flock(f.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        f.seek(0)
        owner = f.read().strip() or '?'
        f.close()
        raise SystemExit(f'[!] Frida gadget :{port} is already owned by relay pid {owner}; refusing a second attach')
    f.seek(0); f.truncate(); f.write(str(os.getpid())); f.flush()
    return f


class Agent:
    """Connection to relay_hook_linux.js inside the game. `on_message(payload)` receives each
    agent message (a dict; a binary attachment is in payload['data']) on Frida's thread, so
    it must only queue it."""

    def __init__(self, port, on_message):
        import frida                                   # only needed at run time, not by the tests
        self._frida = frida
        self._on_message = on_message
        self._port_lock = _acquire_port_lock(port)
        try:
            print(f'[*] connecting to gadget on 127.0.0.1:{port}')
            dev = frida.get_device_manager().add_remote_device(f'127.0.0.1:{port}')
            self.session = dev.attach('Gadget')
            self.session.on('detached', self._detached)
            with open(AGENT_JS) as f:
                self.script = self.session.create_script(f.read())
            self.script.on('message', self._message)
        except BaseException:
            self._port_lock.close()
            self._port_lock = None
            raise

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
        """Unload script, detach the Frida session, then release the single-owner port lock."""
        try:
            self.script.unload()
        except self._frida.InvalidOperationError:
            pass
        try:
            self.session.detach()
        except self._frida.InvalidOperationError:
            pass
        if self._port_lock is not None:
            self._port_lock.close()
            self._port_lock = None
