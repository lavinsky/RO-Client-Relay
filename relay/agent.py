"""The Frida side: find the gadget inside the game, load the agent script, talk to it."""
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
        """Unload the agent; its dispose() clears the debug registers of the send watch."""
        try:
            self.script.unload()
        except self._frida.InvalidOperationError:
            pass
