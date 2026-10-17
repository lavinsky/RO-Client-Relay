"""Importing consolidated packet helpers must not start client/process I/O."""
import subprocess
import sys
from pathlib import Path

root = Path(__file__).resolve().parents[1]
code = r'''
import builtins
import importlib
import os
import pkgutil
import socket
import subprocess
import sys
import relay

def denied(*args, **kwargs):
    raise AssertionError('import attempted socket/process/memory I/O')

socket.socket = denied
socket.create_connection = denied
subprocess.run = denied
subprocess.Popen = denied
os.open = denied
original_import = builtins.__import__
def guarded_import(name, *args, **kwargs):
    if name == 'frida' or name.startswith('frida.'):
        raise AssertionError('Frida must be imported only on explicit connection')
    return original_import(name, *args, **kwargs)
builtins.__import__ = guarded_import

for item in pkgutil.iter_modules(relay.__path__):
    importlib.import_module('relay.' + item.name)
import relay_capture_linux
from relay.actor_recovery import valid_actor
from relay.frida_bridge import scramble_set_msg
from relay.packet_pipeline import pack_move, unpack_move
assert unpack_move(pack_move(150, 187))[:2] == (150, 187)
assert scramble_set_msg(0x438, '0a00')['body'] == '0a00'
assert not valid_actor(b'')
assert 'frida' not in sys.modules
'''
subprocess.run([sys.executable, '-c', code], cwd=root, check=True)
print('PASS: consolidated imports and pure helpers perform no socket/process/memory I/O')
