#!/usr/bin/env python3
"""
relay_capture_linux.py - reassemble the client's packet stream and feed it to the consumer.

The packet bodies are encrypted on the wire, so the Frida agent (relay_hook_linux.js) hooks
libc recvmsg/sendmsg in the Wine process, and this driver turns what it reports into a clean
ordered packet stream for the consumer (XKore 1), reading the client's own DECRYPTED copies out
of /proc/<pid>/mem for the few encrypted parts. The code lives in the
`relay` package; ARCHITECTURE.md maps it.

RUN: ./run.sh (main configuration; --wait handles lifecycle without a stdin pipe).

SETUP: Steam launch option LD_PRELOAD=.../frida-gadget/frida-gadget-32.so %command%
(ptrace attach crashes 32-bit Proton: dead %gs TLS -> Wine SIGSEGV handler dies on it).
"""
import os
import sys

# The package sits next to this file; make it importable even when this file is loaded by path
# from another directory (importlib spec_from_file_location, as the tests do).
_here = os.path.dirname(os.path.abspath(__file__))
if _here not in sys.path:
    sys.path.insert(0, _here)

# Re-exported so `from relay_capture_linux import X` (tests, relay_sendbp.py) keeps working.
from relay import ROOT as HERE                                             # noqa: F401
from relay.actor_recovery import ActorDecrypt, valid_actor                          # noqa: F401
from relay.frida_bridge import gadget_ports, pick_port                             # noqa: F401
from relay.cli import main
from relay.event_log import show                                              # noqa: F401
from relay.packet_pipeline import (MoveTracker, WireFilter, load_lengths,           # noqa: F401
                           pack_move, unpack_pos2)
from relay.xkore_transport import PacketAligner, Relay                                # noqa: F401
from relay.traffic_safety import LOGIN_SOCK, redact_login, sanitize                 # noqa: F401

# Historical imports remain available without loading research on the run.sh path.
def __getattr__(name):
    from importlib import import_module
    module = ('research_diagnostics' if name in ('ActorDiag', 'ActorProbe') else
              'send_recovery' if name in ('SEND_QUEUE_FALLBACK', 'SendWatch', 'packet_at',
                                     'plaintext_guess', 'send_queue_range') else None)
    if module is None:
        raise AttributeError(name)
    return getattr(import_module('relay.' + module), name)

if __name__ == '__main__':
    main()
