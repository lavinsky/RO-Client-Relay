#!/usr/bin/env python3
"""
relay_capture_linux.py - reassemble the client's packet stream and feed it to the consumer.

The packet bodies are encrypted on the wire, so the Frida agent (relay_hook_linux.js) hooks
libc recvmsg/sendmsg in the Wine process, and this driver turns what it reports into a clean
ordered packet stream for the consumer (XKore 1), reading the client's own DECRYPTED copies out
of /proc/<pid>/mem for the few encrypted parts. The code lives in the
`relay` package; ARCHITECTURE.md maps it.

RUN (hold stdin open or the driver EOFs - see README):
  tail -f /dev/null | ~/.venv-frida/bin/python relay_capture_linux.py --port 27053 &
  # defaults: --relay 127.0.0.1:2350 (the consumer XKore_port) --relay-format xkore1 --feed-send

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
from relay.actors import ActorDecrypt, valid_actor                          # noqa: F401
from relay.agent import gadget_ports, pick_port                             # noqa: F401
from relay.cli import main
from relay.console import show                                              # noqa: F401
from relay.packets import (MoveTracker, WireFilter, load_lengths,           # noqa: F401
                           pack_move, unpack_pos2)
from relay.relay import PacketAligner, Relay                                # noqa: F401
from relay.research import ActorDiag, ActorProbe                            # noqa: F401
from relay.safety import LOGIN_SOCK, redact_login, sanitize                 # noqa: F401
from relay.sendwatch import (SendWatch, packet_at, plaintext_guess,       # noqa: F401
                              send_queue_range)

if __name__ == '__main__':
    main()
