"""Driver side of the uaRO capture tool. ARCHITECTURE.md maps the modules.

Modules, in the order data flows through them:
  protocol     message shapes shared with the Frida agent (relay_hook_linux.js)
  agent        Frida connection: finds the gadget, loads the agent, posts to it
  packets      packet-length table + WireFilter (splits a TCP stream into packets)
  actors       ActorDecrypt: fills in encrypted 09fd/09ff bodies from client memory
  sendwatch    recovers plaintext of encrypted client->server packets
  wire_feed    default pipeline: RECV chunks -> ordered, filled-in feed
  relay        XKore framing + connection to the consumer
  safety       credential redaction and the one HTTP check
  console      sanitized JSONL log + console lines
  legacy       --no-wire memory-only path (RingMatcher, SendFinder, reorder buffer)
  research     --probe-actors / --actor-diag tools
  cli          options, wiring, threads
"""
import os

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))   # folder holding the scripts + data files
