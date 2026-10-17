"""Driver side of the uaRO capture tool. ARCHITECTURE.md maps the modules.

Modules, in the order data flows through them:
  protocol     message shapes shared with the Frida agent (relay_hook_linux.js)
  agent        Frida connection: finds the gadget, loads the agent, posts to it
  packets      packet-length table + WireFilter + move packing/0087 decode (MoveTracker)
  actors       ActorDecrypt: fills in encrypted 09fd/09ff bodies from client memory
  sendwatch    recovers plaintext of encrypted client->server packets
  wire_feed    default pipeline: RECV chunks -> ordered, filled-in feed
  relay        XKore framing + connection to the consumer
  safety       credential redaction and the one HTTP check
  console      sanitized JSONL log + console lines
  research     --probe-actors / --actor-diag tools
  commands     bounded readiness, session cancellation and local measurements
  writeback    dispatcher movement, natural action merge and generic native fallback
  runtime      Capture: builds the components and routes agent messages
  config       loads the INI config as argparse defaults
  cli          options, wiring, threads
"""
import os

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))   # folder holding the scripts + data files
