"""Operational OpenKore-to-client relay components.

cli                  INI defaults, command line and process lifecycle
frida_bridge         Gadget connection and agent IPC message constructors
capture_runtime      event worker, receive state and session coordination
client_dispatch      client command routing, readiness and cancellation
packet_pipeline      RO packet framing and ordered receive/send feed
actor_recovery       verified actor plaintext and read-only process memory
xkore_transport      OpenKore socket, XKore frames and connection generations
synthetic_input      natural carriers through window focus and uinput
traffic_safety       credential redaction and HTTP/login traffic policy
event_log            sanitized JSONL and normal/verbose console
send_recovery        optional send-watch plaintext recovery
research_diagnostics optional probes and timing diagnostics
"""
import os

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
