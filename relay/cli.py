"""Command line: parse options, build the feed, connect to the agent, run until stdin closes."""
import argparse
import os
import signal
import sys

from . import ROOT
from .agent import Agent, pick_port, pid_of_port
from .console import CaptureLog
from .packets import WireFilter, load_lengths
from .relay import Relay
from .runtime import Capture

DEFAULT_LENGTHS = os.path.join(ROOT, 'uaro_recvpackets.txt')
DEFAULT_CONFIG = os.path.join(ROOT, 'relay_capture.conf')


def _config_value(act, val):
    """Convert a config string to the type the option expects (bool / int / float / str)."""
    if isinstance(act, (argparse._StoreTrueAction, argparse._StoreFalseAction,
                        argparse.BooleanOptionalAction)):
        s = val.strip().lower()
        if s in ('1', 'true', 'yes', 'on'):
            return True
        if s in ('0', 'false', 'no', 'off'):
            return False
        raise ValueError(val)
    if act.type in (int, float):
        return act.type(val)
    return val


def load_config_defaults(parser, path):
    """Use an INI file's [capture] section as argparse defaults, so the script runs with no launch
    options. Precedence: built-in defaults < config file < command line. A missing/!unreadable file
    is ignored (built-in defaults stand). Keys are long option names (dashes or underscores)."""
    import configparser
    cp = configparser.ConfigParser(inline_comment_prefixes=('#', ';'))
    try:
        if not cp.read(path) or not cp.has_section('capture'):
            return
    except configparser.Error as e:
        print(f'[!] ignoring config {path}: {e}')
        return
    by_name = {opt[2:].replace('-', '_'): act          # --relay-format -> relay_format
               for act in parser._actions for opt in act.option_strings if opt.startswith('--')}
    defaults = {}
    for key, val in cp.items('capture'):
        act = by_name.get(key.replace('-', '_'))
        if act is None:
            print(f'[!] config: unknown setting "{key}" (ignored)')
            continue
        try:
            defaults[act.dest] = _config_value(act, val)
        except ValueError:
            print(f'[!] config: bad value for "{key}": {val!r} (ignored)')
    if defaults:
        parser.set_defaults(**defaults)
        print(f'[*] config: loaded {len(defaults)} settings from {path} (CLI options override these)')


def parse_args(argv=None):
    ap = argparse.ArgumentParser(description='Feed the uaRO client\'s packet stream to the consumer (XKore 1).')
    ap.add_argument('--config', default=DEFAULT_CONFIG,
                    help='INI file of default settings ([capture] section); CLI options override it. '
                         'Missing file = built-in defaults.')
    ap.add_argument('--name', default='uaRO.exe')
    ap.add_argument('--port', type=int)
    ap.add_argument('--out', default=os.path.join(ROOT, 'relay_log.jsonl'))
    ap.add_argument('--relay', default='127.0.0.1:2350',
                    help='feed decrypted server->client packets to this host:port ("" disables). '
                         'Default is the consumer XKore 1 listener (XKore_port, default 2350).')
    ap.add_argument('--relay-format', choices=['xkore1', 'raw'], default='xkore1',
                    help='xkore1 = the consumer X-Kore "R" frames (observation feed); raw = unframed bytes')
    ap.add_argument('--recvpackets', default=DEFAULT_LENGTHS,
                    help='packet-length table (the consumer recvpackets.txt format) for boundary-aligned feeding; '
                         '"" disables alignment')
    ap.add_argument('--drop-ids', default='09fd,09ff',
                    help='comma-separated hex packet ids to omit from the feed (whole-packet, stays aligned). '
                         'Default 09fd/09ff = actor packets whose bodies are encrypted (only reach the consumer '
                         'once --decrypt-actors has verified them). Global chat (02c1, npc_chat/#main) is fed; '
                         'add 02c1 here if the consumer crashes on chat from off-map senders.')
    ap.add_argument('--feed-send', action=argparse.BooleanOptionalAction, default=True,
                    help='feed client->server packets to the consumer as XKore "S" frames so it sees a full '
                         'bidirectional session. Still observation-only: the consumer\'s own outgoing frames are '
                         'discarded, nothing reaches the real server. --no-feed-send keeps the recv-only "R" feed.')
    ap.add_argument('--decrypt-actors', action=argparse.BooleanOptionalAction, default=True,
                    help='--wire: fill in the encrypted 09fd/09ff bodies from the client\'s decrypted '
                         'recv ring (verified against the cleartext stream; unverifiable ones are dropped)')
    ap.add_argument('--actor-delay', type=float, default=0.15,
                    help='max seconds a chunk with 09fd/09ff is held waiting for its decrypted copy '
                         '(later chunks queue behind it, so the consumer still gets the exact stream order)')
    ap.add_argument('--probe-actors', action='store_true',
                    help='--wire: locate the decrypted 09fd/09ff bodies in client memory and report ([probe])')
    ap.add_argument('--actor-diag', action='store_true',
                    help='--decrypt-actors: report when/where each decrypted 09fd/09ff copy appears in the '
                         'ring ([diag] lines; read-only timing study)')
    ap.add_argument('--send-watch', action=argparse.BooleanOptionalAction, default=True,
                    help='--wire: recover the encrypted 0437 action / 0438 skill sends with a hardware '
                         'watchpoint on the client send queue and feed them as plaintext "S" frames; '
                         'unrecovered ones and 035f walks are dropped instead of fed as ciphertext. '
                         '--no-send-watch = feed the wire bytes')
    ap.add_argument('--send-queue', default='auto',
                    help='hex lo-hi of the block holding the client send queue (--send-watch). Default '
                         '"auto" = the recv-ring block ActorDecrypt finds at runtime (the queue lives there)')
    ap.add_argument('--inject', action=argparse.BooleanOptionalAction, default=False,
                    help='WRITE path (off by default): take the packets the consumer sends back '
                         '(XKore "S" frames) and inject them so the client transmits them. '
                         'For a client/server you control. With --scramble-bp, each packet\'s body '
                         'is substituted at the scrambler BP (pre-XOR, one-shot) so the client\'s own '
                         'scrambler encrypts it - the correct path for encrypted ids (035f/0437/0438). '
                         'Without --scramble-bp it writes straight into the send queue via '
                         '/proc/<pid>/mem (same block as --send-watch; --send-queue to override).')
    ap.add_argument('--inject-dry-run', action='store_true',
                    help='--inject: log what would be written (INJECT-DRY) without touching the client')
    ap.add_argument('--inject-call', action=argparse.BooleanOptionalAction, default=False,
                    help='SPONTANEOUS injection (no client packet replaced): call the client\'s own '
                         'SendPacket(this,len,buf) with each consumer "S" packet, so the client builds, '
                         'encrypts and sends it through its normal path. Captures `this` once via a '
                         'hardware breakpoint and calls on the game thread. For a client you own.')
    ap.add_argument('--sendpacket-rva', default='816640',
                    help='--inject-call: hex RVA of SendPacket(this,len,buf) from the client EXE base '
                         '(default 0x816640, discovered for this uaRO build). Resolved against --sendpacket-module.')
    ap.add_argument('--sendpacket-module', default='uaRO.exe',
                    help='--inject-call: the module whose base --sendpacket-rva is relative to.')
    ap.add_argument('--inject-persist', action=argparse.BooleanOptionalAction, default=False,
                    help='--inject + --scramble-bp: keep each consumer packet and replace EVERY matching '
                         'client action of that id (persistent hijack), instead of one-shot per packet. '
                         'Clear by stopping the driver or sending an empty body.')
    ap.add_argument('--send-probe', action='store_true',
                    help='--inject research (read-only): instead of injecting, arm a one-shot breakpoint '
                         'on the scrambler store and, on the first 0437/0438 send, capture the registers '
                         'and a stack walk of return addresses (module+offset + nearest prologue), then '
                         'disarm. Maps the client send routine for call-based injection (logs SCRAMBLE/probe).')
    ap.add_argument('--probe-entry', default='',
                    help='research (read-only): hex OFFSET from gepard.dll base of a function entry. Arms a '
                         'one-shot breakpoint there and, on the first call, captures the registers, the top '
                         'of the stack (args/return addr) and the bytes each points at, then disarms. Used to '
                         'learn a send routine\'s calling convention (logs SCRAMBLE/entry).')
    ap.add_argument('--probe-at', default='',
                    help='research (read-only): like --probe-entry but an ABSOLUTE hex address (for unpacked '
                         'client code in anonymous memory, not gepard-relative). With --scramble-range it only '
                         'fires on a call whose args reference a 0437/0438 in that range.')
    ap.add_argument('--scramble-bp', default='',
                    help='scramble-intercept (injects a valid encrypted client->server packet): hex OFFSET '
                         'from gepard.dll base of the scrambler store. A hardware exec breakpoint there '
                         'rewrites the slot plaintext before it is encrypted. Needs the gadget pid; forces '
                         '--no-send-watch (shares the debug registers). For a client you own. '
                         'LEFT EMPTY with --inject (the default): the scrambler is AUTO-DISCOVERED at '
                         'runtime (send-watch finds the pc on the first 0437/0438, then reg/idoff/range '
                         'self-locate). Set it (with --scramble-reg/-idoff/-range) to pin and skip discovery.')
    ap.add_argument('--scramble-reg', default='edi',
                    help='--scramble-bp: register (edi/esi/...) or stack slot (sN=[esp+4N]) holding the pointer')
    ap.add_argument('--scramble-id', default='035f', help='--scramble-bp: packet id to target (hex)')
    ap.add_argument('--scramble-idoff', type=int, default=0,
                    help='--scramble-bp: signed byte offset from the pointer to the packet id. 0 = pointer at '
                         'packet start; -2 = pointer at body[0] (id just before it). Body is written at id+2.')
    ap.add_argument('--scramble-range', default='',
                    help='--scramble-bp: hex LO-HI; only act when the pointer is in this range (e.g. the stack '
                         'region for 035f, to skip the shared primitive\'s recv-decrypt hits)')
    ap.add_argument('--inject-walk', default='',
                    help='--scramble-bp: "X,Y[,DIR]" to inject as the move body (LIVE). Omit = DRY '
                         '(log the slot bytes + registers, write nothing)')
    ap.add_argument('--feed-dump', default='',
                    help='append every framed byte sent to the consumer to this file (offline replay)')
    pre, _ = ap.parse_known_args(argv)                 # find --config first, then fold it in as defaults
    load_config_defaults(ap, pre.config)
    return ap.parse_args(argv)                          # CLI options still override the config


def parse_ids(spec):
    ids = set()
    for t in spec.split(','):
        try:
            ids.add(int(t.strip(), 16))
        except ValueError:
            pass
    return ids


def read_lengths(path, required):
    """The packet-length table, {} if absent; `required` (the wire path) falls back to the default
    table and exits if there is none."""
    lengths = {}
    if path:
        try:
            lengths = load_lengths(path)
            print(f'[*] loaded {len(lengths)} packet lengths from {path} (boundary-aligned feed)')
        except OSError:
            print(f'[*] no {path}; feeding without packet alignment')
    if required and not lengths:                       # the wire filter always needs the table
        try:
            lengths = load_lengths(DEFAULT_LENGTHS)
        except OSError:
            sys.exit(f'[!] --wire needs a packet-length table; {DEFAULT_LENGTHS} is missing')
    return lengths


def build_feed(a, drop):
    """(Relay, WireFilter) for the options; (None, None) without --relay."""
    if not a.relay:
        return None, None
    host, _, port = a.relay.rpartition(':')
    host = host or '127.0.0.1'
    lengths = read_lengths(a.recvpackets, required=True)
    wire = WireFilter(lengths, drop)
    relay = Relay(host, int(port), a.relay_format)       # unaligned: the filter tokenizes
    print('[*] feeding cleartext wire bytes, per-connection tokenized')
    if a.feed_dump:
        relay.dump = open(a.feed_dump, 'wb')
    print(f'[*] feeding decrypted server->client packets -> {host}:{port} ({a.relay_format})')
    if drop:
        print(f'[*] dropping packet ids from feed: {", ".join("%04x" % d for d in sorted(drop))}')
    return relay, wire


def main(argv=None):
    a = parse_args(argv)
    relay, wire = build_feed(a, parse_ids(a.drop_ids))

    port = a.port or pick_port(a.name)
    pid = pid_of_port(port)
    reads_memory = wire is not None and (a.decrypt_actors or a.probe_actors)
    if pid is None and reads_memory:
        sys.exit(f'[!] no process found listening on gadget port {port} (needed to read its memory)')

    log = CaptureLog(a.out)
    capture = None

    def on_message(payload):                           # Frida's thread: queue only
        capture.work.put(payload)

    agent = Agent(port, on_message)
    capture = Capture(a, pid, relay, wire, log, agent.post)
    capture.start()
    agent.load()                                       # messages start flowing here
    capture.update_send_watch()
    capture.arm_scramble()                             # exec breakpoint at gepard+off, if --scramble-bp
    capture.arm_sendcall()                             # capture SendPacket `this`, if --inject-call
    if capture.send_watch_waiting:
        print('[*] send watch: waiting for the recv ring to locate the send queue')
    print(f'[*] capturing -> {a.out}  (Ctrl-C to stop)')

    def _on_term(signum, frame):                       # pkill/SIGTERM -> same clean path as Ctrl-C,
        raise KeyboardInterrupt                         # so the finally still runs agent.unload() ->
    signal.signal(signal.SIGTERM, _on_term)             # dispose() clears the debug registers

    try:
        sys.stdin.read()                               # hold stdin open (tail -f /dev/null | ...)
    except KeyboardInterrupt:
        pass
    finally:
        agent.unload()
