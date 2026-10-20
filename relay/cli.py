"""Command line: parse options, build the feed, connect to the agent, run until stdin closes."""
import argparse
import os
import signal
import sys

from . import ROOT
from .agent import Agent, pick_port, pid_of_port
from .config import DEFAULT_CONFIG, load_config_defaults
from .console import CaptureLog
from .packets import WireFilter, load_lengths
from .relay import Relay
from .runtime import Capture

DEFAULT_LENGTHS = os.path.join(ROOT, 'data', 'uaro_recvpackets.txt')


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
    ap.add_argument('--drop-ids', default='4754,5395,09fd,09ff',
                    help='comma-separated hex packet ids to omit from the feed (whole-packet, stays aligned). '
                         'Default 4754/5395 = Gepard control handled by the client, absent from the consumer\'s '
                         'RO packet table; 09fd/09ff = actor packets whose bodies are encrypted (only reach the consumer '
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
                         '(XKore "S" frames) and have the client transmit them. For a client/server '
                         'you control. With --scramble-bp, each packet\'s body is substituted at the '
                         'scrambler BP (pre-XOR, one-shot) so the client\'s own scrambler encrypts it '
                         '- the correct path for 035f. Combine with --inject-call to route 035f by the '
                         'merge and 0437/0438 by the client SendPacket. Without --scramble-bp the '
                         'scrambler is auto-discovered at runtime (needs --send-watch).')
    ap.add_argument('--inject-call', action=argparse.BooleanOptionalAction, default=False,
                    help='SPONTANEOUS injection (no client packet replaced): call the client\'s own '
                         'SendPacket(this,len,buf) with each consumer "S" packet, so the client builds, '
                         'encrypts and sends it through its normal path. Captures `this` once via a '
                         'hardware breakpoint and calls on the game thread. For a client you own.')
    ap.add_argument('--map-settle-ms', type=int, default=1500,
                    help='Milliseconds after map transition before recapturing native contexts (default 1500).')
    ap.add_argument('--sendcall-demand', action=argparse.BooleanOptionalAction, default=False,
                    help='EXPERIMENTAL: schedule an immediate SendPacket drain on the captured game thread. '
                         'Disabled by default; --no-sendcall-demand restores existing socket-event drain.')
    ap.add_argument('--sendpacket-rva', default='816640',
                    help='--inject-call: hex RVA of SendPacket(this,len,buf) from the client EXE base '
                         '(default 0x816640, discovered for this uaRO build). Resolved against --sendpacket-module.')
    ap.add_argument('--sendpacket-module', default='uaRO.exe',
                    help='--inject-call: the module whose base --sendpacket-rva is relative to.')
    ap.add_argument('--target-select', action=argparse.BooleanOptionalAction, default=False,
                    help='emit a 0368 (CZ_REQNAME_BYGID) select-by-GID before a targeted action (0437 '
                         'attack / 0438 skill), on BOTH the client-SendPacket path and the --action-merge '
                         'path (the 0368 goes out via SendPacket, the action by its own route). Dedup by '
                         'GID. OFF by default: the action already carries the GID and live tests fired with '
                         'and without the 0368 (refuted as a fix). Enable to re-try the click-mimic.')
    ap.add_argument('--action-merge', action=argparse.BooleanOptionalAction, default=False,
                    help='--inject-call + --scramble-bp: route consumer 0437/0438/0af4 to the scrambler '
                         'merge (one-shot body map, like 035f) instead of the client SendPacket. OFF by '
                         'default. Routing only; the client must itself build that id for it to be sent.')
    ap.add_argument('--synth-input', action=argparse.BooleanOptionalAction, default=False,
                    help='atuador de tecla sintética integrado ao relay (OFF por padrão): quando uma '
                         'ação do consumidor (0437/0438/0af4) é armada no merge, injeta a tecla '
                         '(uinput/ydotool, passa no Gepard) que faz o CLIENTE montar o carrier, que o '
                         'scrambler reescreve. Substitui o sidecar action_trigger.py. Requer ydotoold '
                         'rodando e a janela do cliente focável; efeito colateral = input real no seat0.')
    ap.add_argument('--synth-backend', choices=('ydotool', 'gamescope-eis'), default='ydotool',
                    help='--synth-input: ydotool/seat0 (legado) ou Gamescope EIS isolado; '
                         'o backend EIS não foca janelas KDE nem usa ydotool.')
    ap.add_argument('--synth-eis-socket', default='',
                    help='--synth-backend gamescope-eis: socket privado LIBEI_SOCKET da sessão Gamescope.')
    ap.add_argument('--synth-eis-socket-file', default='',
                    help='--synth-backend gamescope-eis: arquivo privado 0600 contendo o '
                         'LIBEI_SOCKET criado pelo wrapper de inicialização.')
    ap.add_argument('--synth-wid', default='',
                    help='--synth-input: id (hex wmctrl) da janela do cliente a focar; vazio = autodetecta '
                         'pelo título (world of your dream / uaRO / gepard shield / steam_app_).')
    ap.add_argument('--itemuse-input', action=argparse.BooleanOptionalAction, default=False,
                    help='Before each consumer 0439, synchronously press a game key and release it.')
    ap.add_argument('--itemuse-input-key', default='END',
                    help='Game key pressed before SendPacket 0439 (default END).')
    ap.add_argument('--synth-key-0437', default='INSERT',
                    help='--synth-input: tecla para armar o carrier do 0437 (ataque). Default INSERT.')
    ap.add_argument('--synth-key-0438', default='9',
                    help="--synth-input: tecla para o 0438 (perícia em alvo). Default '9' da fileira de "
                         'cima (KEY_9=10), NÃO o do numpad.')
    ap.add_argument('--synth-key-0af4', default='F2',
                    help='--synth-input: tecla para o 0af4 (perícia no chão). Default F2.')
    ap.add_argument('--synth-debounce-ms', type=int, default=500,
                    help='--synth-input: intervalo mínimo entre disparos da MESMA ação (anti-repetição '
                         'quando o consumidor re-arma o mesmo id em rajada). Default 500.')
    ap.add_argument('--synth-dry', action=argparse.BooleanOptionalAction, default=False,
                    help='--synth-input: não injeta a tecla; só registra o que faria (teste).')
    ap.add_argument('--move-dispatch', action=argparse.BooleanOptionalAction, default=False,
                    help='PoC (needs --inject): on a consumer 035f, fire the client\'s native movement '
                         'dispatcher (frame 0x11) from a main-loop PE site so the CLIENT builds, encrypts '
                         'and sends its own 035f. Uses DR2/DR3; keep --no-send-watch.')
    ap.add_argument('--move-dispatch-ptr', default='0xd473b0', help='--move-dispatch: dispatcher address (hex)')
    ap.add_argument('--move-dispatch-site', default='0x4dcba0', help='--move-dispatch: PE main-loop fire site (hex)')
    ap.add_argument('--inject-persist', action=argparse.BooleanOptionalAction, default=False,
                    help='--inject + --scramble-bp: keep each consumer packet and replace EVERY matching '
                         'client action of that id (persistent hijack), instead of one-shot per packet. '
                         'Clear by stopping the driver or sending an empty body.')
    ap.add_argument('--egress-queue', action=argparse.BooleanOptionalAction, default=False,
                    help='--move-dispatch: serialize consumer packets through one FIFO drain so a 035f '
                         'native dispatch never overlaps a 0437/0438 action (the real-client/xKore ordered '
                         'stream does this for free; our PoC fans each id into an async client-side path). '
                         'Preserves arrival order; paces by --egress-interval-ms and holds longer after an '
                         'action (--egress-action-gap-ms) so the synthetic key lands on a settled char. OFF.')
    ap.add_argument('--egress-interval-ms', type=int, default=400,
                    help='--egress-queue: milliseconds between consecutive dispatched packets (default 400).')
    ap.add_argument('--egress-action-gap-ms', type=int, default=400,
                    help='--egress-queue: extra settle gap after dispatching an action (0437/0438/0af4), so '
                         'the client commits it before the next 035f walk resumes (default 400).')
    ap.add_argument('--egress-max-age-ms', type=int, default=800,
                    help='--egress-queue: drop a queued packet instead of dispatching it once it has waited '
                         'longer than this (stale walk requests to old coords pile up when the queue backs '
                         'up). 0 disables the drop (default 800).')
    ap.add_argument('--cast-throttle', type=float, default=0.8,
                    help='--inject-call: minimum seconds between injected cast-time skills (0438/0af4). '
                         'The consumer retries a skill many times; without this they flush back-to-back '
                         'and each cast cancels the previous. 0 disables (default 0.8).')
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
    ap.add_argument('--probe-ids', default='0437,0438',
                    help='comma-separated hex packet ids the probes gate on (default 0437,0438). e.g. 035f to '
                         'map the walk send path, together with --scramble-range set to the stack region.')
    ap.add_argument('--trace-test', type=int, default=0, metavar='MS',
                    help='Stalker (pesquisa): teste de sobrevivencia - segue a thread principal por MS '
                         'milissegundos so contando eventos, depois desliga. Verifica se o gepard tolera '
                         'o Stalker antes do rastreio completo. ARRISCADO num cliente protegido.')
    ap.add_argument('--trace-walk', type=int, default=0, metavar='MS',
                    help='Stalker (pesquisa): segue por MS ms e registra as chamadas do codigo do uaRO '
                         '(anon 0x401000) para dentro do gepard. Rode parado e depois andando e compare '
                         'para achar a chamada do envio do 035f. ARRISCADO; use janelas curtas.')
    ap.add_argument('--trace-internal', type=int, default=0, metavar='MS',
                    help='Stalker (pesquisa): como --trace-walk, mas registra as chamadas uaRO->uaRO '
                         '(internas) para achar o manipulador de alto nivel do movimento. Volume maior; '
                         'use janelas bem curtas (300-500ms). ARRISCADO.')
    ap.add_argument('--probe-anyid', action='store_true',
                    help='--send-probe: capture the first hit whose pointer is inside --scramble-range, '
                         'regardless of packet id (use when the id offset is unknown, e.g. mapping 035f on the '
                         'stack; the range must be exclusive to the target, like the thread stack).')
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
    ap.add_argument('--scramble-trace', type=int, default=0,
                    help='--scramble-bp: captura passo-a-passo (snapshot da tabela/posicoes por byte, '
                         'so no fluxo de envio em --scramble-range); valor = teto de disparos (auto-desarma)')
    ap.add_argument('--scramble-range', default='',
                    help='--scramble-bp: hex LO-HI; only act when the pointer is in this range (e.g. the stack '
                         'region for 035f, to skip the shared primitive\'s recv-decrypt hits)')
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
    capture.arm_move_dispatch()                        # native movement dispatcher, if --move-dispatch
    capture.arm_sendcall()                             # capture SendPacket `this`, if --inject-call
    capture.arm_trace()                                # Stalker trace, if --trace-test / --trace-walk
    if capture.send_watch_waiting:
        print('[*] send watch: waiting for the recv ring to locate the send queue')
    print(f'[*] capturing -> {a.out}  (Ctrl-C to stop)')

    def _on_term(signum, frame):                       # pkill/SIGTERM -> same clean path as Ctrl-C,
        raise KeyboardInterrupt                         # so the finally still runs agent.unload() ->
    signal.signal(signal.SIGTERM, _on_term)             # dispose() clears the debug registers

    def _on_usr1(signum, frame):                       # re-arma o trace sob demanda (abrir a janela
        capture.arm_trace()                             # na hora de clicar; repetir sem reiniciar)
    signal.signal(signal.SIGUSR1, _on_usr1)

    try:
        sys.stdin.read()                               # hold stdin open (tail -f /dev/null | ...)
    except KeyboardInterrupt:
        pass
    finally:
        agent.unload()
