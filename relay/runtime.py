"""Capture: builds the components the options ask for and routes agent messages to them.

Threads:
  Frida callback   Agent._message -> work queue (does nothing else, so the agent never waits)
  worker           Capture.run_worker: one message at a time, in agent order
  wire feeder      WireFeed.run (default path, with a relay)
  watchdog         LegacyPipeline.run_watchdog (--no-wire, with a relay)
  relay connect    inside Relay; short-lived discovery threads inside ActorDecrypt/legacy"""
import queue
import threading

from . import protocol
from .actors import ActorDecrypt
from .inject import InjectError, SendInjector
from .legacy import LegacyPipeline
from .memory import ProcessMemoryWriter
from .moves import MoveTracker, pack_move
from .protocol import scramble_msg, scramble_set_msg, sendcall_emit_msg, sendcall_msg, sendwatch_msg
from .research import ActorDiag, ActorProbe
from .sendwatch import SendWatch, send_queue_range
from .wire_feed import ClientSendFeed, WireFeed

# The send watch reports the scrambler's write pc one instruction PAST the in-place byte store
# (a data watchpoint traps after the write; the store `mov [reg],bl` is 2 bytes). The exec
# breakpoint must sit on the store itself, so the full plaintext is still present when it fires.
SCRAMBLE_STORE_BACK = 2


class Capture:
    def __init__(self, opts, pid, relay, wire, log, post):
        """opts: parsed CLI options. relay/wire: Relay and WireFilter, or None (no the consumer feed).
        post(msg): sends a message to the agent."""
        self.opts, self.relay, self.log, self.post = opts, relay, log, post
        self.work = queue.Queue()
        self.dec = self.sendwatch = self.moves = None
        self._sw_posted = None                         # (lo, hi) the send watch was last pointed at
        self._sw_lock = threading.Lock()
        self.gepard_base = None                        # gepard.dll base (from the GEPARD message)
        pe, pa = getattr(opts, 'probe_entry', ''), getattr(opts, 'probe_at', '')
        if pe or pa:                                   # research: one-shot capture of a function's entry args
            lo = hi = None                             # optional gate: only a call whose args hit this range
            if getattr(opts, 'scramble_range', ''):
                lo, hi = (int(x, 16) for x in opts.scramble_range.split('-'))
            self.scramble = {'reg': 'auto', 'pid': int(opts.scramble_id, 16), 'body': None,
                             'dry': False, 'idoff': 0, 'lo': lo, 'hi': hi, 'persist': False,
                             'probe': True, 'entry': True}
            if pa:                                     # absolute address (unpacked client code in anon memory)
                self.scramble['pc'] = int(pa, 16)
                where = f"0x{self.scramble['pc']:x}"
            else:                                      # offset from gepard.dll base
                self.scramble['off'] = int(pe, 16)
                where = f"gepard+0x{self.scramble['off']:x}"
            gate = f' gated to a 0437/0438 copy into 0x{lo:x}-0x{hi:x}' if lo is not None else ' (first call)'
            print(f'[*] --probe-entry: one-shot capture of args at {where}{gate}, read-only')
        else:
            self.scramble = self._scramble_cfg(opts)   # scramble-intercept config, or None
        feed_send = bool(opts.feed_send and relay and opts.relay_format == 'xkore1')
        if feed_send and getattr(opts, 'inject', False):
            # feeding client->server packets to the consumer, which echoes them back as "S" frames,
            # would re-inject the client's own sends in a loop (observed: floods the server, drops the
            # session). Injection and send-feed are mutually exclusive.
            print('[!] --inject is on: disabling --feed-send to avoid a re-inject feedback loop')
            feed_send = False

        if opts.wire:
            self.dec = ActorDecrypt(pid) if (opts.decrypt_actors and wire) else None
            probe = ActorProbe(pid) if (opts.probe_actors and wire) else None
            diag = ActorDiag(self.dec) if (self.dec and opts.actor_diag) else None
            # scramble intercept, call-inject and the full send watch all need the debug registers.
            uses_dbg = self.scramble or getattr(opts, 'inject_call', False)
            self.sendwatch = SendWatch() if (opts.send_watch and not uses_dbg) else None
            if self.dec:
                print(f'[*] --decrypt-actors: 09fd/09ff bodies from the client recv ring (hold <= {opts.actor_delay*1000:.0f}ms)')
                self.dec.on_ring = self._on_ring_found
            self.moves = MoveTracker(log)              # decode the server's cleartext 0087 move dest
            recv_cbs = ([probe.on_packet] if probe else []) + [self.moves.on_recv_packet]
            wire.on_packet = recv_cbs[0] if len(recv_cbs) == 1 else \
                (lambda c, p, o, k: [cb(c, p, o, k) for cb in recv_cbs])
            print('[*] walk logging: decoding the server 0087 move destination (MOVE-CHECK)')
            if probe:
                print('[*] --probe-actors: locating decrypted 09fd/09ff in client memory')
            if self.sendwatch:
                print('[*] --send-watch: 0437/0438 plaintext from the client send queue (hardware watchpoint); '
                      '035f + unrecovered dropped')
            self.recv_path = WireFeed(wire, relay, log, post, dec=self.dec, diag=diag, probe=probe,
                                      actor_delay=opts.actor_delay, report_stats=self.report_stats)
            self.send_path = ClientSendFeed(relay, feed_send, self.sendwatch)
        else:
            find_send = opts.find_send or feed_send
            if find_send:
                print('[*] --find-send: locating client plaintext send buffer (logs SEND-PLAIN)')
            self.recv_path = self.send_path = LegacyPipeline(pid, relay, log, post, feed_send, find_send)
        if feed_send:
            print('[*] --feed-send: relaying client->server packets to the consumer as "S" frames '
                  '(bidirectional observation; nothing reaches the real server)')

        # Write path (opt-in): packets the consumer sends back are injected into the client.
        # With a scramble BP armed (--inject + --scramble-bp) they are substituted into the slot
        # pre-XOR so the client's own scrambler encrypts them (the only correct timing); otherwise
        # SendInjector writes them straight into the send queue via /proc/<pid>/mem.
        self.injector = None
        self.sendcall_rva = None                       # --inject-call: SendPacket RVA (set below)
        self.autodiscover = False                      # discovering the scrambler at runtime
        self._scramble_armed = self.scramble is not None
        self._disc_lock = threading.Lock()
        if getattr(opts, 'inject', False) and relay is not None:
            if getattr(opts, 'probe_entry', '') or getattr(opts, 'probe_at', ''):
                pass                                   # the entry probe owns the breakpoint; no injection
            elif getattr(opts, 'inject_call', False):
                self.sendcall_rva = int(opts.sendpacket_rva, 16)
                relay.on_inbound = self._on_inbound_sendcall
                print(f'[*] --inject-call: consumer "S" packets -> client SendPacket(this,len,buf) '
                      f'at {opts.sendpacket_module}+0x{self.sendcall_rva:x} (spontaneous; captures this, '
                      f'calls on the game thread)')
            elif pid is None:
                print('[!] --inject needs the gadget-port process (pid) to write its memory; disabled')
            elif self.scramble:
                relay.on_inbound = self._on_inbound_scramble
                mode = 'persistent (replaces every matching client action)' if self.scramble.get('persist') \
                    else 'one-shot per packet'
                print(f'[*] --inject + --scramble-bp: consumer "S" packets -> scramble BP body map '
                      f'(substituted pre-XOR, {mode})')
            elif opts.wire and not getattr(opts, 'scramble_bp', ''):
                # No scrambler location given: discover it at runtime. The send watch (already on)
                # reports the scrambler write pc on the first encrypted 0437/0438; then we disarm it
                # and arm the exec breakpoint there with reg='auto' (the agent self-locates the
                # pointer + id offset) and the recv-ring block as the range. See _autodiscover_scramble.
                self.autodiscover = bool(self.sendwatch)
                if self.autodiscover:
                    relay.on_inbound = self._on_inbound_scramble
                    print('[*] --inject: auto-discovering the scrambler via send-watch; arms on the '
                          'first encrypted 0437/0438 (do one in-client action to bootstrap)')
                else:
                    print('[!] --inject auto-discovery needs --send-watch (it finds the scrambler pc); '
                          'enable it or set scramble-bp in the config. Injection disabled this run.')
            else:
                self.injector = SendInjector(ProcessMemoryWriter(pid), self._queue_range,
                                             wire.L if wire else {}, log=log,
                                             dry_run=getattr(opts, 'inject_dry_run', False))
                relay.on_inbound = self._on_inbound
                mode = 'DRY-RUN (nothing written)' if self.injector.dry_run else 'LIVE (writes the client)'
                print(f'[*] --inject: consumer "S" packets -> client send queue [{mode}]')

    # ---- threads ----------------------------------------------------------------------------
    def start(self):
        threading.Thread(target=self.run_worker, name='worker', daemon=True).start()
        if self.relay and isinstance(self.recv_path, WireFeed):
            threading.Thread(target=self.recv_path.run, name='wire-feeder', daemon=True).start()
        if self.relay and isinstance(self.recv_path, LegacyPipeline):
            threading.Thread(target=self.recv_path.run_watchdog, name='feed-watchdog', daemon=True).start()

    def run_worker(self):
        while True:
            m = self.work.get()
            try:
                self.dispatch(m)
            except Exception as e:                     # one bad message must not end the capture
                print(f"[!] worker: {type(e).__name__}: {e} (tag {m.get('tag')})")

    def dispatch(self, m):
        tag = m.get('tag')
        if tag == protocol.SENDWATCH_ERR:
            print(f"[!] send watch: {m.get('e')}")
        elif tag == protocol.RINGSNAP:
            self.recv_path.on_ringsnap(m)
        elif tag == protocol.RECV:
            self.recv_path.on_recv(m)                  # logs the chunk itself (maybe later, legacy)
        elif tag == protocol.GEPARD:
            self.gepard_base = int(m['base'], 16) if m.get('base') else None
            print(f"[*] gepard.dll base: {m.get('base')}")
            self.log.write(m)                          # record it in the JSONL too
        else:
            if tag == protocol.SEND:
                self.send_path.on_send(m)
                if self.injector:
                    self.injector.on_send(m)           # follow the live send-queue tail slot
                if m.get('enc') and self.gepard_base:  # discovery: scrambler write-pc as gepard+offset
                    m['enc_off'] = hex(int(m['enc'], 16) - self.gepard_base)
                    if self.autodiscover and not self._scramble_armed:
                        self._autodiscover_scramble(m)
            self.log.write(m)

    # ---- agent control ----------------------------------------------------------------------
    def _on_ring_found(self, base):
        self.recv_path.on_ring_found(base)
        self.update_send_watch()

    def _scramble_cfg(self, opts):
        """Parse --scramble-bp/--inject-walk into {off, reg, pid, body, dry}, or None."""
        sb = getattr(opts, 'scramble_bp', '')
        if not sb:
            return None
        body, dry = None, True
        if opts.inject_walk:
            p = [int(v) for v in opts.inject_walk.split(',')]
            body = pack_move(p[0], p[1], p[2] if len(p) > 2 else 0).hex()
            dry = False
        elif getattr(opts, 'inject', False):
            dry = False                                # --inject merge: arm LIVE, bodies come from the consumer
        lo = hi = None
        if getattr(opts, 'scramble_range', ''):
            lo, hi = (int(x, 16) for x in opts.scramble_range.split('-'))
        cfg = {'off': int(sb, 16), 'reg': opts.scramble_reg, 'pid': int(opts.scramble_id, 16),
               'body': body, 'dry': dry, 'idoff': getattr(opts, 'scramble_idoff', 0), 'lo': lo, 'hi': hi,
               'persist': bool(getattr(opts, 'inject_persist', False))}
        rng = f" range 0x{lo:x}-0x{hi:x}" if lo is not None else ''
        if dry:
            mode = 'DRY (log only)'
        elif opts.inject_walk:
            mode = 'LIVE walk ' + opts.inject_walk
        else:
            mode = 'LIVE --inject merge (bodies from the consumer)'
        print(f"[*] --scramble-bp: exec breakpoint at gepard+0x{cfg['off']:x} reg {cfg['reg']} "
              f"idoff {cfg['idoff']} id 0x{cfg['pid']:04x}{rng} [{mode}] (send watch disabled)")
        return cfg

    def _autodiscover_scramble(self, m):
        """First encrypted send recovered: `m['enc']` is the scrambler write pc. Switch from the
        send watch to the scramble intercept - disarm the watch (frees the debug registers) and arm
        an exec breakpoint on the store itself (enc - SCRAMBLE_STORE_BACK) with reg='auto' (the agent
        locates the pointer + id offset by matching the packet id) and the recv-ring block as range.
        Runs on the worker thread under _disc_lock, so it arms exactly once."""
        with self._disc_lock:
            if self._scramble_armed:
                return
            store_off = int(m['enc'], 16) - self.gepard_base - SCRAMBLE_STORE_BACK
            if getattr(self.opts, 'scramble_range', ''):   # honour an explicit range if set
                lo, hi = (int(x, 16) for x in self.opts.scramble_range.split('-'))
            else:
                r = self._queue_range()                    # the recv-ring/send-queue block
                lo, hi = (r[0], r[1]) if r else (None, None)
            persist = bool(getattr(self.opts, 'inject_persist', False))
            probe = bool(getattr(self.opts, 'send_probe', False))
            pid = int(self.opts.scramble_id, 16)
            self.post(sendwatch_msg())                     # disarm the send watch (lo omitted = off)
            self.sendwatch = None
            self.post(scramble_msg(store_off, 'auto', pid, None, False, 0, lo, hi, persist, probe=probe))
            self.scramble = {'off': store_off, 'reg': 'auto', 'pid': pid, 'body': None, 'dry': False,
                             'idoff': 0, 'lo': lo, 'hi': hi, 'persist': persist, 'probe': probe}
            self._scramble_armed = True
        rng = f' range 0x{lo:x}-0x{hi:x}' if lo is not None else ' (id-match only, no range)'
        if probe:
            print(f"[*] --send-probe: one-shot breakpoint on the scrambler store @ gepard+0x{store_off:x} "
                  f"(from {m['enc_off']}){rng}; captures the next 0437/0438 send's stack + registers")
        else:
            print(f"[*] auto-discovered scrambler: store @ gepard+0x{store_off:x} (from {m['enc_off']}), "
                  f"reg=auto{rng}, {'persistent' if persist else 'one-shot'} inject armed")

    def arm_scramble(self):
        """Post the scramble breakpoint to the agent (gepard+off is resolved agent-side)."""
        if self.scramble:
            c = self.scramble
            self.post(scramble_msg(off=c.get('off'), reg=c['reg'], pid=c['pid'], body=c['body'],
                                   dry=c['dry'], idoff=c['idoff'], lo=c['lo'], hi=c['hi'],
                                   persist=c['persist'], probe=c.get('probe', False),
                                   entry=c.get('entry', False), pc=c.get('pc')))

    def _queue_range(self):
        """(lo, hi, source) of the client send-queue block, or None - shared by the send watch and
        the injector so both point at the same block (the recv-ring block ActorDecrypt verifies)."""
        dec = self.dec
        ring = (dec.region or (None, None)) if dec else None   # one read: never a new base with an old hi
        return send_queue_range(self.opts.send_queue, ring, dec is not None)

    def _on_inbound(self, payload, typ):
        """A packet the consumer sent back (XKore 'S' = client->server): drop it into the client's
        send queue so the client transmits it. Runs on the relay-connect thread."""
        if self.injector is None:
            return
        pid = payload[0] | payload[1] << 8 if len(payload) >= 2 else -1
        slot = self.injector.slots.get(pid)
        where = (f"0x{slot[0]:x} (client's own 0x{pid:04x} slot, len {slot[1]})" if slot
                 else f"{self.injector.next_slot or 'base'} (queue tail)")
        print(f"[inject] inbound typ={typ!r} len={len(payload)} id=0x{pid:04x} -> {where}: "
              f"{payload[:16].hex()}")
        if typ != 'S' or not payload:
            self.injector.stats[f'skip-typ-{typ!r}'] += 1
            return
        try:
            self.injector.inject_stream(payload)
        except InjectError as e:
            print(f'[inject] dropped: {e}')

    def _on_inbound_scramble(self, payload, typ):
        """--inject + --scramble-bp: a packet the consumer sent back (XKore 'S' = client->server).
        Hand its body to the agent keyed by id; the scramble BP substitutes it (pre-XOR) the next
        time the client builds that id, so the client's own scrambler encrypts our bytes. One-shot:
        the agent forgets it after the first write, and the player's own sends resume."""
        if typ != 'S' or len(payload) < 2:
            print(f"[inject] skip typ={typ!r} len={len(payload)} (need an 'S' packet with an id)")
            return
        pid = payload[0] | payload[1] << 8
        body = payload[2:]                             # id is already correct in the slot; only the body is XORed
        print(f"[inject] inbound id=0x{pid:04x} len={len(payload)} -> scramble body map (pre-XOR): "
              f"{payload[:16].hex()}")
        self.post(scramble_set_msg(pid, body.hex()))

    def _on_inbound_sendcall(self, payload, typ):
        """--inject-call: a packet the consumer sent back (XKore 'S' = client->server). Hand it to the
        agent to transmit through the client's own SendPacket - spontaneous, replacing nothing. The
        agent captures `this` once, then calls on the game thread."""
        if typ != 'S' or len(payload) < 2:
            print(f"[inject] skip typ={typ!r} len={len(payload)} (need an 'S' packet with an id)")
            return
        pid = payload[0] | payload[1] << 8
        print(f"[inject] inbound id=0x{pid:04x} len={len(payload)} -> SendPacket: {payload[:16].hex()}")
        self.post(sendcall_emit_msg(payload.hex()))

    def arm_sendcall(self):
        """Arm call-based injection: tell the agent where SendPacket is so it can capture `this`."""
        if getattr(self.opts, 'inject_call', False) and self.relay is not None:
            self.post(sendcall_msg(self.sendcall_rva, getattr(self.opts, 'sendpacket_module', 'uaRO.exe')))
            print('[*] --inject-call: do one in-client 0437/0438 action to capture the send object (this)')

    def update_send_watch(self):
        """Point the agent's send watch at the queue block (again, if the ring moved)."""
        if not self.sendwatch:
            return
        r = self._queue_range()
        with self._sw_lock:
            if r is None or r[:2] == self._sw_posted:
                return
            self._sw_posted = r[:2]
        print(f'[*] send watch: queue block 0x{r[0]:x}-0x{r[1]:x} ({r[2]})')
        self.post(sendwatch_msg(r[0], r[1]))

    @property
    def send_watch_waiting(self):
        return self.sendwatch is not None and self._sw_posted is None

    def report_stats(self):
        if self.dec and self.dec.stats:
            print(f'[actor] stats: {dict(self.dec.stats)}')
        if self.sendwatch and self.sendwatch.stats:
            print(f'[send] stats: {dict(self.sendwatch.stats)}')
        if self.injector and self.injector.stats:
            print(f'[inject] stats: {dict(self.injector.stats)}')
        if self.moves and self.moves.stats:
            print(f'[move] stats: {dict(self.moves.stats)}')
