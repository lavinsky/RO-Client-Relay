"""Capture: monta os componentes que as opções pedem e roteia as mensagens do agente.

Threads:
  callback do Frida  Agent._message -> fila de trabalho (nada mais, o agente nunca espera)
  worker             Capture.run_worker: uma mensagem por vez, na ordem do agente
  wire feeder        WireFeed.run (com relay)
  relay connect      dentro de Relay; threads curtas de descoberta dentro de ActorDecrypt

O caminho de escrita e readiness pertencem ao ClientDispatcher composto."""
import queue
import threading
from contextlib import nullcontext

from . import frida_bridge as protocol
from .actor_recovery import ActorDecrypt
from .frida_bridge import sendwatch_msg
from .packet_pipeline import ClientSendFeed, MoveTracker, WireFeed
from .client_dispatch import ClientDispatcher


class Capture:
    def __init__(self, opts, pid, relay, wire, log, post):
        """opts: opções da CLI. relay/wire: Relay e WireFilter, ou None (sem feed). post(msg): envia
        uma mensagem ao agente."""
        self.opts, self.relay, self.log = opts, relay, log
        self._agent_post = post
        self.work = queue.Queue()
        self.dec = self.sendwatch = self.moves = None
        self._sw_posted = None                         # (lo, hi) para onde a send-watch foi apontada
        self._sw_lock = threading.Lock()
        self.gepard_base = None                        # base da gepard.dll (da mensagem GEPARD)
        self.client_dispatch = ClientDispatcher(self, opts, post)

        feed_send = bool(opts.feed_send and relay and opts.relay_format == 'xkore1')
        if feed_send and getattr(opts, 'inject', False):
            # alimentar o consumidor com os envios do cliente, que ele devolve como "S", reinjetaria
            # os próprios envios num laço (observado: inunda o servidor, derruba a sessão).
            print('[!] --inject is on: disabling --feed-send to avoid a re-inject feedback loop')
            feed_send = False

        self.recv_path = self.send_path = None
        if wire is not None:                           # pipeline do feed (precisa de relay/WireFilter)
            self.dec = ActorDecrypt(pid) if opts.decrypt_actors else None
            if opts.probe_actors or opts.actor_diag:
                from .research_diagnostics import ActorDiag, ActorProbe
            probe = ActorProbe(pid) if opts.probe_actors else None
            diag = ActorDiag(self.dec) if (self.dec and opts.actor_diag) else None
            # merge, call-inject e a send-watch completa usam os registradores de depuração.
            uses_dbg = self.client_dispatch.scramble or getattr(opts, 'inject_call', False)
            if opts.send_watch and not uses_dbg:
                from .send_recovery import SendWatch
            self.sendwatch = SendWatch() if (opts.send_watch and not uses_dbg) else None
            if self.dec:
                print(f'[*] --decrypt-actors: 09fd/09ff bodies from the client recv ring (hold <= {opts.actor_delay*1000:.0f}ms)')
                self.dec.on_ring = self._on_ring_found
            self.moves = MoveTracker(log)              # decodifica o destino do 0087 (texto claro)
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

        self.client_dispatch.configure(pid, wire)
        self.commands = self.client_dispatch.commands
        if self.recv_path:
            self.recv_path.on_timing = self.commands.measure
        self._map_conn = None
        self._closed_map_conns = set()
        self._relay_generation = 0
        if feed_send:
            print('[*] --feed-send: relaying client->server packets to the consumer as "S" frames '
                  '(bidirectional observation; nothing reaches the real server)')

    # ---- threads ----------------------------------------------------------------------------
    def start(self):
        threading.Thread(target=self.run_worker, name='worker', daemon=True).start()
        if self.relay and isinstance(self.recv_path, WireFeed):
            threading.Thread(target=self.recv_path.run, name='wire-feeder', daemon=True).start()

    def run_worker(self):
        while True:
            m = self.work.get()
            try:
                self.dispatch(m)
            except Exception as e:                     # uma mensagem ruim não pode encerrar a captura
                print(f"[!] worker: {type(e).__name__}: {e} (tag {m.get('tag')})")

    def dispatch(self, m):
        # Session boundaries and the final receive feed share this fence. Always
        # Relay.lock -> commands.lock; no path takes them in reverse order.
        with self.relay.lock if self.relay else nullcontext():
            self._dispatch_locked(m)

    def _dispatch_locked(self, m):
        with self.commands.lock:
            if m.get('epoch') is not None and m['epoch'] != self.commands.epoch:
                return
            if m.get('tag') in (protocol.RECV, protocol.RINGSNAP, protocol.SEND) and m.get('conn') in self._closed_map_conns:
                return
            # Network capture remains available while disconnected, but never feeds
            # old session fragments to the next OpenKore connection.
            if not self.commands.active and m.get('tag') in (protocol.RECV, protocol.RINGSNAP, protocol.SEND):
                if self.relay:
                    return
            if m.get('tag') in (protocol.RECV, protocol.SEND) and str(m.get('sock', '')).endswith(':5121'):
                conn = protocol.conn_of(m)
                if self._map_conn is not None and conn != self._map_conn:
                    # A replacement map connection invalidates captured native objects.
                    # Old epoch events are rejected above, rather than rebinding old work.
                    self._closed_map_conns.add(self._map_conn)
                    # Keep the network epoch: further fragments of this new TCP
                    # connection can already be queued in the Frida callback.
                    # A token barrier cancels native work without losing them.
                    self.commands.session(self.commands.active, advance_epoch=False)
                self._map_conn = conn
            self.commands.observe(m)
            generation = self._relay_generation
            packet = self._dispatch_event(m)
        # Never acquire Relay.lock while holding commands.lock. Connection callbacks
        # take the locks in the opposite order to cancel pending commands atomically.
        if packet and self.relay:
            self.relay.feed_send(packet, generation=generation)

    def _dispatch_event(self, m):
        tag = m.get('tag')
        if tag == protocol.SENDWATCH_ERR:
            print(f"[!] send watch: {m.get('e')}")
        elif tag == protocol.RINGSNAP:
            if self.recv_path:
                self.recv_path.on_ringsnap(m)
        elif tag == protocol.RECV:
            if self.recv_path:
                self.recv_path.on_recv(m)              # loga o próprio trecho
            else:
                self.log.write(m)                      # sem feed (sem --relay): só loga
        elif tag == protocol.GEPARD:
            self.gepard_base = int(m['base'], 16) if m.get('base') else None
            print(f"[*] gepard.dll base: {m.get('base')}")
            self.log.write(m)
        else:
            packet = None
            if tag == protocol.SEND:
                if self.send_path:
                    packet = self.send_path.on_send(m, emit=False)
                if m.get('enc') and self.gepard_base:  # descoberta: pc do store da cifragem como gepard+off
                    m['enc_off'] = hex(int(m['enc'], 16) - self.gepard_base)
                    if self.client_dispatch.autodiscover and not self.client_dispatch._scramble_armed:
                        self.client_dispatch._autodiscover_scramble(m)
            self.log.write(m)
            return packet

    def post(self, message):
        self.client_dispatch.post(message)

    def arm_scramble(self):
        self.client_dispatch.arm_scramble()

    def arm_sendcall(self):
        self.client_dispatch.arm_sendcall()

    def arm_move_dispatch(self):
        self.client_dispatch.arm_move_dispatch()

    def suspend_commands(self):
        with self.relay.lock if self.relay else nullcontext():
            self.commands.session(False)

    def _reset_session(self, epoch, active):
        if not active:
            self._map_conn = None
            self._closed_map_conns.clear()
        self._relay_generation = getattr(self.relay, 'generation', 0)
        if self.recv_path:
            self.recv_path.reset_session(epoch, self._relay_generation)
            if self.dec:
                # A replacement isolates old discovery threads and stale ring evidence.
                decoder = ActorDecrypt(self.dec.pid)
                self.dec = self.recv_path.dec = decoder
                decoder.on_ring = lambda base: self._on_ring_found(base) if self.dec is decoder else None
                if self.recv_path.diag:
                    self.recv_path.diag.dec = decoder
                self._sw_posted = None
        if self.moves:
            self.moves.last_walk = None

    # ---- controle do agente -----------------------------------------------------------------
    def _on_ring_found(self, base):
        self.recv_path.on_ring_found(base)
        self.update_send_watch()

    def _queue_range(self):
        """(lo, hi, origem) do bloco da fila de envio, ou None - compartilhado pela send-watch e pela
        autodescoberta (o bloco da recv-ring que o ActorDecrypt verifica)."""
        from .send_recovery import send_queue_range
        dec = self.dec
        ring = (dec.region or (None, None)) if dec else None   # uma leitura: nunca base nova com hi antigo
        return send_queue_range(self.opts.send_queue, ring, dec is not None)

    def update_send_watch(self):
        """Aponta a send-watch do agente para o bloco da fila (de novo, se a ring se moveu)."""
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
        if self.commands.samples:
            self.log.write({'tag': 'LATENCY', 'stages': self.commands.summary()})
        if self.dec and self.dec.stats:
            print(f'[actor] stats: {dict(self.dec.stats)}')
        if self.sendwatch and self.sendwatch.stats:
            print(f'[send] stats: {dict(self.sendwatch.stats)}')
        if self.moves and self.moves.stats:
            print(f'[move] stats: {dict(self.moves.stats)}')
