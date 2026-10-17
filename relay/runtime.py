"""Capture: monta os componentes que as opções pedem e roteia as mensagens do agente.

Threads:
  callback do Frida  Agent._message -> fila de trabalho (nada mais, o agente nunca espera)
  worker             Capture.run_worker: uma mensagem por vez, na ordem do agente
  wire feeder        WireFeed.run (com relay)
  relay connect      dentro de Relay; threads curtas de descoberta dentro de ActorDecrypt

O caminho de escrita (merge/SendPacket/autodescoberta/rastreio) está no mixin WriteBack."""
import queue
import threading

from . import protocol
from .actors import ActorDecrypt
from .packets import MoveTracker
from .protocol import sendwatch_msg
from .research import ActorDiag, ActorProbe
from .sendwatch import SendWatch, send_queue_range
from .wire_feed import ClientSendFeed, WireFeed
from .writeback import WriteBack


class Capture(WriteBack):
    def __init__(self, opts, pid, relay, wire, log, post):
        """opts: opções da CLI. relay/wire: Relay e WireFilter, ou None (sem feed). post(msg): envia
        uma mensagem ao agente."""
        self.opts, self.relay, self.log, self.post = opts, relay, log, post
        self.work = queue.Queue()
        self.dec = self.sendwatch = self.moves = None
        self._sw_posted = None                         # (lo, hi) para onde a send-watch foi apontada
        self._sw_lock = threading.Lock()
        self.gepard_base = None                        # base da gepard.dll (da mensagem GEPARD)
        self.scramble = self._build_scramble(opts)     # config do BP de cifragem, ou None

        feed_send = bool(opts.feed_send and relay and opts.relay_format == 'xkore1')
        if feed_send and getattr(opts, 'inject', False):
            # alimentar o consumidor com os envios do cliente, que ele devolve como "S", reinjetaria
            # os próprios envios num laço (observado: inunda o servidor, derruba a sessão).
            print('[!] --inject is on: disabling --feed-send to avoid a re-inject feedback loop')
            feed_send = False

        self.recv_path = self.send_path = None
        if wire is not None:                           # pipeline do feed (precisa de relay/WireFilter)
            self.dec = ActorDecrypt(pid) if opts.decrypt_actors else None
            probe = ActorProbe(pid) if opts.probe_actors else None
            diag = ActorDiag(self.dec) if (self.dec and opts.actor_diag) else None
            # merge, call-inject e a send-watch completa usam os registradores de depuração.
            uses_dbg = self.scramble or getattr(opts, 'inject_call', False)
            self.sendwatch = SendWatch() if (opts.send_watch and not uses_dbg) else None
            if self.dec:
                print(f'[*] --decrypt-actors: 09fd/09ff bodies from the client recv ring (hold <= {opts.actor_delay*1000:.0f}ms)')
                self.dec.on_ring = self._on_ring_found
            self.moves = MoveTracker(log)              # decodifica o destino do 0087 (texto claro)
            recv_cbs = ([probe.on_packet] if probe else []) + [self.moves.on_recv_packet, self.on_map_boundary]
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

        self._wire_writeback(opts, pid, wire)          # aponta relay.on_inbound (ver writeback.py)
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
            if tag == protocol.SEND:
                if self.send_path:
                    self.send_path.on_send(m)
                if m.get('enc') and self.gepard_base:  # descoberta: pc do store da cifragem como gepard+off
                    m['enc_off'] = hex(int(m['enc'], 16) - self.gepard_base)
                    if self.autodiscover and not self._scramble_armed:
                        self._autodiscover_scramble(m)
            self.log.write(m)

    # ---- controle do agente -----------------------------------------------------------------
    def _on_ring_found(self, base):
        self.recv_path.on_ring_found(base)
        self.update_send_watch()

    def _queue_range(self):
        """(lo, hi, origem) do bloco da fila de envio, ou None - compartilhado pela send-watch e pela
        autodescoberta (o bloco da recv-ring que o ActorDecrypt verifica)."""
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
        if self.dec and self.dec.stats:
            print(f'[actor] stats: {dict(self.dec.stats)}')
        if self.sendwatch and self.sendwatch.stats:
            print(f'[send] stats: {dict(self.sendwatch.stats)}')
        if self.moves and self.moves.stats:
            print(f'[move] stats: {dict(self.moves.stats)}')
