"""Native client write routes, with no game pacing or decision logic.

Movement uses the proven dispatcher; actions use natural carrier merge with
byte-zero repair in the agent; other packets use native SendPacket fallback.
Optional store discovery remains available without running probes by default.
"""
import threading

from .packets import unpack_move
from .protocol import (move_dispatch_msg, scramble_msg, scramble_set_msg, sendcall_emit_msg, sendcall_msg,
                       sendwatch_msg)
from .synth_input import build_actuator

# A watch de dados dispara uma instrução DEPOIS da escrita; o store `mov [reg],bl` tem 2 bytes.
# O breakpoint de execução precisa cair no próprio store, com o texto claro ainda presente.
SCRAMBLE_STORE_BACK = 2


class WriteBack:
    WALK_ID = 0x035f                                   # andar: único pacote roteado para o merge
    ACTION_MERGE_IDS = (0x0437, 0x0438, 0x0af4)         # ações com alvo roteáveis ao merge (--action-merge)
    SKIP_IDS = (0x0368, 0x0369, 0x0193, 0x0094, 0x0360)   # tagarelice que o cliente já emite sozinho
    #                                                    (pedido de nome por GID / tick): não reinjetamos
    #                                                    a do consumidor, senão floda o servidor (gepard).

    # ---- configuração do ponto de cifragem --------------------------------------------------
    def _build_scramble(self, opts):
        if getattr(opts, 'probe_entry', '') or getattr(opts, 'probe_at', ''):
            from .research import scramble_probe_config
            return scramble_probe_config(opts)
        return self._scramble_cfg(opts)

    def _scramble_cfg(self, opts):
        """Config do merge (--scramble-bp), ou None. DRY quando sem --inject (só registra); com
        --inject arma LIVE e os corpos chegam do consumidor."""
        sb = getattr(opts, 'scramble_bp', '')
        if not sb:
            return None
        dry = not getattr(opts, 'inject', False)
        lo = hi = None
        if getattr(opts, 'scramble_range', ''):
            lo, hi = (int(x, 16) for x in opts.scramble_range.split('-'))
        cfg = {'off': int(sb, 16), 'reg': opts.scramble_reg, 'pid': int(opts.scramble_id, 16),
               'body': None, 'dry': dry, 'idoff': getattr(opts, 'scramble_idoff', 0), 'lo': lo,
               'hi': hi, 'persist': False,
               'trace': int(getattr(opts, 'scramble_trace', 0) or 0)}
        rng = f" range 0x{lo:x}-0x{hi:x}" if lo is not None else ''
        mode = 'DRY (log only)' if dry else 'LIVE --inject merge (bodies from the consumer)'
        print(f"[*] --scramble-bp: exec breakpoint at gepard+0x{cfg['off']:x} reg {cfg['reg']} "
              f"idoff {cfg['idoff']} id 0x{cfg['pid']:04x}{rng} [{mode}] (send watch disabled)")
        return cfg

    # ---- seleção do caminho de escrita ------------------------------------------------------
    def _wire_writeback(self, opts, pid, wire):
        """Decide por onde os pacotes 'S' do consumidor saem e aponta relay.on_inbound."""
        self.sendcall_rva = None
        self.autodiscover = False
        self._scramble_armed = self.scramble is not None
        self._disc_lock = threading.Lock()
        # Input starts only after the agent acknowledges readiness for this body.
        self.synth = build_actuator(opts)
        if not (getattr(opts, 'inject', False) and self.relay is not None):
            return
        relay = self.relay
        if getattr(opts, 'probe_entry', '') or getattr(opts, 'probe_at', ''):
            return                                     # a sonda de entrada é dona do breakpoint; sem escrita
        if getattr(opts, 'move_dispatch', False):
            # PoC: 035f -> dispatcher nativo de movimento (o cliente cifra o proprio). Os DEMAIS
            # pacotes "S" do consumidor so chegam ao cliente pela SendPacket (--inject-call); sem ela
            # caem no ramo de drop de _on_inbound_split e o OpenKore nao sincroniza/loga.
            if getattr(opts, 'inject_call', False):
                self.sendcall_rva = int(opts.sendpacket_rva, 16)
            relay.on_inbound = self._on_inbound_split
            print(f'[*] --move-dispatch: 035f from the consumer -> native movement dispatcher '
                  f'(client builds/encrypts its own 035f); original 035f is DROPPED'
                  + ('' if getattr(opts, 'inject_call', False)
                     else '  [!] sem --inject-call: demais pacotes do consumidor sao DROPADOS'))
        elif getattr(opts, 'inject_call', False):
            self.sendcall_rva = int(opts.sendpacket_rva, 16)
            if self.scramble:
                # roteia por id: 035f pelo merge (DR0), demais ações pela SendPacket (DR1).
                relay.on_inbound = self._on_inbound_split
                print(f'[*] --inject-call + --scramble-bp: andar (0x{self.WALK_ID:04x}) -> merge no BP '
                      f'de cifragem (uso unico); demais acoes -> SendPacket do cliente em '
                      f'{opts.sendpacket_module}+0x{self.sendcall_rva:x}')
            else:
                relay.on_inbound = self._on_inbound_sendcall
                print(f'[*] --inject-call: consumer "S" packets -> client SendPacket(this,len,buf) '
                      f'at {opts.sendpacket_module}+0x{self.sendcall_rva:x} (spontaneous)')
        elif self.scramble:
            relay.on_inbound = self._on_inbound_scramble
            mode = 'persistent (replaces every matching client action)' if self.scramble.get('persist') \
                else 'one-shot per packet'
            print(f'[*] --inject + --scramble-bp: consumer "S" packets -> scramble BP body map '
                  f'(substituted pre-XOR, {mode})')
        elif wire is not None and not getattr(opts, 'scramble_bp', ''):
            # sem a localização da cifragem: autodescobrir. A send-watch (ligada) relata o pc do
            # store no primeiro 0437/0438; então desarmamos a watch e armamos o BP de execução lá.
            self.autodiscover = bool(self.sendwatch)
            if self.autodiscover:
                relay.on_inbound = self._on_inbound_scramble
                print('[*] --inject: auto-discovering the scrambler via send-watch; arms on the '
                      'first encrypted 0437/0438 (do one in-client action to bootstrap)')
            else:
                print('[!] --inject auto-discovery needs --send-watch (it finds the scrambler pc); '
                      'enable it or set scramble-bp in the config. Injection disabled this run.')

    # ---- autodescoberta ---------------------------------------------------------------------
    def _autodiscover_scramble(self, m):
        """Primeiro envio cifrado recuperado: m['enc'] é o pc do store. Troca a send-watch pelo
        merge — desarma a watch (libera os registradores) e arma o BP de execução no store
        (enc - SCRAMBLE_STORE_BACK) com reg='auto' e o bloco da ring como faixa. Roda no worker
        sob _disc_lock, então arma exatamente uma vez."""
        with self._disc_lock:
            if self._scramble_armed:
                return
            store_off = int(m['enc'], 16) - self.gepard_base - SCRAMBLE_STORE_BACK
            probe = bool(getattr(self.opts, 'send_probe', False))
            ids = [int(x, 16) for x in getattr(self.opts, 'probe_ids', '0437,0438').split(',') if x.strip()]
            if getattr(self.opts, 'scramble_range', ''):   # faixa explícita (ex.: a pilha do 035f)
                lo, hi = (int(x, 16) for x in self.opts.scramble_range.split('-'))
            else:
                r = self._queue_range()                    # o bloco ring/fila (padrão)
                lo, hi = (r[0], r[1]) if r else (None, None)
            persist = False
            anyid = bool(getattr(self.opts, 'probe_anyid', False))
            pid = int(self.opts.scramble_id, 16)
            self.post(sendwatch_msg())                     # desarma a send-watch (lo omitido = off)
            self.sendwatch = None
            self.post(scramble_msg(store_off, 'auto', pid, None, False, 0, lo, hi, persist,
                                   probe=probe, ids=ids if probe else None, anyid=anyid if probe else False))
            self.scramble = {'off': store_off, 'reg': 'auto', 'pid': pid, 'body': None, 'dry': False,
                             'idoff': 0, 'lo': lo, 'hi': hi, 'persist': persist, 'probe': probe,
                             'ids': ids if probe else None, 'anyid': anyid if probe else False}
            self._scramble_armed = True
        rng = f' range 0x{lo:x}-0x{hi:x}' if lo is not None else ' (id-match only, no range)'
        if probe:
            print(f"[*] --send-probe: one-shot breakpoint on the scrambler store @ gepard+0x{store_off:x} "
                  f"(from {m['enc_off']}){rng}; captures the next 0437/0438 send's stack + registers")
        else:
            print(f"[*] auto-discovered scrambler: store @ gepard+0x{store_off:x} (from {m['enc_off']}), "
                  f"reg=auto{rng}, {'persistent' if persist else 'one-shot'} inject armed")

    # ---- armar no agente --------------------------------------------------------------------
    def arm_scramble(self):
        if self.scramble:
            c = self.scramble
            self.post(scramble_msg(off=c.get('off'), reg=c['reg'], pid=c['pid'], body=c['body'],
                                   dry=c['dry'], idoff=c['idoff'], lo=c['lo'], hi=c['hi'],
                                   persist=c['persist'], probe=c.get('probe', False),
                                   entry=c.get('entry', False), pc=c.get('pc'), ids=c.get('ids'),
                                   anyid=c.get('anyid', False), trace=c.get('trace', 0)))

    def arm_sendcall(self):
        """Diz ao agente onde está a SendPacket para ele capturar `this` (DR1)."""
        if getattr(self.opts, 'inject_call', False) and self.relay is not None:
            self.post(sendcall_msg(self.sendcall_rva, getattr(self.opts, 'sendpacket_module', 'uaRO.exe')))
            print('[*] SendPacket: aguardando captura passiva do contexto nativo')

    def arm_move_dispatch(self):
        """Arma a captura passiva do `this` do dispatcher nativo (DR2); o sitio de disparo (DR3) so
        e armado quando chega um 035f."""
        if getattr(self.opts, 'move_dispatch', False) and self.relay is not None:
            self.post(move_dispatch_msg(arm=True, dispatcher=getattr(self.opts, 'move_dispatch_ptr', None),
                                        site=getattr(self.opts, 'move_dispatch_site', None)))
            print('[*] --move-dispatch: walk once in-client so the dispatcher `this` is captured (passive)')

    def post_move_dispatch(self, x, y):
        self.post(move_dispatch_msg(x, y))

    # ---- pacotes que o consumidor devolve ---------------------------------------------------
    def _on_inbound_scramble(self, payload, typ):
        """Entrega o corpo ao agente por id; o BP de cifragem o substitui (pré-XOR) na próxima vez
        que o cliente montar esse id. Uso único: o agente o descarta após a primeira escrita."""
        if typ != 'S' or len(payload) < 2:
            print(f"[inject] skip typ={typ!r} len={len(payload)} (need an 'S' packet with an id)")
            return
        pid = payload[0] | payload[1] << 8
        expected = {0x035f: 5, 0x0437: 7, 0x0438: 10, 0x0af4: 11}.get(pid)
        if expected is not None and len(payload) != expected:
            print(f'[inject] error id=0x{pid:04x}: length {len(payload)} expected {expected}')
            return
        body = payload[2:]                             # o id já está correto no slot; só o corpo é XORado
        self.post(scramble_set_msg(pid, body.hex()))

    def _on_inbound_split(self, payload, typ):
        """Roteia por id: 035f pelo merge (uso único), demais ações pela SendPacket."""
        if typ != 'S' or len(payload) < 2:
            print(f"[inject] skip typ={typ!r} len={len(payload)} (need an 'S' packet with an id)")
            return
        pid = payload[0] | payload[1] << 8
        md = getattr(getattr(self, 'opts', None), 'move_dispatch', False)
        if pid == self.WALK_ID and md:
            if len(payload) != 5:
                print(f'[inject] 035f invalid length ({len(payload)}B): dropped')
                return
            x, y, _d = unpack_move(payload[2:5])
            print(f'[inject] 035f -> native dispatch to ({x},{y}); original 035f dropped')
            self.post_move_dispatch(x, y)              # o cliente monta/cifra o proprio; nada e reenviado
        elif pid == self.WALK_ID:
            self._on_inbound_scramble(payload, typ)
        elif (getattr(getattr(self, 'opts', None), 'action_merge', False) and pid in WriteBack.ACTION_MERGE_IDS
              and getattr(self, '_scramble_armed', False)):
            self._on_inbound_scramble(payload, typ)    # --action-merge: ação com alvo -> merge, não SendPacket
        elif md and not getattr(self.opts, 'inject_call', False):
            print(f'[inject] id=0x{pid:04x}: no handler under --move-dispatch without --inject-call; dropped')
        else:
            self._on_inbound_sendcall(payload, typ)

    def _on_inbound_sendcall(self, payload, typ):
        """Generic fallback: native call completion does not prove wire/server acceptance."""
        if typ != 'S' or len(payload) < 2:
            print(f"[inject] skip typ={typ!r} len={len(payload)} (need an 'S' packet with an id)")
            return
        pid = payload[0] | payload[1] << 8
        if pid in self.SKIP_IDS:                       # o cliente já emite isso; não reinjetar (anti-flood)
            print(f'[inject] omit id=0x{pid:04x}: emitido naturalmente pelo cliente (anti-reinjeção)')
            return
        print(f'[inject] id=0x{pid:04x} len={len(payload)} -> SendPacket (execução não confirmada)')
        self.post(sendcall_emit_msg(payload.hex()))
