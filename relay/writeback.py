"""Caminho de escrita (opt-in): fazer o cliente transmitir os pacotes que o consumidor devolve.

Dois caminhos, combinados por id de pacote (ver ARCHITECTURE.md §6):
  - merge no ponto de cifragem (035f/andar): substitui o corpo que o PRÓPRIO cliente monta, antes
    do XOR em memória, no breakpoint de execução DR0. É o único jeito correto para o 035f (enviá-lo
    pela SendPacket dessincroniza a cifra).
  - chamada da SendPacket do cliente (0437/0438/...): envio espontâneo, captura `this` no DR1.
Também mora aqui a autodescoberta do ponto de cifragem e o rastreio com Stalker (pesquisa).

É um mixin de Capture (runtime.py): usa o estado de Capture (self.post, self.opts, self.relay,
self.scramble, self.sendwatch, self.gepard_base, self._queue_range, self._disc_lock)."""
import queue
import threading
import time

from .packets import unpack_move
from .protocol import (move_dispatch_msg, scramble_msg, scramble_set_msg, sendcall_emit_msg, sendcall_msg,
                       sendwatch_msg, trace_msg)
from .synth_input import build_actuator

# A watch de dados dispara uma instrução DEPOIS da escrita; o store `mov [reg],bl` tem 2 bytes.
# O breakpoint de execução precisa cair no próprio store, com o texto claro ainda presente.
SCRAMBLE_STORE_BACK = 2


class WriteBack:
    WALK_ID = 0x035f                                   # andar: único pacote roteado para o merge
    SELECT_ID = 0x0368                                 # seleção de alvo por GID (o que um clique gera)
    SKILL_ID = 0x0438                                  # perícia em alvo: [id][nível:2][skill:2][GID:4]
    ACT_ID = 0x0437                                    # ação: [id][GID:4][ação:1] (ataque tem GID != 0)
    CAST_IDS = (0x0438, 0x0af4)                         # perícias com tempo de cast (alvo e chão): um novo
    #                                                    cast cancela o anterior, então o consumidor não
    #                                                    pode repeti-las em rajada (ver _on_inbound_sendcall).
    ACTION_MERGE_IDS = (0x0437, 0x0438, 0x0af4)         # ações com alvo roteáveis ao merge (--action-merge)

    # ---- configuração do ponto de cifragem --------------------------------------------------
    def _build_scramble(self, opts):
        """Config do breakpoint de cifragem a partir das opções, ou None. Modo pesquisa
        (--probe-entry/--probe-at): captura de disparo único dos argumentos de uma função."""
        pe, pa = getattr(opts, 'probe_entry', ''), getattr(opts, 'probe_at', '')
        if pe or pa:
            lo = hi = None
            if getattr(opts, 'scramble_range', ''):
                lo, hi = (int(x, 16) for x in opts.scramble_range.split('-'))
            ids = [int(x, 16) for x in getattr(opts, 'probe_ids', '0437,0438').split(',') if x.strip()]
            cfg = {'reg': 'auto', 'pid': int(opts.scramble_id, 16), 'body': None, 'dry': False,
                   'idoff': 0, 'lo': lo, 'hi': hi, 'persist': False, 'probe': True, 'entry': True,
                   'ids': ids}
            if pa:
                cfg['pc'] = int(pa, 16)
                where = f"0x{cfg['pc']:x}"
            else:
                cfg['off'] = int(pe, 16)
                where = f"gepard+0x{cfg['off']:x}"
            gate = f' gated to a 0437/0438 copy into 0x{lo:x}-0x{hi:x}' if lo is not None else ' (first call)'
            print(f'[*] --probe-entry: one-shot capture of args at {where}{gate}, read-only')
            return cfg
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
               'hi': hi, 'persist': bool(getattr(opts, 'inject_persist', False)),
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
        # Atuador de tecla sintética (--synth-input, OFF por padrão): quando uma ação (0437/0438/0af4)
        # é armada no merge, dispara a tecla que faz o cliente montar o carrier. Antes era o processo
        # externo action_trigger.py tailando o stdout; agora é chamado direto em _on_inbound_scramble.
        self.synth = build_actuator(opts)
        # Paceamento dos casts: o consumidor (OpenKore) re-tenta a perícia várias vezes; enfileiradas,
        # elas drenam em rajada e cada cast cancela o anterior. O agente deixa passar no máximo um cast
        # por esta janela, NO DRENO (arm_sendcall envia cast_ms). 0 desliga. (Política do lado do
        # consumidor por natureza; vive aqui até o plugin dele fazê-la.)
        self._cast_throttle = float(getattr(opts, 'cast_throttle', 0.0) or 0.0)
        # Cache somente para --target-select: evita pedidos extras 0368 repetidos.
        # Solicitações 0368 originadas pelo consumidor seguem normalmente.
        self._last_select_gid = None
        if not (getattr(opts, 'inject', False) and self.relay is not None):
            return
        relay = self.relay
        if getattr(opts, 'probe_entry', '') or getattr(opts, 'probe_at', ''):
            return                                     # a sonda de entrada é dona do breakpoint; sem escrita
        if getattr(opts, 'move_dispatch', False):
            # PoC: 035f -> dispatcher nativo de movimento (o cliente cifra o proprio). Os DEMAIS
            # pacotes "S" do consumidor so chegam ao cliente pela SendPacket (--inject-call); sem ela
            # caem no ramo de drop de _on_inbound_split e o OpenKore nao sincroniza/loga.
            relay.on_connect = self.recapture_move_dispatch   # reconexão/relogin -> recaptura o `this` (anti-freeze)
            relay.on_disconnect = self.recapture_move_dispatch  # fail closed ao perder consumidor
            if getattr(opts, 'inject_call', False):
                self.sendcall_rva = int(opts.sendpacket_rva, 16)   # demais acoes -> client SendPacket (DR1)
            # Fila de egresso (opt-in): no cliente real/xKore o movimento e as ações saem por UM fluxo
            # ordenado (a máquina de estado do cliente serializa); nossa PoC abre CADA id num caminho
            # assíncrono distinto (035f -> dispatcher nativo no main-loop; 0437/0438 -> corpo armado +
            # tecla sintética fora de banda), que CORREM em paralelo — um 035f contínuo mantém o char
            # andando e a tecla do ataque cai no meio do passo. A fila reintroduz a serialização: drena
            # um pacote por vez, na ordem de chegada, com --egress-interval-ms entre eles e um gap maior
            # (--egress-action-gap-ms) após uma ação, p/ a tecla sintética cair com o char assentado.
            if getattr(opts, 'egress_queue', False):
                self._egress_interval = max(0, int(getattr(opts, 'egress_interval_ms', 100))) / 1000.0
                self._egress_action_gap = max(0, int(getattr(opts, 'egress_action_gap_ms', 400))) / 1000.0
                self._egress_max_age = max(0, int(getattr(opts, 'egress_max_age_ms', 800))) / 1000.0
                self._egress_q = queue.Queue()
                threading.Thread(target=self._egress_drain, name='egress-drain', daemon=True).start()
                relay.on_inbound = self._egress_enqueue
                print(f'[*] --egress-queue: FIFO serializada; {int(self._egress_interval*1000)}ms entre '
                      f'pacotes, +{int(self._egress_action_gap*1000)}ms após ação (ordem preservada)')
            else:
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
            persist = bool(getattr(self.opts, 'inject_persist', False))
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
            cast_ms = int(getattr(self, '_cast_throttle', 0.0) * 1000)
            self.post(sendcall_msg(self.sendcall_rva, getattr(self.opts, 'sendpacket_module', 'uaRO.exe'),
                                   cast_ms=cast_ms, demand=getattr(self.opts, 'sendcall_demand', False)))
            print(f'[*] --inject-call: do one in-client 0437/0438 action to capture the send object (this)'
                  f'{f"; casts pacejados a {cast_ms}ms no dreno" if cast_ms else ""}')

    def arm_move_dispatch(self):
        """Arma a captura passiva do `this` do dispatcher nativo (DR2); o sitio de disparo (DR3) so
        e armado quando chega um 035f."""
        if getattr(self.opts, 'move_dispatch', False) and self.relay is not None:
            self.post(move_dispatch_msg(arm=True, dispatcher=getattr(self.opts, 'move_dispatch_ptr', None),
                                        site=getattr(self.opts, 'move_dispatch_site', None)))
            print('[*] --move-dispatch: walk once in-client so the dispatcher `this` is captured (passive)')

    def recapture_sendcall(self, reason='session transition'):
        """Fail closed on map/session changes: invalidate the old native SendPacket this."""
        if getattr(self.opts, 'inject_call', False) and self.relay is not None:
            self.post({'type': 'sendcall', 'recapture': True, 'reason': reason, 'delayMs': max(0, int(getattr(self.opts, 'map_settle_ms', 1500)))})
            print(f'[*] --inject-call: {reason}; SendPacket invalidado, aguardando recaptura nativa')

    def on_map_boundary(self, conn, pid, off, pkt):
        """Recognized ZC map transition (0091/0092) in the tokenized inbound stream."""
        if pid not in (0x0091, 0x0092):
            return
        self.recapture_sendcall(f'map packet 0x{pid:04x}')
        # A single trigger in the agent invalidates BOTH SendPacket and move-dispatch.

    def recapture_move_dispatch(self):
        """Pós reconexão/relogin: o `this` capturado do dispatcher aponta para objeto de mapa já
        liberado; firá-lo congela o cliente. Zera e re-arma a captura passiva (DR2) para recapturar
        no próximo passo in-client. Ligado em relay.on_connect (só dispara em RE-conexão)."""
        self.recapture_sendcall('relay connection change')
        # resetNativeSession invalidates BOTH native contexts, then waits 5000 ms.

    def post_move_dispatch(self, x, y):
        self.post(move_dispatch_msg(x, y))

    def arm_trace(self):
        """Rastreio com Stalker: teste de sobrevivência (--trace-test), uaRO->gepard (--trace-walk)
        ou uaRO->uaRO (--trace-internal). Faixa do código uaRO 0x401000..0x1717000."""
        w, t = getattr(self.opts, 'trace_walk', 0), getattr(self.opts, 'trace_test', 0)
        ti = getattr(self.opts, 'trace_internal', 0)
        if ti:
            print(f'[*] --trace-internal: Stalker por {ti}ms registrando chamadas uaRO->uaRO (ARRISCADO)')
            self.post(trace_msg(ti, 0x401000, 0x1717000, interno=True))
        elif w:
            print(f'[*] --trace-walk: Stalker por {w}ms registrando chamadas uaRO->gepard (ARRISCADO)')
            self.post(trace_msg(w, 0x401000, 0x1717000))
        elif t:
            print(f'[*] --trace-test: Stalker por {t}ms (teste de sobrevivencia, ARRISCADO)')
            self.post(trace_msg(t))

    # ---- pacotes que o consumidor devolve ---------------------------------------------------
    def _on_inbound_scramble(self, payload, typ):
        """Entrega o corpo ao agente por id; o BP de cifragem o substitui (pré-XOR) na próxima vez
        que o cliente montar esse id. Uso único: o agente o descarta após a primeira escrita."""
        if typ != 'S' or len(payload) < 2:
            print(f"[inject] skip typ={typ!r} len={len(payload)} (need an 'S' packet with an id)")
            return
        pid = payload[0] | payload[1] << 8
        body = payload[2:]                             # o id já está correto no slot; só o corpo é XORado
        print(f"[inject] inbound id=0x{pid:04x} len={len(payload)} -> scramble body map (pre-XOR): "
              f"{payload[:16].hex()}")
        self.post(scramble_set_msg(pid, body.hex()))
        synth = getattr(self, 'synth', None)               # --synth-input: dispara a tecla do carrier
        if synth is not None:                              # (só ids com tecla mapeada; 035f é ignorado)
            synth.on_armed(pid)

    def _egress_enqueue(self, payload, typ):
        """relay.on_inbound sob --egress-queue: enfileira o quadro do consumidor com o instante de
        chegada, em ordem. O dreno (_egress_drain) despacha um por vez, com espaço, para 035f e
        0437/0438 não se atropelarem, e DESCARTA o que esperou demais (--egress-max-age-ms).
        SÓ quadros 'S' (cliente->servidor, o que injetamos) entram: os 'R' (recv que o consumidor
        espelha) não são injeção e, em massa, afogariam a FIFO e atrasariam/expulsariam as ações."""
        if typ != 'S' or len(payload) < 2:
            return
        self._egress_q.put((time.monotonic(), payload, typ))

    def _egress_drain(self):
        """Worker único: tira um quadro da fila FIFO. Se ele já esperou mais de --egress-max-age-ms
        (fila atolada -> pedido de andar com coordenada velha), DROPA sem despachar nem pacear (drena
        rápido até o fresco). Senão despacha pela rota normal (_on_inbound_split) e dorme
        --egress-interval-ms (ou --egress-action-gap-ms após uma ação). Preserva a ordem de chegada."""
        while True:
            ts, payload, typ = self._egress_q.get()
            age = time.monotonic() - ts
            if self._egress_max_age > 0 and age > self._egress_max_age:
                pid = (payload[0] | payload[1] << 8) if (typ == 'S' and len(payload) >= 2) else None
                idtxt = f'0x{pid:04x}' if pid is not None else f'typ={typ!r}'
                print(f'[egress] drop {idtxt} (esperou {age*1000:.0f}ms > {int(self._egress_max_age*1000)}ms)')
                continue
            try:
                self._on_inbound_split(payload, typ)
            except Exception as e:
                print(f'[egress] dispatch error: {type(e).__name__}: {e}')
            gap = self._egress_interval
            if typ == 'S' and len(payload) >= 2:
                pid = payload[0] | payload[1] << 8
                if pid in WriteBack.ACTION_MERGE_IDS:
                    gap = self._egress_action_gap
            if gap > 0:
                time.sleep(gap)

    def _on_inbound_split(self, payload, typ):
        """Roteia por id: 035f pelo merge (uso único), demais ações pela SendPacket."""
        if typ != 'S' or len(payload) < 2:
            print(f"[inject] skip typ={typ!r} len={len(payload)} (need an 'S' packet with an id)")
            return
        pid = payload[0] | payload[1] << 8
        md = getattr(getattr(self, 'opts', None), 'move_dispatch', False)
        if pid == self.WALK_ID and md:
            if len(payload) < 5:
                print(f'[inject] 035f too short ({len(payload)}B): dropped')
                return
            x, y, _d = unpack_move(payload[2:5])
            print(f'[inject] 035f -> native dispatch to ({x},{y}); original 035f dropped')
            self.post_move_dispatch(x, y)              # o cliente monta/cifra o proprio; nada e reenviado
        elif pid == self.WALK_ID:
            self._on_inbound_scramble(payload, typ)
        elif (getattr(getattr(self, 'opts', None), 'action_merge', False) and pid in WriteBack.ACTION_MERGE_IDS
              and getattr(self, '_scramble_armed', False)):
            if getattr(getattr(self, 'opts', None), 'target_select', False):
                self._emit_target_select(pid, payload)  # --target-select: 0368 (seleção) antes da ação
            self._on_inbound_scramble(payload, typ)    # --action-merge: ação com alvo -> merge, não SendPacket
        elif md and not getattr(self.opts, 'inject_call', False):
            print(f'[inject] id=0x{pid:04x}: no handler under --move-dispatch without --inject-call; dropped')
        else:
            self._on_inbound_sendcall(payload, typ)

    def _target_gid(self, pid, payload):
        """GID do alvo de uma ação, ou None quando ela não tem alvo (sentar/levantar têm GID 0).
        Perícia 0438: GID no deslocamento 6. Ação 0437: GID no deslocamento 2 (ataque = GID != 0)."""
        if pid == self.SKILL_ID and len(payload) >= 10:
            return payload[6:10]
        if pid == self.ACT_ID and len(payload) >= 7 and payload[2:6] != b'\x00\x00\x00\x00':
            return payload[2:6]
        return None

    def _emit_target_select(self, pid, payload):
        """--target-select: emite um 0368 (CZ_REQNAME_BYGID) de seleção do alvo pela SendPacket do
        cliente ANTES da ação, imitando o clique. Dedup por GID (só reemite quando o alvo muda) para
        não floodar o gepard. Vale tanto na via SendPacket quanto na via merge (--action-merge).
        OFF por padrão: o 0368 é só um PEDIDO DE NOME, não um lock de alvo, e a ação (0437/0438) já
        carrega o GID — ao vivo o ataque saiu com e sem ele (ver REFUTADO em HANDOFF_CODEX.md); fica
        como experimento reabilitável, sem alterar o caminho padrão."""
        if not getattr(getattr(self, 'opts', None), 'target_select', False):
            return
        gid = self._target_gid(pid, payload)
        if gid is None or gid == getattr(self, '_last_select_gid', None):
            return
        select = bytes([self.SELECT_ID & 0xff, self.SELECT_ID >> 8]) + gid
        print(f"[inject] target-select 0x{self.SELECT_ID:04x} GID={gid.hex()} antes de 0x{pid:04x}")
        self.post(sendcall_emit_msg(select.hex()))
        self._last_select_gid = gid                    # só reemite o 0368 quando o alvo muda (anti-flood)

    def _on_inbound_sendcall(self, payload, typ):
        """Entrega ao agente para transmitir pela SendPacket do próprio cliente (espontâneo).
        Para ações com alvo, emite antes um 0368 (seleção do alvo por GID) se --target-select (ver
        _emit_target_select; OFF por padrão porque o 0368 não é necessário e já foi refutado como
        solução)."""
        if typ != 'S' or len(payload) < 2:
            print(f"[inject] skip typ={typ!r} len={len(payload)} (need an 'S' packet with an id)")
            return
        pid = payload[0] | payload[1] << 8
        # O paceamento dos casts (0438/0af4) é feito no DRENO do agente, não aqui: o consumidor manda
        # re-tentativas espaçadas que passariam deste filtro mas, enfileiradas, drenam juntas e cada
        # cast cancela o anterior. O agente deixa passar um cast por janela (ver cast_ms em sendcall).
        self._emit_target_select(pid, payload)         # --target-select (OFF por padrão): 0368 antes
        print(f"[inject] inbound id=0x{pid:04x} len={len(payload)} -> SendPacket: {payload[:16].hex()}")
        self.post(sendcall_emit_msg(payload.hex()))
