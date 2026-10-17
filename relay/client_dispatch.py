"""Bounded client readiness, session cancellation and local monotonic timings.

There is no clock-based release or expiry. A native completion releases the next
command; a full interface reports failure instead of overwriting pending bytes.
Completion means local execution, never server acceptance.
"""
from collections import defaultdict, deque
import threading
import time

from .packet_pipeline import unpack_move
from .frida_bridge import (move_dispatch_msg, scramble_msg, scramble_set_msg, sendcall_emit_msg, sendcall_msg,
                       sendwatch_msg)
from .synthetic_input import build_actuator


class CommandPipeline:
    CAPACITY = 64
    ACTION_IDS = {0x035f, 0x0437, 0x0438, 0x0af4}
    TERMINAL = {'SCRAMBLE': {'consumed', 'error', 'cancelled'},
                'SENDCALL': {'sent', 'error'},
                'MOVE-DISPATCH': {'dispatched', 'abort', 'error'}}

    def __init__(self, dispatch, reset, log, armed=None, clock=time.monotonic_ns):
        self.dispatch, self.reset, self.log, self.armed = dispatch, reset, log, armed
        self.clock = clock
        self.lock = threading.RLock()
        self.epoch = 0
        self.active = False
        self.pending = deque()
        self.current = None
        self.serial = 0
        self.samples = defaultdict(lambda: deque(maxlen=2048))

    def session(self, active, advance_epoch=True):
        with self.lock:
            count = len(self.pending) + bool(self.current)
            if advance_epoch:
                self.epoch += 1
            self.active = active
            self.pending.clear()
            self.current = None
            self.reset(self.epoch, active)
            self.log({'tag': 'SESSION', 'epoch': self.epoch, 'active': active, 'cancelled': count})

    def accept(self, payload, typ):
        if typ != 'S' or len(payload) < 2:
            return False
        with self.lock:
            if not self.active or len(self.pending) + bool(self.current) >= self.CAPACITY:
                self.log({'tag': 'COMMAND', 'hit': 'error', 'e': 'disconnected' if not self.active
                          else 'client readiness capacity exhausted', 'epoch': self.epoch,
                          'code': 'COMMAND_CAPACITY' if self.active else 'COMMAND_DISCONNECTED',
                          'id': int.from_bytes(payload[:2], 'little'), 'len': len(payload),
                          **self._blocked_metadata()})
                return False
            self.serial += 1
            self.pending.append({'payload': bytes(payload), 'typ': typ, 'token': self.serial,
                                 'epoch': self.epoch, 'received_ns': self.clock()})
            self._next()
            return True

    def _blocked_metadata(self):
        """Describe readiness without exposing packet bodies or native pointers. Lock held."""
        state = {'pending': len(self.pending), 'capacity': self.CAPACITY}
        c = self.current
        if c is not None:
            stage = ('input' if c.get('native_done') else
                     'carrier' if 'armed_ns' in c else 'native')
            state.update(blocked_id=int.from_bytes(c['payload'][:2], 'little'),
                         blocked_token=c['token'], blocked_stage=stage,
                         blocked_ms=(self.clock() - c['received_ns']) / 1e6)
        return state

    def _next(self):
        while self.active and self.current is None and self.pending:
            c = self.current = self.pending.popleft()
            c['dispatch_ns'] = self.clock()
            self.samples['ready_wait_ms'].append((c['dispatch_ns'] - c['received_ns']) / 1e6)
            pid = int.from_bytes(c['payload'][:2], 'little')
            if pid in self.ACTION_IDS:
                self.log({'tag': 'COMMAND', 'hit': 'dispatch', 'id': pid,
                          'token': c['token'], 'epoch': c['epoch'], 'len': len(c['payload'])})
            try:
                # False = explicit local rejection; no native completion can arrive.
                waiting = self.dispatch(c)
            except Exception as e:
                waiting = False
                self.log({'tag': 'COMMAND', 'hit': 'error', 'token': c['token'],
                          'epoch': c['epoch'], 'id': pid, 'code': 'COMMAND_DISPATCH_FAILED',
                          'e': type(e).__name__})
            if waiting is False and self.current is c:
                self.current = None
            elif self.current is c:
                break

    def observe(self, m):
        with self.lock:
            c = self.current
            if c is None or m.get('epoch') != self.epoch or m.get('token') != c['token']:
                return False
            tag, hit = m.get('tag'), m.get('hit')
            now = self.clock()
            m['local_elapsed_ms'] = (now - c['received_ns']) / 1e6
            if isinstance(m.get('observed_ns'), int):
                self.samples['event_worker_wait_ms'].append((now - m['observed_ns']) / 1e6)
            begin, end, accepted = (m.get(k) for k in
                                    ('native_begin_mono_ms', 'native_end_mono_ms', 'accepted_mono_ms'))
            if isinstance(begin, (float, int)) and isinstance(end, (float, int)):
                self.samples['native_call_ms'].append(end - begin)
                if isinstance(accepted, (float, int)):
                    self.samples['agent_schedule_ms'].append(begin - accepted)
            if tag == 'SCRAMBLE' and hit == 'armed':
                c['armed_ns'] = now
                self.samples['post_to_armed_ms'].append((now - c['dispatch_ns']) / 1e6)
                if self.armed:
                    c['input_pending'] = self.armed(m) is True
            if tag == 'INPUT' and hit == 'released':
                c['input_done'] = True
                if not c.get('native_done') and 'armed_ns' in c:
                    self.log({'tag': 'COMMAND', 'hit': 'waiting', 'code': 'COMMAND_CARRIER_PENDING',
                              'epoch': self.epoch, **self._blocked_metadata()})
            if hit in self.TERMINAL.get(tag, ()):
                self.samples['local_completion_ms'].append(m['local_elapsed_ms'])
                if 'armed_ns' in c:
                    self.samples['carrier_wait_ms'].append((now - c['armed_ns']) / 1e6)
                c['native_done'] = True
            if c.get('native_done') and (not c.get('input_pending') or c.get('input_done')):
                self.current = None
                self._next()
            return True

    def measure(self, stage, value):
        with self.lock:
            self.samples[stage].append(value)

    def summary(self):
        with self.lock:
            out = {}
            for name, values in self.samples.items():
                ordered = sorted(values)
                if ordered:
                    out[name] = {'n': len(ordered), **{label: ordered[max(0, (len(ordered)*p+99)//100-1)]
                                 for label, p in (('median', 50), ('p95', 95), ('p99', 99), ('max', 100))}}
            return out


# A watch de dados dispara uma instrução DEPOIS da escrita; o store `mov [reg],bl` tem 2 bytes.
# O breakpoint de execução precisa cair no próprio store, com o texto claro ainda presente.
SCRAMBLE_STORE_BACK = 2


class ClientDispatcher:
    def __init__(self, capture, opts, post):
        self.capture, self.opts, self.relay = capture, opts, capture.relay
        self.log, self._agent_post = capture.log, post
        self.scramble = self._build_scramble(opts)

    def configure(self, pid, wire):
        self._wire_writeback(self.opts, pid, wire)
        self._route = self.relay.on_inbound if self.relay else None
        self.commands = CommandPipeline(self._dispatch_command, self._reset_session,
                                        self.log.write, self._carrier_armed)
        if self.relay:
            self.relay.on_inbound = self.commands.accept if self._route else None
            self.relay.on_connect = lambda: self.commands.session(True)
            self.relay.on_disconnect = self.capture.suspend_commands
        if self.synth:
            self.synth.on_error = self._carrier_failed
            self.synth.on_finished = self.capture.work.put

    def post(self, message, command=None):
        if command is not None:
            message = dict(message, token=command['token'], epoch=command['epoch'])
            command['posted'] = True
        self._agent_post(message)

    def _dispatch_command(self, command):
        self._route(command['payload'], command['typ'], command)
        return command.get('posted', False)

    def _reset_session(self, epoch, active):
        self._agent_post({'type': 'session-reset', 'epoch': epoch, 'active': active,
                          'min_token': self.commands.serial + 1})
        if self.synth:
            self.synth.reset(epoch, active)
        self.capture._reset_session(epoch, active)

    WALK_ID = 0x035f                                   # andar: único pacote roteado para o merge
    ACTION_MERGE_IDS = (0x0437, 0x0438, 0x0af4)         # ações com alvo roteáveis ao merge (--action-merge)
    SKIP_IDS = (0x0368, 0x0369, 0x0193, 0x0094, 0x0360)   # tagarelice que o cliente já emite sozinho
    #                                                    (pedido de nome por GID / tick): não reinjetamos
    #                                                    a do consumidor, senão floda o servidor (gepard).

    # ---- configuração do ponto de cifragem --------------------------------------------------
    def _build_scramble(self, opts):
        if getattr(opts, 'probe_entry', '') or getattr(opts, 'probe_at', ''):
            from .research_diagnostics import scramble_probe_config
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
            self.autodiscover = bool(self.capture.sendwatch)
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
            store_off = int(m['enc'], 16) - self.capture.gepard_base - SCRAMBLE_STORE_BACK
            probe = bool(getattr(self.opts, 'send_probe', False))
            ids = [int(x, 16) for x in getattr(self.opts, 'probe_ids', '0437,0438').split(',') if x.strip()]
            if getattr(self.opts, 'scramble_range', ''):   # faixa explícita (ex.: a pilha do 035f)
                lo, hi = (int(x, 16) for x in self.opts.scramble_range.split('-'))
            else:
                r = self.capture._queue_range()                    # o bloco ring/fila (padrão)
                lo, hi = (r[0], r[1]) if r else (None, None)
            persist = False
            anyid = bool(getattr(self.opts, 'probe_anyid', False))
            pid = int(self.opts.scramble_id, 16)
            self.post(sendwatch_msg())                     # desarma a send-watch (lo omitido = off)
            self.capture.sendwatch = None
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

    def post_move_dispatch(self, x, y, command=None):
        self.post(move_dispatch_msg(x, y), command)

    # ---- pacotes que o consumidor devolve ---------------------------------------------------
    def _on_inbound_scramble(self, payload, typ, command=None):
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
        self.post(scramble_set_msg(pid, body.hex()), command)

    def _on_inbound_split(self, payload, typ, command=None):
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
            self.post_move_dispatch(x, y, command)              # o cliente monta/cifra o proprio; nada e reenviado
        elif pid == self.WALK_ID:
            self._on_inbound_scramble(payload, typ, command)
        elif (getattr(getattr(self, 'opts', None), 'action_merge', False) and pid in self.ACTION_MERGE_IDS
              and getattr(self, '_scramble_armed', False)):
            self._on_inbound_scramble(payload, typ, command)    # --action-merge: ação com alvo -> merge, não SendPacket
        elif md and not getattr(self.opts, 'inject_call', False):
            print(f'[inject] id=0x{pid:04x}: no handler under --move-dispatch without --inject-call; dropped')
        else:
            self._on_inbound_sendcall(payload, typ, command)

    def _on_inbound_sendcall(self, payload, typ, command=None):
        """Generic fallback: native call completion does not prove wire/server acceptance."""
        if typ != 'S' or len(payload) < 2:
            print(f"[inject] skip typ={typ!r} len={len(payload)} (need an 'S' packet with an id)")
            return
        pid = payload[0] | payload[1] << 8
        if pid in self.SKIP_IDS:                       # o cliente já emite isso; não reinjetar (anti-flood)
            print(f'[inject] omit id=0x{pid:04x}: emitido naturalmente pelo cliente (anti-reinjeção)')
            return
        print(f'[inject] id=0x{pid:04x} len={len(payload)} -> SendPacket (execução não confirmada)')
        self.post(sendcall_emit_msg(payload.hex()), command)

    def _carrier_armed(self, m):
        if self.synth:
            return self.synth.on_armed(m['id'], m['epoch'], m['token'])

    def _carrier_failed(self, m):
        # Clear an armed body before allowing another command. Agent emits cancelled
        # for the current head; no synthetic failure can leave a stale body armed.
        with self.commands.lock:
            current = self.commands.current
            if current and m['epoch'] == self.commands.epoch and m['token'] == current['token']:
                if not current.get('native_done'):
                    self._agent_post({'type': 'scramble-set', 'id': m['id'], 'body': None,
                                      'epoch': m['epoch'], 'token': m['token']})
                self.log.write(m)
