"""Interactive fallback discovery integrated into the relay process.

The wizard is deliberately observation-only: it collects short internal call-edge
traces and ranks shared callees. It never promotes or invokes a candidate.
"""
from collections import defaultdict
import json
from pathlib import Path
import queue
import time

from .client_discovery import discover_gamemode_sendmsg
from .client_discovery_fallback import profile_for_executable, rank_behavioral_dispatchers
from .client_profile import ClientFingerprint
from .protocol import module_info_msg, trace_msg


STEPS = (
    ('baseline', 'Não faça nada no cliente durante a janela de coleta.'),
    ('move', 'Faça UM movimento/click para andar assim que a coleta começar.'),
    ('attack', 'Faça UM ataque normal assim que a coleta começar.'),
    ('skill_target', 'Use UMA skill com alvo assim que a coleta começar.'),
    ('use_item', 'Use UM item assim que a coleta começar.'),
)


class DiscoveryWizardError(RuntimeError):
    pass


class DiscoveryWizard:
    def __init__(self, post, module, out_path, runs=3, trace_ms=1200, arm_delay_ms=1500,
                 input_fn=input, sleep_fn=time.sleep, print_fn=print):
        if runs < 2:
            raise ValueError('discovery wizard requires at least two runs per step')
        if not 200 <= trace_ms <= 5000:
            raise ValueError('trace_ms must be between 200 and 5000')
        if not 0 <= arm_delay_ms <= 10000:
            raise ValueError('arm_delay_ms must be between 0 and 10000')
        self.post = post
        self.module = module
        self.out_path = Path(out_path)
        self.runs = runs
        self.trace_ms = trace_ms
        self.arm_delay_ms = arm_delay_ms
        self.input = input_fn
        self.sleep = sleep_fn
        self.print = print_fn
        self.messages = queue.Queue()
        self.serial = 0
        self.traces = defaultdict(list)
        self.module_info = None

    def on_message(self, payload):
        if payload.get('tag') in ('MODULE-INFO', 'TRACE'):
            self.messages.put(payload)

    def _token(self, prefix):
        self.serial += 1
        return f'wizard-{prefix}-{self.serial}'

    def _await(self, tag, token, timeout):
        deadline = time.monotonic() + timeout
        while True:
            left = deadline - time.monotonic()
            if left <= 0:
                raise DiscoveryWizardError(f'timeout waiting for {tag} ({token})')
            try:
                msg = self.messages.get(timeout=left)
            except queue.Empty as exc:
                raise DiscoveryWizardError(f'timeout waiting for {tag} ({token})') from exc
            if msg.get('tag') == tag and msg.get('token') == token:
                if msg.get('erro'):
                    raise DiscoveryWizardError(f'{tag}: {msg["erro"]}')
                return msg

    def resolve_module(self):
        token = self._token('module')
        self.post(module_info_msg(self.module, token))
        info = self._await('MODULE-INFO', token, 5.0)
        self.module_info = info
        return int(info['base'], 16), int(info['end'], 16)

    def _persist(self):
        self.out_path.parent.mkdir(parents=True, exist_ok=True)
        payload = {label: runs for label, runs in self.traces.items()}
        tmp = self.out_path.with_suffix(self.out_path.suffix + '.tmp')
        tmp.write_text(json.dumps(payload, indent=2) + '\n', encoding='utf-8')
        tmp.replace(self.out_path)

    def _capture_one(self, label, run_index, lo, hi):
        self.print('')
        self.print(f'[wizard] {label} — amostra {run_index}/{self.runs}')
        instruction = dict(STEPS)[label]
        self.print(f'[wizard] {instruction}')
        self.print('[wizard] Pressione ENTER quando o cliente estiver pronto. Você terá um curto intervalo para voltar ao jogo.')
        self.input()
        if self.arm_delay_ms:
            self.print(f'[wizard] coleta começa em {self.arm_delay_ms / 1000:.1f}s...')
            self.sleep(self.arm_delay_ms / 1000)
        self.print(f'[wizard] AGORA — janela de {self.trace_ms}ms')
        token = self._token(f'{label}-{run_index}')
        self.post(trace_msg(self.trace_ms, lo, hi, interno=True, token=token))
        msg = self._await('TRACE', token, self.trace_ms / 1000 + 5.0)
        run = {
            'chamadas': list(msg.get('chamadas') or []),
            'ms': msg.get('ms', self.trace_ms),
            'bytes': msg.get('bytes', 0),
        }
        self.traces[label].append(run)
        self._persist()
        self.print(f'[wizard] capturadas {len(run["chamadas"])} arestas internas distintas.')
        return run

    def run(self):
        lo, hi = self.resolve_module()
        self.print(f'[wizard] módulo {self.module}: 0x{lo:x}-0x{hi:x}')
        self.print('[wizard] modo somente-observação: nenhum candidato será chamado automaticamente.')
        for label, _instruction in STEPS:
            for run_index in range(1, self.runs + 1):
                self._capture_one(label, run_index, lo, hi)

        candidates = rank_behavioral_dispatchers(self.traces)
        result = {
            'method': 'behavioral-passive',
            'module': self.module,
            'module_base': lo,
            'module_end': hi,
            'runs_per_step': self.runs,
            'trace_ms': self.trace_ms,
            'trace_set': str(self.out_path),
            'promotion_required': True,
            'candidates': candidates[:20],
        }
        result_path = self.out_path.with_suffix('.result.json')
        result_path.write_text(json.dumps(result, indent=2) + '\n', encoding='utf-8')
        return result, result_path


def static_or_profile_available(executable, profiles_dir):
    """Return discovery metadata when the interactive fallback is unnecessary."""
    try:
        found = discover_gamemode_sendmsg(executable)
        return {
            'method': 'static-rtti',
            'confidence': found.get('confidence'),
            'send_msg_rva': found['game_mode']['send_msg_rva'],
        }
    except (ValueError, OSError):
        pass
    profile = profile_for_executable(executable, profiles_dir)
    if profile is not None:
        game_mode = profile.native_group('game_mode')
        return {
            'method': 'known-profile',
            'confidence': 'exact-build',
            'profile': profile.name,
            'send_msg_rva': (profile.native_int('game_mode', 'send_msg_rva')
                             if 'send_msg_rva' in game_mode else None),
        }
    return None


def print_result(result, result_path, print_fn=print):
    candidates = result.get('candidates', [])
    print_fn('')
    print_fn(f'[wizard] concluído. Traces: {result["trace_set"]}')
    print_fn(f'[wizard] ranking: {result_path}')
    if not candidates:
        print_fn('[wizard] nenhum candidato multi-ação confiável; manter adapters por ação.')
        return
    print_fn('[wizard] candidatos (ainda NÃO promovidos):')
    for i, item in enumerate(candidates[:10], 1):
        actions = ','.join(item['actions'])
        print_fn(f'  {i:>2}. RVA 0x{item["target_rva"]:x} score={item["score"]} '
                 f'actions={item["action_count"]} callers={item["caller_count"]} [{actions}]')


def _default_output(executable):
    root = Path(__file__).resolve().parents[1] / 'research' / 'client_discovery'
    if executable:
        try:
            digest = ClientFingerprint.from_file(executable).sha256[:12]
        except Exception:
            digest = 'unknown-build'
    else:
        digest = 'runtime-only'
    return root / f'{digest}-traces.json'


def run_wizard_mode(args):
    """CLI entry point. `auto` runs the wizard only when static/profile discovery fails."""
    from .agent import Agent, pick_port

    mode = getattr(args, 'discovery_wizard', 'off')
    if mode == 'off':
        return None
    profiles_dir = getattr(args, 'discovery_profiles', '') or str(Path(__file__).resolve().parents[1] / 'profiles')
    executable = getattr(args, 'client_exe', '')

    if mode == 'auto':
        if not executable:
            raise SystemExit('[!] --discovery-wizard auto requires --client-exe for static/profile preflight')
        found = static_or_profile_available(executable, profiles_dir)
        if found is not None:
            rva = found.get('send_msg_rva')
            suffix = f' SendMsg RVA=0x{rva:x}' if isinstance(rva, int) else ''
            print(f'[*] discovery wizard not needed: {found["method"]} ({found["confidence"]}){suffix}')
            return 0

    port = args.port or pick_port(args.name)
    output = Path(getattr(args, 'discovery_out', '') or _default_output(executable))
    wizard = DiscoveryWizard(
        post=lambda _msg: None,
        module=args.name,
        out_path=output,
        runs=args.discovery_runs,
        trace_ms=args.discovery_trace_ms,
        arm_delay_ms=args.discovery_arm_delay_ms,
    )
    agent = Agent(port, wizard.on_message)
    wizard.post = agent.post
    try:
        agent.load()
        result, result_path = wizard.run()
        print_result(result, result_path)
        return 0
    finally:
        agent.unload()
