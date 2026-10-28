#!/usr/bin/env python3
"""Discover client entry points with layered fallbacks.

Order:
  1. static PE/MSVC discovery;
  2. exact known-profile fingerprint;
  3. behavioral ranking from repeated bounded call traces;
  4. fail closed with a concrete dynamic-capture plan.
"""
import argparse
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from relay.client_discovery import discover_gamemode_sendmsg
from relay.client_discovery_fallback import (
    dynamic_fallback_plan,
    load_trace_set,
    profile_for_executable,
    rank_behavioral_dispatchers,
)
from relay.client_profile import ClientFingerprint

DEFAULT_PROFILES = ROOT / 'profiles'


def hx(value):
    return f'0x{value:x}' if isinstance(value, int) else value


def _static_result(executable):
    discovery = discover_gamemode_sendmsg(executable)
    return {'method': 'static-rtti', **discovery}


def _profile_result(executable, profiles_dir):
    profile = profile_for_executable(executable, profiles_dir)
    if profile is None:
        return None
    game_mode = profile.native_group('game_mode')
    result = {
        'method': 'known-profile',
        'profile': profile.name,
        'profile_path': str(profile.source),
        'confidence': 'exact-build',
    }
    if game_mode:
        result['game_mode'] = {
            'send_msg_rva': profile.native_int('game_mode', 'send_msg_rva')
            if 'send_msg_rva' in game_mode else None,
            'send_msg_vslot': game_mode.get('send_msg_vslot'),
            'stack_args': game_mode.get('stack_args'),
        }
    return result


def _behavioral_result(trace_set_path, limit=12):
    traces = load_trace_set(trace_set_path)
    candidates = rank_behavioral_dispatchers(traces)
    if not candidates:
        return {
            'method': 'behavioral-passive',
            'confidence': 'insufficient-evidence',
            'candidates': [],
        }
    return {
        'method': 'behavioral-passive',
        'confidence': 'candidate-ranking',
        'candidates': candidates[:limit],
        'promotion_required': True,
    }


def discover(executable, profiles_dir=DEFAULT_PROFILES, trace_set=None):
    fp = ClientFingerprint.from_file(executable)
    attempts = []

    try:
        result = _static_result(executable)
        result['fingerprint'] = fp.as_dict()
        result['attempts'] = attempts
        return result
    except (ValueError, OSError) as exc:
        attempts.append({'method': 'static-rtti', 'ok': False, 'reason': str(exc)})

    profile = _profile_result(executable, profiles_dir)
    if profile is not None:
        profile['fingerprint'] = fp.as_dict()
        profile['attempts'] = attempts
        return profile
    attempts.append({'method': 'known-profile', 'ok': False, 'reason': 'no exact fingerprint match'})

    if trace_set:
        behavioral = _behavioral_result(trace_set)
        behavioral['fingerprint'] = fp.as_dict()
        behavioral['attempts'] = attempts
        if behavioral['candidates']:
            return behavioral
        attempts.append({
            'method': 'behavioral-passive',
            'ok': False,
            'reason': 'trace set produced no multi-action candidates',
        })

    return {
        'method': 'dynamic-required',
        'confidence': 'none',
        'fingerprint': fp.as_dict(),
        'attempts': attempts,
        'fallback_plan': dynamic_fallback_plan(),
    }


def _print_human(result, executable):
    print(f'Client: {executable}')
    print(f'  sha256:     {result["fingerprint"]["sha256"]}')
    print(f'  method:     {result["method"]}')
    print(f'  confidence: {result.get("confidence", "?")}')

    gm = result.get('game_mode')
    if gm:
        if gm.get('send_msg_va') is not None:
            print(f'  SendMsg VA:  {hx(gm["send_msg_va"])}')
        if gm.get('send_msg_rva') is not None:
            print(f'  SendMsg RVA: {hx(gm["send_msg_rva"])}')
        if gm.get('send_msg_vslot') is not None:
            print(f'  vslot:       {gm["send_msg_vslot"]}')
    if result.get('profile'):
        print(f'  profile:     {result["profile"]}')

    if result.get('candidates') is not None:
        print('Behavioral candidates:')
        for i, candidate in enumerate(result['candidates'], 1):
            print(
                f'  {i:>2}. target RVA {hx(candidate["target_rva"])} '
                f'coverage={candidate["action_count"]} actions '
                f'callers={candidate["caller_count"]} score={candidate["score"]}'
            )
            print(f'      actions: {", ".join(candidate["actions"])}')

    if result['method'] == 'dynamic-required':
        print('Static discovery was not sufficient. Dynamic fallback is required.')
        plan = result['fallback_plan']
        print(f'  mode: {plan["mode"]}')
        print(f'  trace window: {plan["capture"]["window_ms"]} ms')
        print('  capture repeated idle + MOVE + ATTACK + SKILL + ITEM windows; rank shared callees.')
        print('  candidates remain passive until argument/this validation succeeds.')

    if result.get('attempts'):
        print('Fallback history:')
        for attempt in result['attempts']:
            print(f'  {attempt["method"]}: {attempt["reason"]}')


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('executable')
    ap.add_argument('--profiles', default=str(DEFAULT_PROFILES),
                    help='directory of exact-build profiles')
    ap.add_argument('--trace-set',
                    help='JSON with repeated baseline/action TRACE runs for behavioral fallback')
    ap.add_argument('--json', action='store_true', help='emit machine-readable JSON')
    args = ap.parse_args(argv)

    result = discover(args.executable, args.profiles, args.trace_set)
    if args.json:
        print(json.dumps(result, indent=2))
    else:
        _print_human(result, args.executable)
    return 2 if result['method'] == 'dynamic-required' else 0


if __name__ == '__main__':
    raise SystemExit(main())
