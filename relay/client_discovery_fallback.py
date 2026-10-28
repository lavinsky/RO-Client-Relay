"""Fallbacks when static CGameMode discovery is unavailable.

The dynamic path consumes bounded call-edge observations collected while the
user performs known actions. It never assumes symbol names or stable absolute
addresses, so it remains useful when a protector strips RTTI or virtualizes
parts of the executable.
"""
from collections import defaultdict
import json
from pathlib import Path
import re

from .client_profile import ClientFingerprint, ClientProfile, ProfileError


_INTERNAL_EDGE = re.compile(r'^(0x[0-9a-fA-F]+)>u(0x[0-9a-fA-F]+)$')


def profile_for_executable(executable, profiles_dir):
    """Return an exact SHA-256 profile match, or None."""
    fp = ClientFingerprint.from_file(executable)
    root = Path(profiles_dir)
    if not root.is_dir():
        return None
    for path in sorted(root.glob('*.json')):
        try:
            profile = ClientProfile.load(path)
            if profile.fingerprint.get('sha256', '').lower() == fp.sha256.lower():
                profile.verify_executable(executable)
                return profile
        except ProfileError:
            continue
    return None


def _edge_set(run):
    """Normalize one TRACE run into {(caller_rva, callee_rva), ...}."""
    if isinstance(run, dict):
        run = run.get('chamadas', run.get('calls', []))
    edges = set()
    for raw in run or ():
        match = _INTERNAL_EDGE.match(str(raw))
        if not match:
            continue
        edges.add((int(match.group(1), 16), int(match.group(2), 16)))
    return edges


def stable_edges(runs, min_fraction=0.67):
    """Edges recurring in enough repeated runs to be considered action-stable."""
    runs = list(runs or ())
    if not runs:
        return set()
    counts = defaultdict(int)
    for run in runs:
        for edge in _edge_set(run):
            counts[edge] += 1
    required = max(1, int(len(runs) * min_fraction + 0.999999))
    return {edge for edge, count in counts.items() if count >= required}


def load_trace_set(path):
    """Load {baseline:[runs...], move:[runs...], ...} JSON."""
    raw = json.loads(Path(path).read_text(encoding='utf-8'))
    if not isinstance(raw, dict):
        raise ValueError('trace set must be a JSON object keyed by action label')
    normalized = {}
    for label, runs in raw.items():
        if isinstance(runs, dict):
            runs = [runs]
        if not isinstance(runs, list):
            raise ValueError(f'trace label {label!r} must contain a list of runs')
        normalized[label] = runs
    return normalized


def rank_behavioral_dispatchers(trace_set, min_actions=2, stable_fraction=0.67):
    """Rank internal call targets shared by several actions but absent from idle baseline.

    This intentionally returns candidates rather than claiming a unique dispatcher:
    packet-build, send and other shared layers can also converge across actions.
    A later passive breakpoint/argument validation step must promote one candidate.
    """
    baseline = stable_edges(trace_set.get('baseline', []), stable_fraction)
    action_labels = [label for label in trace_set if label != 'baseline']
    stable = {
        label: stable_edges(trace_set[label], stable_fraction) - baseline
        for label in action_labels
    }

    by_target = defaultdict(lambda: {'actions': set(), 'callers': set(), 'edges': set()})
    for label, edges in stable.items():
        for caller, target in edges:
            entry = by_target[target]
            entry['actions'].add(label)
            entry['callers'].add(caller)
            entry['edges'].add((caller, target))

    candidates = []
    total_actions = max(1, len(action_labels))
    for target, evidence in by_target.items():
        action_count = len(evidence['actions'])
        if action_count < min_actions:
            continue
        caller_count = len(evidence['callers'])
        coverage = action_count / total_actions
        score = action_count * 100 + min(caller_count, 9) * 10
        if coverage == 1.0 and total_actions >= 3:
            score += 50
        candidates.append({
            'target_rva': target,
            'actions': sorted(evidence['actions']),
            'action_count': action_count,
            'action_coverage': round(coverage, 3),
            'caller_count': caller_count,
            'callers': sorted(evidence['callers']),
            'score': score,
        })
    candidates.sort(key=lambda item: (-item['score'], item['target_rva']))
    return candidates


def dynamic_fallback_plan():
    return {
        'mode': 'behavioral-passive',
        'required_runs': {
            'baseline': 3,
            'move': 3,
            'attack': 3,
            'skill_target': 3,
            'use_item': 3,
        },
        'capture': {
            'trace': 'bounded uaRO->uaRO call edges',
            'window_ms': '300-700',
            'rule': 'one known action per window; repeat the same action in separate runs',
        },
        'ranking': [
            'keep edges stable across repeated runs of the same action',
            'subtract edges stable during idle baseline',
            'rank internal callees shared by multiple distinct actions',
            'validate top candidates passively before any NativeFunction call',
        ],
        'promotion_rule': (
            'never auto-call a candidate: require repeatable hits for multiple actions, '
            'sane arguments/this, and no idle-only explanation'
        ),
        'last_resort': {
            'mode': 'per-action-adapters',
            'when': 'shared callable dispatcher remains hidden/virtualized or candidates stay ambiguous',
            'policy': (
                'keep known-good native UI/carrier/merge/SendPacket routes per semantic action; '
                'do not guess a dispatcher address merely to make discovery look complete'
            ),
        },
    }
