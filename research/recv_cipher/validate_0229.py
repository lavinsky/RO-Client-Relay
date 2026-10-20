"""Offline, read-only 0229 candidate assessment. Never authorizes delivery by itself.

OpenKore ServerType0: ID(a4), opt1(v), opt2(v), option(V), stance(C).
The wire packet ID is two clear bytes; GID and flags are in the encrypted body.
"""
import collections
import json
import struct
from pathlib import Path

PACKET_ID = b'\x29\x02'
STRUCT = struct.Struct('<2sIHHIB')

# Descriptive reference values from a local sample, NOT protocol allowlists.
REFERENCE_OPT1 = frozenset((0,))
REFERENCE_OPT2 = frozenset((0, 16))
REFERENCE_OPTION = frozenset((0, 16, 32))
REFERENCE_STANCE = frozenset((0,))


def assess(wire, candidate, *, matched_context=False, fresh_slot=False, ambiguous=False):
    """Conservative gate requiring independent ring provenance, not merely plausible flags.

    Return a metadata-only decision (no GIDs or packet bodies).
    """
    flags = {'length': len(wire) == 15 and len(candidate) == 15,
             'header': len(wire) >= 2 and len(candidate) >= 2
                       and wire[:2] == candidate[:2] == PACKET_ID,
             'changed': wire != candidate}
    if not flags['length'] or not flags['header']:
        return {'deliver': False, 'reason': 'invalid-structure', 'checks': flags}
    _, gid, opt1, opt2, option, stance = STRUCT.unpack(candidate)
    # A zero GID is flagged as suspicious, not claimed impossible on every server.
    flags['gid_nonzero'] = gid != 0
    flags['opt1_reference'] = opt1 in REFERENCE_OPT1
    flags['opt2_reference'] = opt2 in REFERENCE_OPT2
    flags['option_reference'] = option in REFERENCE_OPTION
    flags['stance_reference'] = stance in REFERENCE_STANCE
    flags['provenance'] = bool(matched_context and fresh_slot and not ambiguous)
    # Neither matching encrypted GID nor known-looking status fields proves decryption.
    allowed = flags['changed'] and flags['gid_nonzero'] and flags['provenance']
    return {'deliver': bool(allowed),
            'reason': ('verified-context' if allowed else 'insufficient-evidence'),
            'checks': flags}


def audit_log(path):
    counts = collections.Counter()
    for line in Path(path).open(encoding='utf-8', errors='replace'):
        try:
            event = json.loads(line)
            if event.get('tag') != 'RECV-PLAIN' or event.get('id') != '0229':
                continue
            candidate = bytes.fromhex(event['P'])
            if len(candidate) != 15 or candidate[:2] != PACKET_ID:
                counts['invalid-structure'] += 1
                continue
            _, gid, opt1, opt2, option, stance = STRUCT.unpack(candidate)
            counts['total'] += 1
            counts['zero-gid' if not gid else 'nonzero-gid'] += 1
            for name, value, reference in (('opt1', opt1, REFERENCE_OPT1),
                                            ('opt2', opt2, REFERENCE_OPT2),
                                            ('option', option, REFERENCE_OPTION),
                                            ('stance', stance, REFERENCE_STANCE)):
                counts[name + ('-seen-reference' if value in reference else '-outside-reference')] += 1
        except (ValueError, KeyError, TypeError, json.JSONDecodeError):
            counts['malformed-record'] += 1
    return dict(sorted(counts.items()))


if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument('log', type=Path)
    args = parser.parse_args()
    print(json.dumps(audit_log(args.log), indent=2))
