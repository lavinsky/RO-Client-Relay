"""Offline, hypothetical one-byte dependency plan; never executed-flow proof.

python3 -m research.cipher.candidate_slice --input PRIVATE_CAPTURE
Outputs code/relative offsets only. Ambiguous decodes and missing coverage stop it.
"""
import argparse
from pathlib import Path
from .chain_audit import audit_chain
from .core import open_regular, parse_json, require


def candidate_slice(capture, limit=32):
    require(type(limit) is int and 1 <= limit <= 32, 'invalid slice limit')
    audit = audit_chain(capture)
    end = next(e for e in capture['events'] if e.get('tag') == 'DONE')
    result = dict(classification='HYPOTHESIS', executed_path_proven=False,
                  runtime_health=audit['runtime_health'], steps=[])
    require(audit.get('cl_origin', {}).get('conclusion') == 'CL_LOAD_AND_STORE_CONFIRMED' and
            not audit['capture_limit_reached'], 'slice requires complete local CL coverage')
    frame = end['cl_origin']['context']['frame']
    address = end['cl_origin']['source_address']
    expected = end['cl_origin']['source_sample'] & 255
    cutoff = end.get('cl_producer', {}).get('load_order')
    require(type(cutoff) is int, 'missing global consumer order')
    rows = [(r, address) for r in end.get('cl_writer_observations', [])]
    source_watch = end.get('cl_source_watch')
    if source_watch:
        rows += [(r, source_watch['address']) for r in end.get('cl_source_writer_observations', [])]
    extra_watch=end.get('cl_extra_source_watch')
    if extra_watch:
        rows += [(r,extra_watch['address']) for r in end.get('cl_extra_source_writer_observations',[])]
    watched = {a for _, a in rows}
    for _ in range(limit):
        candidates = [r for r, a in rows if a == address and r['order'] < cutoff]
        result['next_offset'] = address - frame
        if not candidates:
            result['stop'] = 'MISSING_WATCHED_WRITER' if address in watched else 'SOURCE_NOT_WATCHED'
            break
        row = max(candidates, key=lambda r: r['order'])
        if row['byte_after'] != expected:
            result['stop'] = 'CANDIDATE_VALUE_MISMATCH'
            break
        if len(row['candidates']) != 1:
            result['stop'] = 'AMBIGUOUS_WRITER_DECODE'
            break
        code = row['candidates'][0]
        step = dict(order=row['order'], writer_rva=hex(code['rva']), instruction=code['instruction'],
                    destination_offset=address-frame)
        result['steps'].append(step)
        swap = code.get('swap_candidate')
        if not swap:
            result['stop'] = 'NO_SWAP_CANDIDATE'
            break
        require(type(swap.get('source_address')) is int and type(swap.get('destination_address')) is int,
                'invalid swap candidate pointers')
        displacement = address - swap['destination_address']
        require(0 <= displacement < 4, 'swap destination does not cover watched byte')
        source = swap['source_address'] + displacement
        step['source_offset'] = source-frame
        step['swap_prefix_execution_proven'] = swap.get('executed_path_proven') is True
        first_pops = [r for r, a in rows if a == source and r['order'] < row['order'] and
                      any(c.get('rva') == swap['first_pop_rva'] and
                          c.get('effective_address') == swap['source_address'] for c in r['candidates'])]
        if not first_pops:
            result.update(stop='FIRST_POP_NOT_OBSERVED', next_offset=source-frame)
            break
        # Original source is read before this first POP overwrites its location.
        # This edge is conditional on the candidate prefix having executed.
        cutoff = max(r['order'] for r in first_pops)
        step['source_cutoff_order'] = cutoff
        address = source
    else:
        result['stop'] = 'SLICE_LIMIT'
    return result


def main():
    import json
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--input', type=Path, required=True)
    args = parser.parse_args()
    with open_regular(args.input) as handle:
        raw = handle.read(262145)
    require(len(raw) <= 262144, 'slice input size limit')
    print(json.dumps(candidate_slice(parse_json(raw)), indent=2))


if __name__ == '__main__':
    main()
