#!/usr/bin/env python3
"""Read-only write correlation audit; never upgrades candidates to verified."""
import collections
import json
import sys


def audit(records):
    candidates = {r['candidate_id']: r for r in records if r.get('kind') == 'ring_candidate'}
    results = {r['candidate_id']: bytes.fromhex(r['plaintext']) for r in records
               if r.get('kind') in ('ring_match', 'ring_snapshot_match', 'ring_replay_match')}
    writes = [w for r in records if r.get('kind') == 'write_trace_batch' for w in r['events']]
    classes = collections.Counter()
    samples = []
    for cid, c in candidates.items():
        if cid not in results:
            classes['unrecovered'] += 1
            continue
        data = results[cid]
        lo, hi = c['slot_offset'], c['slot_offset'] + c['length']
        same = [w for w in writes if w['recv_seq_hint'] == c.get('recv_seq')
                and w['fd_hint'] == c['fd'] and lo <= w['offset'] < hi]
        other_candidates = [k for k, d in candidates.items() if k != cid
                            and d.get('recv_seq') == c.get('recv_seq') and d['fd'] == c['fd']
                            and max(lo, d['slot_offset']) < min(hi, d['slot_offset'] + d['length'])]
        equal = sum(w['byte'] == data[w['offset'] - lo] for w in same)
        mismatch = len(same) - equal
        if other_candidates:
            status = 'ambiguous_slot_overlap'
        elif not same:
            status = 'no_write_in_recv_window'
        elif mismatch:
            status = 'write_transient_or_mismatch'
        else:
            status = 'write_bytes_consistent_not_proven'
        classes[status] += 1
        if len(samples) < 15:
            samples.append({'candidate_id':cid,'packet_id':c['packet_id'],
                            'recv_seq':c['recv_seq'],'writes_in_slot':len(same),
                            'bytes_matching_final':equal,'transient_bytes':mismatch,
                            'classification':status})
    return {'candidates':len(candidates),'recovered':len(results),
            'writer_events':len(writes),'classification':dict(classes),
            'examples':samples,
            'note':'Matching address, thread and bytes is not sufficient to prove unique reception provenance.'}

if __name__ == '__main__':
    with open(sys.argv[1]) as f:
        data=[json.loads(l) for l in f if l.strip()]
    print(json.dumps(audit(data),indent=2))
