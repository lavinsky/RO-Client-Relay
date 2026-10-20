"""Pure offline tests for write-to-candidate attribution."""
from audit_write_trace import audit


def test_exact_write_bytes_are_consistent_not_proof():
    records = [
        dict(kind='ring_candidate', candidate_id=1, recv_seq=20, fd=9,
             slot_offset=64, length=4, packet_id='09ff'),
        dict(kind='ring_match', candidate_id=1, plaintext='11223344'),
        dict(kind='write_trace_batch', events=[
            dict(recv_seq_hint=20, fd_hint=9, offset=64+i, byte=v)
            for i, v in enumerate((0x11, 0x22, 0x33, 0x44))]),
    ]
    result = audit(records)
    assert result['classification'] == {'write_bytes_consistent_not_proven': 1}
    records[-1]['events'][2]['byte'] = 0xff
    result = audit(records)
    assert result['classification'] == {'write_transient_or_mismatch': 1}


def test_overlap_remains_ambiguous():
    records = [
        dict(kind='ring_candidate', candidate_id=1, recv_seq=20, fd=9,
             slot_offset=64, length=4, packet_id='09ff'),
        dict(kind='ring_candidate', candidate_id=2, recv_seq=20, fd=9,
             slot_offset=66, length=4, packet_id='09fd'),
        dict(kind='ring_match', candidate_id=1, plaintext='11223344'),
        dict(kind='ring_match', candidate_id=2, plaintext='33445566'),
        dict(kind='write_trace_batch', events=[
            dict(recv_seq_hint=20, fd_hint=9, offset=66, byte=0x33)])]
    assert audit(records)['classification'] == {'ambiguous_slot_overlap': 2}


if __name__ == '__main__':
    test_exact_write_bytes_are_consistent_not_proof()
    test_overlap_remains_ambiguous()
    print('write-trace attribution offline tests: PASS')
