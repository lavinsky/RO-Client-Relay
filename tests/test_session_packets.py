"""Synthetic boundaries/privacy tests for the passive login inventory; no client or Frida."""
import _boot
from research.cipher.session_packets import PacketInventory, instrument_source, window_reason, ROOT

L = {0x4754: -1, 0x5395: -1, 0xc392: -1, 0x02eb: 13, 0x006b: -1, 0x007d: 2, 0x00b2: 3}
control = b'\x54\x47\x08\x00TEST'
position = b'\xeb\x02' + bytes(11)
for chunks in ([control + position], [bytes([b]) for b in control + position]):
    records = []
    inv = PacketInventory(L, lambda k, v: records.append((k, v)))
    for seq, chunk in enumerate(chunks):
        inv.push(dict(tag='RECV', sock='127.0.0.1:5121', conn=123,
                      ts=1000 + seq, seq=seq, C=chunk.hex()))
    packets = [v for k, v in records if k == 'packet']
    assert [p['id'] for p in packets] == ['4754', '02eb']
    assert [p['offset'] for p in packets] == [0, 8]
    assert packets[0]['ts'] == 1000
    assert inv.map_accept_ts == 1000 + len(chunks) - 1
    assert inv.map_ts is None
    assert inv.summary()['pending_bytes'] == 0
    assert all('hex' not in v for k, v in records if k == 'packet')
    assert [v['hex'] for k, v in records if k == 'control'] == [control.hex()]
    inv.push(dict(tag='SEND', sock='127.0.0.1:5121', conn=123, ts=1500, seq=90, C='7d00'))
    assert inv.map_ts == 1500

# Both directions preserve one TCP identity; HTTP data is never retained.
inv.push(dict(tag='SEND', sock='127.0.0.1:5121', conn=123, ts=2000, seq=100,
              C=b'\x92\xc3\x08\x00TEST'.hex()))
assert records[-1][1]['connection'] == packets[0]['connection']
before = len(records)
inv.push(dict(tag='RECV', sock='127.0.0.1:3000', conn=456, ts=2001, seq=101,
              C=b'HTTP/1.1 200 OK private_token'.hex()))
assert len(records) == before

# An AID preamble is counted, not logged. Unknown traffic halts with explicit lost coverage.
inv.push(dict(tag='RECV', sock='127.0.0.1:6121', conn=789, ts=3000, seq=102,
              C=(b'\x11\x22\x33\x44\x6b\x00\x08\x00ABCD').hex()))
assert inv.counts['account_preamble_bytes'] == 4
assert records[-1][1]['id'] == '006b'
assert 'hex' not in records[-1][1]
inv.push(dict(tag='RECV', sock='127.0.0.1:5121', conn=123, ts=3001, seq=103, C='ffffabcd'))
assert inv.summary()['halted_streams'] == 1
assert inv.counts['unparsed_bytes'] == 4
# Closing a TCP socket creates a new identity if its local port/peer is reused.
inv.close(dict(conn=123, sock='127.0.0.1:5121', ts=3500))
inv.push(dict(tag='RECV', sock='127.0.0.1:5121', conn=123, ts=4000, seq=104, C=position.hex()))
assert records[-1][1]['connection'] != packets[0]['connection']
assert records[-1][1]['offset'] == 0
inv.push(dict(tag='RECV', sock='127.0.0.1:5121', conn=123, ts=4001, seq=105, C='eb02'))
inv.close(dict(conn=123, sock='127.0.0.1:5121', ts=4500))
assert inv.counts['closed_partial_bytes'] == 2
assert inv.map_ts is None and inv.interrupted_windows[0]['reason'] == 'map_socket_closed'
inv.push(dict(tag='RECV', sock='127.0.0.1:5121', conn=123, ts=5000, seq=106, C=position.hex()))
inv.push(dict(tag='SEND', sock='127.0.0.1:5121', conn=123, ts=5001, seq=107, C='7d00'))
inv.push(dict(tag='SEND', sock='127.0.0.1:5121', conn=123, ts=8001, seq=108, C='b20000'))
assert inv.map_ts is None and inv.interrupted_windows[-1]['reason'] == 'restart_request'
assert window_reason(None, 10, 1000) == 'timeout_before_map'
assert window_reason(None, 10, 1000, had_interruption=True) == 'timeout_after_map_interrupt'
assert window_reason(1000, 10, 10.999) == 'timeout_during_map'
assert window_reason(1000, 10, 11) == 'map_window_complete'
source = (ROOT / 'agent/relay_hook_linux.js').read_text()
adapted = instrument_source(source)
assert 'callers: controlCallers(callCtx, h)' in adapted
assert 'callers: controlCallers(this.context, h)' in adapted
try:
    instrument_source('changed agent')
    raise AssertionError('adapter must reject an unknown agent layout')
except ValueError:
    pass
print('session inventory boundaries, privacy, coverage and source adapter PASS')
