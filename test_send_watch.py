"""Offline test for SendWatch (--send-watch): recovers 0437/0438 plaintext from the real watchpoint
windows of the live relay_sendbp.py --queue run (sendbp_queue.jsonl), passes cleartext sends through
unchanged, and drops 035f walks, unarmed sends and implausible plaintext instead of feeding ciphertext."""
import importlib.util, json, os
HERE = os.path.dirname(os.path.abspath(__file__))
sp = importlib.util.spec_from_file_location('g', os.path.join(HERE, 'relay_capture_linux.py'))
g = importlib.util.module_from_spec(sp); sp.loader.exec_module(g)

sw = g.SendWatch()
got = []
for line in open(os.path.join(HERE, 'sendbp_queue.jsonl')):
    r = json.loads(line)
    if r.get('tag') != 'SEND' or r['id'] not in (0x0437, 0x0438) or not r.get('win'):
        continue
    m = {'C': r['C'], 'buf': r['buf']}                    # what the agent's SEND carries
    W = {'base': r['win']['base'], 'n': r['win']['n'],
         'hits': [{'pc': h['pc'], 'win': h['win']} for h in r['win']['hits']]}
    Q = sw.resolve(m, bytes.fromhex(r['C']), W)
    got.append(Q and Q.hex())
    assert m.get('tag') == 'SEND-PLAIN' and m['P'] == Q.hex(), m
print('live windows ->', got)
assert got == ['37040000000002',                           # sit
               '37040000000003',                           # stand
               '3704d935960607',                           # attack 0x069635d9, action 7
               '38040a000d00d9359606'], got                # lv 10 Soul Strike (13) on it

clear = bytes.fromhex('6003d8b3c103')                      # 0360 tick: not an encrypted id
assert sw.resolve({'C': clear.hex()}, clear, None) == clear
walk = bytes.fromhex('5f03bec3fd')
assert sw.resolve({'C': walk.hex()}, walk, None) is None   # 035f dropped
act = bytes.fromhex('3704bebbfaab29')
assert sw.resolve({'C': act.hex(), 'buf': '0x24e602f2'}, act, None) is None   # slot not armed
assert sw.resolve({'C': act.hex() + '00'}, act + b'\0', {'hits': []}) is None # not one whole packet
bad = {'base': '0x24e602f0', 'n': 3, 'hits': [                                 # action 0x99: implausible
    {'pc': '0x1', 'win': '00003704000000009900000000000000'},
    {'pc': '0x2', 'win': '000037041111111111000000000000000'[:32]},
    {'pc': '0x2', 'win': '0000370422222222220000000000000000'[:32]}]}
m = {'C': '370422222222220000', 'buf': '0x24e602f2'}
assert sw.resolve(m, bytes.fromhex('37042222222222'), bad) is None
print('stats:', dict(sw.stats))
assert sw.stats['ok-0437'] == 3 and sw.stats['ok-0438'] == 1 and sw.stats['drop-035f'] == 1
assert sw.stats['nowin-0437'] == 1 and sw.stats['multi-0437'] == 1 and sw.stats['implausible-0437'] == 1

# --send-queue: 'auto' follows the recv ring ActorDecrypt found; explicit overrides; fallback without it
q = g.send_queue_range
assert q('auto', (0x24dd0000, 0x24f80000)) == (0x24dd0000, 0x24f80000, 'recv ring block')
assert q('auto', (0x31000000, 0x311b0000)) == (0x31000000, 0x311b0000, 'recv ring block')   # moved block
assert q('auto', (None, None)) is None                       # ring not found yet: wait, don't guess
assert q('auto', None, have_dec=False)[:2] == g.SEND_QUEUE_FALLBACK
assert q('12340000-12350000', (0x24dd0000, 0x24f80000)) == (0x12340000, 0x12350000, '--send-queue')
print('send_queue_range ok')
print('ALL PASS')
