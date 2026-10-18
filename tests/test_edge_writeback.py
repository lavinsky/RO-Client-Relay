"""Writeback safety under malformed actions, lifecycle, and item-use barriers."""
import unittest
from types import SimpleNamespace
import _boot
from relay.writeback import WriteBack
from relay.protocol import sendcall_emit_msg, move_dispatch_msg, scramble_set_msg
from relay.packets import pack_move


class WB(WriteBack):
    def __init__(self, opts=None, synth=None):
        self.posted=[]
        self.opts=opts or SimpleNamespace(target_select=False, itemuse_input=False,
                                          move_dispatch=False,inject_call=True,
                                          action_merge=False, map_settle_ms=1500)
        self.synth=synth
        self.relay=object()
        self._scramble_armed=True
        self._last_select_gid=None
    def post(self,msg):self.posted.append(msg)


class FakeSynth:
    def __init__(self,err=None):
        self.keys=[]
        self.err=err
    def send_before_packet(self,key):
        self.keys.append(key)
        if self.err:
            raise self.err


class WritebackEdgeTests(unittest.TestCase):
    def test_itemuse_barrier_sends_key_before_packet(self):
        opts=SimpleNamespace(itemuse_input=True,itemuse_input_key='END',target_select=False)
        spy=FakeSynth();w=WB(opts,spy)
        w._on_inbound_sendcall(bytes.fromhex('3904010000000000'),'S')
        self.assertEqual(spy.keys,['END'])
        self.assertEqual(w.posted,[sendcall_emit_msg('3904010000000000')])

    def test_itemuse_without_synth_fails_closed(self):
        opts=SimpleNamespace(itemuse_input=True,itemuse_input_key='END',target_select=False)
        w=WB(opts,None)
        w._on_inbound_sendcall(bytes.fromhex('3904010000000000'),'S')
        self.assertEqual(w.posted,[])

    def test_itemuse_failed_input_never_emits_packet(self):
        opts=SimpleNamespace(itemuse_input=True,itemuse_input_key='END',target_select=False)
        spy=FakeSynth(RuntimeError('disconnected'))
        w=WB(opts,spy)
        w._on_inbound_sendcall(bytes.fromhex('3904010000000000'),'S')
        self.assertEqual(w.posted,[])
        self.assertEqual(spy.keys,['END'])

    def test_invalid_0439_length_must_not_trigger_any_input(self):
        opts=SimpleNamespace(itemuse_input=True,itemuse_input_key='END',target_select=False)
        spy=FakeSynth()
        for payload in (bytes.fromhex('3904'),bytes.fromhex('39040100'),
                        bytes.fromhex('390401000000000000')):
            w=WB(opts,spy)
            w._on_inbound_sendcall(payload,'S')
            self.assertEqual(w.posted,[],payload)
        self.assertEqual(spy.keys,[])

    def test_non_send_frames_do_not_inject(self):
        spy=FakeSynth()
        opts=SimpleNamespace(itemuse_input=True,itemuse_input_key='END',target_select=False)
        w=WB(opts,spy)
        for t in ('R','?',None):
            w._on_inbound_sendcall(bytes.fromhex('3904010000000000'),t)
        self.assertEqual(spy.keys,[])
        self.assertEqual(w.posted,[])

    def test_empty_packet_cannot_queue(self):
        w=WB()
        for payload in (b'',b'\x39'):
            w._on_inbound_sendcall(payload,'S')
            self.assertEqual(w.posted,[])

    def test_target_gid_bounds_and_zero(self):
        w=WB()
        self.assertIsNone(w._target_gid(0x437,b'\x37\x04'+bytes(5)))
        self.assertIsNone(w._target_gid(0x438,b'\x38\x04'+bytes(7)))
        self.assertEqual(w._target_gid(0x437,bytes.fromhex('37040102030407')),bytes.fromhex('01020304'))
        self.assertEqual(w._target_gid(0x438,bytes.fromhex('38040100020001020304')),bytes.fromhex('01020304'))

    def test_target_select_debounce_and_target_change(self):
        opts=SimpleNamespace(target_select=True,itemuse_input=False)
        w=WB(opts)
        a=bytes.fromhex('37040102030407')
        b=bytes.fromhex('37040403020107')
        w._on_inbound_sendcall(a,'S')
        self.assertEqual(len(w.posted),2)
        w.posted.clear()
        w._on_inbound_sendcall(a,'S')
        self.assertEqual(w.posted,[sendcall_emit_msg(a.hex())])
        w.posted.clear()
        w._on_inbound_sendcall(b,'S')
        self.assertEqual(len(w.posted),2)

    def test_map_boundary_recapture_only_for_0091_0092(self):
        opts=SimpleNamespace(inject_call=True,map_settle_ms=1500)
        w=WB(opts)
        for pid in (0x0087,0x09ff,0x0081):
            w.on_map_boundary('c',pid,0,b'')
        self.assertEqual(w.posted,[])
        for pid in (0x91,0x92):
            w.on_map_boundary('c',pid,0,b'')
        self.assertEqual(len(w.posted),2)
        self.assertTrue(all(x.get('recapture') and x.get('delayMs')==1500 for x in w.posted))

    def test_move_requests_refuse_short_and_non_send(self):
        opts=SimpleNamespace(move_dispatch=True,inject_call=True,action_merge=False,target_select=False)
        w=WB(opts)
        for payload in (b'\x5f\x03',b'\x5f\x03\x00\x01'):
            w._on_inbound_split(payload,'S')
        self.assertEqual(w.posted,[])
        w._on_inbound_split(b'\x5f\x03'+pack_move(0,1023,15),'R')
        self.assertEqual(w.posted,[])
        w._on_inbound_split(b'\x5f\x03'+pack_move(0,1023,15),'S')
        self.assertEqual(w.posted,[move_dispatch_msg(0,1023)])

    def test_merge_and_sendcall_routes_are_exclusive(self):
        action=bytes.fromhex('37040102030407')
        for merge,armed in ((True,True),(True,False),(False,True)):
            opts=SimpleNamespace(action_merge=merge,inject_call=True,
                                 move_dispatch=False,target_select=False,itemuse_input=False)
            w=WB(opts)
            w._scramble_armed=armed
            w._on_inbound_split(action,'S')
            expected=scramble_set_msg(0x437,action[2:].hex()) if merge and armed else sendcall_emit_msg(action.hex())
            self.assertEqual(w.posted,[expected])


if __name__=='__main__':
    unittest.main(verbosity=2)
