"""Offline routing contract: bytes, generic fallback, duplicate policy, no pacing."""
import threading
import unittest
from types import SimpleNamespace
import _boot
from relay.runtime import Capture
from relay.packets import pack_move
from relay.protocol import scramble_set_msg, sendcall_msg


class Routes(unittest.TestCase):
    def make_capture(self):
        c = Capture.__new__(Capture)
        c.opts = SimpleNamespace(move_dispatch=True, inject_call=True, action_merge=True)
        c._scramble_armed = True
        c.posted = []
        c.post = c.posted.append
        return c

    def test_actions_exact_bytes_and_movement(self):
        c = self.make_capture()
        packets = [bytes.fromhex(p) for p in ('37040102030407','37040506070807',
            '38040a001c0001020304','f40a0a001c009600bb0000')]
        for p in packets:
            c._on_inbound_split(p, 'S')
        self.assertEqual(c.posted, [scramble_set_msg(int.from_bytes(p[:2],'little'),p[2:].hex())
                                    for p in packets])
        c.posted.clear()
        c._on_inbound_split(b'\x5f\x03' + pack_move(150,187), 'S')
        self.assertEqual(c.posted[0]['args'], {'x':150,'y':187})

    def test_generic_and_duplicate_policy(self):
        c = self.make_capture()
        p = bytes.fromhex('efbe001122334455')
        c._on_inbound_split(p, 'S')
        self.assertEqual(c.posted, [{'type':'sendcall-emit','data':p.hex()}])
        for pid in c.SKIP_IDS:
            c._on_inbound_split(pid.to_bytes(2,'little')+b'fixture', 'S')
        c._on_inbound_split(p, 'R')
        self.assertEqual(len(c.posted), 1)
        self.assertEqual(sendcall_msg(0x816640), {'type':'sendcall','rva':0x816640,'module':'uaRO.exe'})

    def test_invalid_walk_and_no_route(self):
        c = self.make_capture()
        c._on_inbound_split(b'\x5f\x03x','S')
        c.opts.inject_call = False
        c._on_inbound_split(b'\xef\xbe12','S')
        self.assertEqual(c.posted, [])

    def test_discovery_preserves_store_anchor(self):
        c = self.make_capture()
        c._disc_lock = threading.Lock()
        c._scramble_armed = False
        c.opts = SimpleNamespace(scramble_id='035f', scramble_range='1000-2000')
        c.gepard_base = 0x10000000
        c._autodiscover_scramble({'enc':'1018eff4','enc_off':'0x18eff4'})
        self.assertEqual(c.scramble['off'], 0x18eff2)
        self.assertTrue(c._scramble_armed)


if __name__ == '__main__':
    unittest.main()
