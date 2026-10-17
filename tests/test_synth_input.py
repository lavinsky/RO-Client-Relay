"""Offline input readiness and session cancellation; never touches the desktop."""
import threading
import unittest
from types import SimpleNamespace
import _boot
from relay.synth_input import KEYCODES, SynthActuator, build_actuator
from relay.runtime import Capture


class InputTests(unittest.TestCase):
    def test_keymap_repeated_and_interleaved(self):
        self.assertEqual((KEYCODES['9'], KEYCODES['INSERT'], KEYCODES['F2']), (10, 110, 60))
        sent, done = [], threading.Event()
        def sender(key, dry, hold):
            sent.append((key, dry, hold))
            if len(sent) == 4:
                done.set()
        act = SynthActuator({0x437:'INSERT',0x438:'9',0xaf4:'F2'}, wid='fixture',
                            focuser=lambda *a: None, sender=sender)
        for pid in (0x437,0x437,0x438,0xaf4):
            self.assertTrue(act.on_armed(pid))
        self.assertFalse(act.on_armed(0x35f))
        self.assertTrue(done.wait(1))
        self.assertEqual([s[0] for s in sent], ['INSERT','INSERT','9','F2'])
        self.assertTrue(all(s[2] == 120 for s in sent))

    def test_reset_during_focus_cancels_old_key_and_queue(self):
        entered, release, sent = threading.Event(), threading.Event(), []
        def focus(*a):
            entered.set()
            release.wait(1)
        act = SynthActuator({0x437:'INSERT'}, wid='fixture', focuser=focus,
                            sender=lambda *a: sent.append(a))
        act.on_armed(0x437, 0, 1)
        self.assertTrue(entered.wait(1))
        act.on_armed(0x437, 0, 2)
        act.reset(1, False)
        release.set()
        self.assertFalse(act.on_armed(0x437, 0, 3))
        self.assertTrue(act._q.empty())
        # New work gets a different key and a completion event, proving old work
        # has passed the focus barrier before assertions.
        done = threading.Event()
        act._focus = lambda *a: None
        act._send = lambda *a: (sent.append(a), done.set())[0]
        act.reset(2, True)
        act.on_armed(0x437, 2, 4)
        self.assertTrue(done.wait(1))
        self.assertEqual(len(sent), 1)

    def test_error_and_dry(self):
        done, errors = threading.Event(), []
        def fail(*a):
            raise RuntimeError('fixture')
        act = SynthActuator({0x438:'9'}, wid='fixture', dry=True,
                            focuser=fail, sender=lambda *a: None)
        act.on_error = lambda m: (errors.append(m), done.set())
        act.on_armed(0x438, 0, 5)
        self.assertTrue(done.wait(1))
        self.assertEqual((errors[0]['token'], errors[0]['hit']), (5,'error'))
        self.assertIsNone(build_actuator(SimpleNamespace(synth_input=False)))

    def test_same_epoch_map_reset_cancels_input_already_focusing(self):
        entered, release, finished = threading.Event(), threading.Event(), threading.Event()
        sent=[]
        def focus(*args):
            entered.set()
            release.wait(1)
        act=SynthActuator({0x437:'INSERT'},wid='fixture',focuser=focus,
                          sender=lambda *a:sent.append(a))
        act.on_finished=lambda m:finished.set()
        act.on_armed(0x437,0,1)
        self.assertTrue(entered.wait(1))
        act.reset(0,True)
        release.set()
        self.assertTrue(finished.wait(1))
        self.assertEqual(sent,[])

    def test_only_agent_ack_triggers_input(self):
        posted, armed = [], []
        capture = Capture.__new__(Capture)
        capture.post = posted.append
        capture.synth = SimpleNamespace(on_armed=lambda *args: armed.append(args))
        capture._on_inbound_scramble(bytes.fromhex('38040a001c0001020304'), 'S')
        self.assertEqual(armed, [])
        self.assertEqual(posted[0]['body'], '0a001c0001020304')
        capture._carrier_armed({'id':0x438,'epoch':4,'token':6})
        self.assertEqual(armed, [(0x438,4,6)])


if __name__ == '__main__':
    unittest.main()
