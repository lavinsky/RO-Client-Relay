"""Actuator failure, concurrency, debounce and input safety tests; no desktop input."""
import threading
import time
import unittest
from unittest.mock import patch

import _boot
from relay.synth_input import SynthActuator, send_key, focus, KEYCODES


class SyntheticActuatorTests(unittest.TestCase):
    def test_all_default_key_names_have_unique_keycodes(self):
        self.assertEqual(len(KEYCODES),30)
        self.assertEqual(len(set(KEYCODES.values())),30)
        self.assertEqual(KEYCODES['9'],10)
        for i in range(1,13):
            self.assertEqual(KEYCODES[f'F{i}'],58+i)

    def test_key_press_and_release_order_even_in_dry_mode(self):
        with patch('relay.synth_input._run', return_value=(0, '', '')) as run:
            send_key('9',True,hold_ms=0)
        self.assertEqual(run.call_count,2)
        self.assertEqual(run.call_args_list[0].args[0][-1],'10:1')
        self.assertEqual(run.call_args_list[1].args[0][-1],'10:0')

    def test_unknown_key_fails_closed(self):
        with patch('relay.synth_input._run', side_effect=AssertionError('must not send')):
            with self.assertRaises(ValueError):
                send_key('notakey',True)

    def test_failed_press_must_not_be_reported_successful(self):
        calls=[]
        def fake(cmd,dry,env=None):
            calls.append(cmd[-1])
            return (1,'','failure') if cmd[-1].endswith(':1') else (0,'','')
        with patch('relay.synth_input._run',side_effect=fake):
            ret=send_key('INSERT',True,hold_ms=0)
        self.assertNotEqual(ret,0)
        self.assertEqual(calls,['110:1','110:0'])

    def test_failed_release_is_failure(self):
        with patch('relay.synth_input._run',side_effect=[(0,'',''),(1,'','error')]):
            self.assertEqual(send_key('END',True,0),1)

    def test_failed_window_focus_must_not_dispatch_seat0(self):
        with patch('relay.synth_input._run',return_value=(1,'','window unavailable')):
            with self.assertRaises(RuntimeError):
                focus('0xDEAD',False)

    def test_sync_barrier_success(self):
        order=[]
        act=SynthActuator({0x437:'INSERT'},wid='0x123',focuser=lambda wid,dry: order.append(('focus',wid)),
                          sender=lambda key,dry,hold:(order.append(('send',key)),0)[-1],
                          hold_ms=0)
        act.send_before_packet('END')
        self.assertEqual(order,[('focus','0x123'),('send','END')])

    def test_sync_barrier_no_window(self):
        act=SynthActuator({},wid=None,focuser=lambda *_:None,
                          sender=lambda *_:self.fail('unexpected key'))
        with patch('relay.synth_input.find_wid',return_value=None):
            with self.assertRaises(RuntimeError):
                act.send_before_packet('END')

    def test_sync_barrier_propagates_sender_failure(self):
        act=SynthActuator({},wid='0x44',focuser=lambda *_:None,
                          sender=lambda *_:2)
        with self.assertRaisesRegex(RuntimeError,'exit 2'):
            act.send_before_packet('END')

    def test_initial_window_missing_must_retry_after_appearance(self):
        act=SynthActuator({},focuser=lambda *_:None,sender=lambda *_:0)
        with patch('relay.synth_input.find_wid',side_effect=[None,'0x4455']) as finder:
            self.assertIsNone(act._resolve_wid())
            self.assertEqual(act._resolve_wid(),'0x4455')
            self.assertEqual(finder.call_count,2)

    def test_same_packet_debounce_other_packet_not_suppressed(self):
        act=SynthActuator({0x437:'INSERT',0x438:'9'},wid='0x42',
                          debounce_ms=100)
        act._started=True
        with patch('relay.synth_input.time.monotonic',side_effect=[100,100.001,100.002,100.2]):
            act.on_armed(0x437)
            act.on_armed(0x437)
            act.on_armed(0x438)
            act.on_armed(0x437)
        self.assertEqual(list(act._q.queue),[(0x437,'INSERT'),(0x438,'9'),(0x437,'INSERT')])

    def test_worker_rejects_nonzero_sender_exit(self):
        sent=threading.Event()
        results=[]
        def sender(key,dry,hold):
            sent.set()
            return 3
        act=SynthActuator({0x437:'INSERT'},wid='0x44',focuser=lambda *_:None,
                          sender=sender,debounce_ms=0)
        with patch('builtins.print') as logger:
            act.on_armed(0x437)
            self.assertTrue(sent.wait(timeout=1))
            # flush deterministic: worker may still be logging
            end=time.monotonic()+1
            while time.monotonic()<end and not any('error' in str(c) or 'erro' in str(c) for c in logger.call_args_list):
                time.sleep(0.005)
            self.assertTrue(any('erro' in str(c) for c in logger.call_args_list))


if __name__=='__main__':
    unittest.main(verbosity=2)
