"""Unbuffered ordered send admission, native completion and cancellation (offline)."""
import ast
from pathlib import Path
import threading
import unittest
import _boot
from relay.client_dispatch import CommandPipeline


class PipelineTests(unittest.TestCase):
    def make(self):
        dispatched, events, resets, armed = [], [], [], []
        clock = iter(range(0, 1000000000, 1000)).__next__
        p = CommandPipeline(lambda c: (dispatched.append(dict(c)), True)[1],
                            lambda *a: resets.append(a), events.append, armed.append, clock)
        p.session(True)
        return p, dispatched, events, resets, armed

    def ack(self, p, tag='SCRAMBLE', hit='consumed'):
        c = p.current
        return p.observe(dict(tag=tag, hit=hit, token=c['token'], epoch=c['epoch']))

    def test_burst_same_opcode_and_interleaved_are_admitted_in_order(self):
        p, d, events, resets, armed = self.make()
        frames = [bytes.fromhex(x) for x in (
            '37040102030407', '37040506070807', '38040a001c0001020304',
            '5f03010203', 'f40a0a001c000102030400')]
        for i, payload in enumerate(frames):
            self.assertTrue(p.accept(payload, 'S'))
            self.assertEqual(len(d), i + 1)  # no dispatch sleeps or pacing
            if i + 1 < len(frames):
                self.assertIs(p.accept(frames[i+1], 'S'), False)
                self.assertEqual(len(d), i + 1)
            self.ack(p, tag='MOVE-DISPATCH' if i == 3 else 'SCRAMBLE',
                     hit='dispatched' if i == 3 else 'consumed')
        self.assertEqual([c['payload'] for c in d], frames)
        self.assertIsNone(p.current)
        self.assertFalse(hasattr(p, 'pending'))  # no application-level command backlog
        self.assertEqual(p.summary()['local_completion_ms']['n'], 5)

    def test_disconnect_drops_only_native_work_and_rejects_stale_ack(self):
        p, d, events, resets, armed = self.make()
        self.assertTrue(p.accept(b'\\x37\\x04first', 'S'))
        self.assertFalse(p.accept(b'\\x38\\x04later', 'S'))
        old = dict(tag='SCRAMBLE', hit='consumed', token=p.current['token'], epoch=p.epoch)
        p.session(False)
        self.assertIsNone(p.accept(b'\\x37\\x04old-session', 'S'))
        p.session(True)
        self.assertTrue(p.accept(b'\\x37\\x04new', 'S'))
        self.assertFalse(p.observe(old))
        self.assertEqual(p.current['payload'], b'\\x37\\x04new')
        self.assertEqual(len(d), 2)
        self.assertEqual(resets, [(1, True), (2, False), (3, True)])

    def test_busy_retains_command_in_transport_not_python_pipeline(self):
        p, d, events, *_ = self.make()
        self.assertTrue(p.accept(b'\\x37\\x04first', 'S'))
        old_serial = p.serial
        self.assertIs(p.accept(b'\\x37\\x04second', 'S'), False)
        self.assertEqual(p.serial, old_serial)
        self.assertEqual(events[-1]['code'], 'COMMAND_BUSY')
        self.assertTrue(events[-1]['in_flight'])
        self.assertEqual(events[-1]['blocked_token'], p.current['token'])
        self.ack(p, hit='error')
        self.assertIsNone(p.current)
        self.assertTrue(p.accept(b'\\x37\\x04second', 'S'))
        self.assertEqual([c['payload'] for c in d], [b'\\x37\\x04first', b'\\x37\\x04second'])

    def test_busy_is_not_a_disconnected_drop(self):
        p, *_ = self.make()
        self.assertTrue(p.accept(b'\\x37\\x04first', 'S'))
        self.assertIs(p.accept(b'\\x37\\x04second', 'S'), False)
        p.session(False)
        self.assertIsNone(p.accept(b'\\x37\\x04second', 'S'))

    def test_key_release_and_native_consumption_must_both_complete(self):
        for release_first in (False, True):
            p, d, *_ = self.make()
            p.armed = lambda m: True
            self.assertTrue(p.accept(b'\\x37\\x04first', 'S'))
            self.ack(p, hit='armed')
            first = p.current.copy()
            release = dict(tag='INPUT', hit='released', epoch=p.epoch, token=first['token'])
            if release_first:
                p.observe(release)
                self.assertIs(p.accept(b'\\x37\\x04second', 'S'), False)
                self.ack(p)
            else:
                self.ack(p)
                self.assertIs(p.accept(b'\\x37\\x04second', 'S'), False)
                p.observe(release)
            self.assertIsNone(p.current)
            self.assertTrue(p.accept(b'\\x37\\x04second', 'S'))
            self.assertEqual(len(d), 2)

    def test_missing_carrier_pauses_only_tx_and_does_not_claim_success(self):
        p, d, events, *_ = self.make()
        p.armed = lambda m: True
        self.assertTrue(p.accept(bytes.fromhex('37040102030407'), 'S'))
        self.ack(p, hit='armed')
        self.ack(p, tag='INPUT', hit='released')
        waiting = events[-1]
        self.assertEqual(waiting['code'], 'COMMAND_CARRIER_PENDING')
        self.assertEqual(waiting['blocked_id'], 0x0437)
        self.assertEqual(waiting['blocked_stage'], 'carrier')
        self.assertEqual(p.summary().get('local_completion_ms', {}), {})
        next_frame = bytes.fromhex('5f03010203')
        self.assertIs(p.accept(next_frame, 'S'), False)
        self.assertEqual(events[-1]['code'], 'COMMAND_BUSY')
        self.assertEqual(len(d), 1)
        self.ack(p, hit='cancelled')
        self.assertEqual(len(d), 1)  # no speculative dispatch of a frame still held by TCP
        self.assertTrue(p.accept(next_frame, 'S'))
        self.assertEqual(len(d), 2)
        p.session(False)
        self.assertIsNone(p.current)

    def test_dispatch_exception_does_not_log_sensitive_message(self):
        p, d, events, *_ = self.make()
        def fail(_):
            raise RuntimeError('private credential fixture')
        p.dispatch = fail
        p.accept(bytes.fromhex('5f03010203'), 'S')
        self.assertEqual(events[-1]['code'], 'COMMAND_DISPATCH_FAILED')
        self.assertEqual(events[-1]['e'], 'RuntimeError')
        self.assertNotIn('private', str(events))
        self.assertIsNone(p.current)

    def test_no_clock_pacing_and_serial_admission(self):
        tree = ast.parse(Path('relay/client_dispatch.py').read_text())
        self.assertFalse(any(isinstance(n, ast.Attribute) and n.attr in ('sleep', 'Timer')
                             for n in ast.walk(tree)))
        p, d, *_ = self.make()
        for _ in range(50):
            self.assertTrue(p.accept(b'\\x37\\x04x', 'S'))
            self.ack(p)
        self.assertEqual(len(d), 50)
        self.assertFalse(hasattr(p, 'pending'))

    def test_concurrent_ack_and_disconnect_finishes(self):
        p, d, *_ = self.make()
        p.accept(b'\\x37\\x04x', 'S')
        c = p.current.copy()
        barrier = threading.Barrier(3)
        def ack():
            barrier.wait()
            p.observe(dict(tag='SCRAMBLE', hit='consumed', token=c['token'], epoch=c['epoch']))
        def reset():
            barrier.wait()
            p.session(False)
        threads = [threading.Thread(target=ack), threading.Thread(target=reset)]
        for t in threads:
            t.start()
        barrier.wait()
        for t in threads:
            t.join(1)
            self.assertFalse(t.is_alive())
        self.assertFalse(p.active)
        self.assertIsNone(p.current)


if __name__ == '__main__':
    unittest.main()
