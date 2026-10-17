"""Client readiness, event ordering, bounds and cancellation without timers."""
import ast
from pathlib import Path
import threading
import unittest
import _boot
from relay.client_dispatch import CommandPipeline


class PipelineTests(unittest.TestCase):
    def make(self):
        dispatched, events, resets, armed = [], [], [], []
        clock = iter(range(0,1000000000,1000)).__next__
        p = CommandPipeline(lambda c: dispatched.append(dict(c)), lambda *a:resets.append(a),
                            events.append, armed.append, clock)
        p.session(True)
        return p,dispatched,events,resets,armed

    def ack(self,p,tag='SCRAMBLE',hit='consumed'):
        c=p.current
        return p.observe(dict(tag=tag,hit=hit,token=c['token'],epoch=c['epoch']))

    def test_burst_same_opcode_and_interleaved(self):
        p,d,events,resets,armed=self.make()
        frames=[bytes.fromhex(x) for x in ('37040102030407','37040506070807','38040a001c0001020304',
                                          '5f03010203','f40a0a001c000102030400')]
        for payload in frames:
            self.assertTrue(p.accept(payload,'S'))
        self.assertEqual(len(d),1)
        self.ack(p,hit='armed')
        self.assertEqual(len(d),1)
        self.assertEqual(len(armed),1)
        self.ack(p);self.ack(p);self.ack(p)
        self.ack(p,tag='MOVE-DISPATCH',hit='dispatched')
        self.ack(p)
        self.assertEqual([c['payload'] for c in d],frames)
        self.assertEqual(len(p.pending),0)
        self.assertIsNone(p.current)
        self.assertEqual(p.summary()['local_completion_ms']['n'],5)

    def test_disconnect_old_events_and_new_session(self):
        p,d,events,resets,armed=self.make()
        p.accept(b'\x37\x04fixture','S')
        p.accept(b'\x38\x04fixture','S')
        old=dict(tag='SCRAMBLE',hit='consumed',token=p.current['token'],epoch=p.epoch)
        p.session(False)
        self.assertIsNone(p.accept(b'\x37\x04fixture','S'))
        p.session(True)
        p.accept(b'\x37\x04new','S')
        self.assertFalse(p.observe(old))
        self.assertEqual(p.current['payload'],b'\x37\x04new')
        self.assertEqual(len(d),2)
        self.assertEqual(resets,[(1,True),(2,False),(3,True)])

    def test_capacity_and_explicit_native_error(self):
        p,d,events,resets,armed=self.make()
        for _ in range(p.CAPACITY):
            self.assertTrue(p.accept(b'\x37\x04fixture','S'))
        self.assertFalse(p.accept(b'\x37\x04overflow','S'))
        self.assertEqual(events[-1]['hit'],'error')
        self.ack(p,hit='error')
        self.assertEqual(len(d),2)
        self.assertEqual(len(p.pending),p.CAPACITY-2)

    def test_capacity_rejection_is_distinguishable_from_disconnect(self):
        p,*_=self.make()
        for _ in range(p.CAPACITY):
            p.accept(b'\x37\x04fixture','S')
        self.assertIs(p.accept(b'\x37\x04overflow','S'), False)  # transport must pause, retain frame
        p.session(False)
        self.assertIsNone(p.accept(b'\x37\x04old-session','S'))  # disconnect must drop, never retain

    def test_next_body_waits_for_native_consumption_and_key_release(self):
        for release_first in (False,True):
            p,d,*_=self.make()
            p.armed=lambda m: True
            p.accept(b'\x37\x04first','S')
            p.accept(b'\x37\x04second','S')
            self.ack(p,hit='armed')
            first=p.current.copy()
            release=dict(tag='INPUT',hit='released',epoch=p.epoch,token=first['token'])
            if release_first:
                p.observe(release)
                self.assertEqual(len(d),1)
                self.ack(p)
            else:
                self.ack(p)
                self.assertEqual(len(d),1)
                p.observe(release)
            self.assertEqual(len(d),2)

    def test_missing_carrier_identifies_blocker_without_claiming_completion(self):
        p,d,events,*_=self.make()
        p.armed=lambda m: True
        p.accept(bytes.fromhex('37040102030407'),'S')
        self.ack(p,hit='armed')
        self.ack(p,tag='INPUT',hit='released')
        waiting=events[-1]
        self.assertEqual(waiting['code'],'COMMAND_CARRIER_PENDING')
        self.assertEqual(waiting['blocked_id'],0x0437)
        self.assertEqual(waiting['blocked_stage'],'carrier')
        # Neither input release nor missing carrier proves that a packet was sent.
        self.assertEqual(p.summary().get('local_completion_ms',{}),{})
        following=[bytes.fromhex(s) for s in ('5f03010203','38040a001c0001020304')]
        for i in range(p.CAPACITY-1):
            self.assertTrue(p.accept(following[i%2],'S'))
        self.assertFalse(p.accept(following[0],'S'))
        error=events[-1]
        self.assertEqual(error['code'],'COMMAND_CAPACITY')
        self.assertEqual(error['id'],0x035f)
        self.assertEqual(error['blocked_id'],0x0437)
        self.assertEqual(error['blocked_token'],p.current['token'])
        self.assertEqual(error['pending'],p.CAPACITY-1)
        self.assertGreaterEqual(error['blocked_ms'],0)
        self.assertEqual(len(d),1)
        self.assertNotIn('payload',error)
        # An explicit native cancellation, unlike silence, can release readiness.
        self.ack(p,hit='cancelled')
        self.assertEqual(d[1]['payload'],following[0])
        p.session(False)
        self.assertIsNone(p.current)
        self.assertFalse(p.pending)

    def test_dispatch_exception_does_not_log_private_exception_text(self):
        p,d,events,*_=self.make()
        def fail(c):
            raise RuntimeError('private credential fixture')
        p.dispatch=fail
        p.accept(bytes.fromhex('5f03010203'),'S')
        self.assertEqual(events[-1]['code'],'COMMAND_DISPATCH_FAILED')
        self.assertEqual(events[-1]['e'],'RuntimeError')
        self.assertNotIn('private',str(events))
        self.assertIsNone(p.current)

    def test_no_hidden_clock_release_or_age_drop(self):
        tree=ast.parse(Path('relay/client_dispatch.py').read_text())
        self.assertFalse(any(isinstance(n,ast.Attribute) and n.attr in ('sleep','Timer') for n in ast.walk(tree)))
        p,d,*_=self.make()
        for _ in range(50):p.accept(b'\x37\x04x','S')
        for _ in range(50):self.ack(p)
        self.assertEqual(len(d),50)

    def test_concurrent_ack_and_disconnect_finishes(self):
        p,d,*_=self.make()
        p.accept(b'\x37\x04x','S')
        c=p.current.copy()
        barrier=threading.Barrier(3)
        def ack():
            barrier.wait()
            p.observe(dict(tag='SCRAMBLE',hit='consumed',token=c['token'],epoch=c['epoch']))
        def reset():barrier.wait();p.session(False)
        threads=[threading.Thread(target=ack),threading.Thread(target=reset)]
        for t in threads:t.start()
        barrier.wait()
        for t in threads:t.join(1);self.assertFalse(t.is_alive())
        self.assertFalse(p.active)
        self.assertIsNone(p.current)


if __name__=='__main__':unittest.main()
