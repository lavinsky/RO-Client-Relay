"""Offline integration of session callbacks, routing and stale receive evidence."""
import threading
from collections import deque
import unittest
from unittest.mock import Mock, patch
import _boot
from relay.cli import parse_args
from relay.capture_runtime import Capture
from relay.xkore_transport import Relay
from relay.packet_pipeline import WireFilter
from relay.packet_pipeline import new_chunk


class Sessions(unittest.TestCase):
    def make(self):
        a = parse_args(['--config','/missing/offline.ini','--inject','--inject-call',
                        '--move-dispatch','--action-merge','--scramble-bp','18eff2',
                        '--scramble-reg','auto','--no-decrypt-actors','--no-synth-input'])
        relay=Relay('offline',0,autostart=False)
        log=Mock()
        posted=[]
        wire=WireFilter({1:4},set())
        capture=Capture(a,None,relay,wire,log,posted.append)
        def connect():
            with patch('relay.xkore_transport.socket.create_connection',return_value=Mock()):relay._connect()
        connect()
        return capture,relay,wire,posted,connect

    def test_dispatch_metadata_is_explicit_and_control_posts_are_unbound(self):
        c,r,w,posted,connect=self.make()
        self.assertIsNotNone(c.client_dispatch)
        c.commands.accept(bytes.fromhex('37040102030407'), 'S')
        current=c.commands.current
        self.assertEqual((posted[-1]['epoch'],posted[-1]['token']),
                         (current['epoch'],current['token']))
        c.post({'type':'trace','fixture':True})
        self.assertNotIn('epoch',posted[-1])
        self.assertNotIn('token',posted[-1])
        self.assertFalse(hasattr(c, '_context'))

    def test_reconnect_cancels_commands_and_partial_receive(self):
        c,r,w,posted,connect=self.make()
        r._inbound(r.frame(bytes.fromhex('37040102030407'),'S'),r.sock)
        old=c.commands.current.copy()
        self.assertEqual(posted[-1]['epoch'],c.commands.epoch)
        c.dispatch(dict(tag='RECV',epoch=c.commands.epoch,sock='fixture:5121',conn='one',
                        C='0100',len=2,ts=10))
        self.assertTrue(w.conns['one']['buf'])
        r._drop_sock(r.sock)
        self.assertFalse(c.commands.active)
        self.assertEqual(w.conns,{})
        connect()
        r._inbound(r.frame(bytes.fromhex('38040a001c0001020304'),'S'),r.sock)
        token=c.commands.current['token']
        c.dispatch(dict(tag='SCRAMBLE',hit='consumed',epoch=old['epoch'],token=old['token']))
        self.assertEqual(c.commands.current['token'],token)
        self.assertEqual(posted[-1]['body'],'0a001c0001020304')

    def test_new_map_connection_invalidates_native_context(self):
        c,r,w,posted,connect=self.make()
        for conn in ('one','two'):
            c.dispatch(dict(tag='RECV',epoch=c.commands.epoch,sock='fixture:5121',conn=conn,
                            C='01000102',len=4,ts=10))
        self.assertEqual(c.commands.epoch,1)
        self.assertEqual(set(w.conns),{'two'})
        self.assertTrue(any(m['type']=='session-reset' and m.get('min_token')==1 for m in posted))

    def test_cancelled_synthetic_carrier_clears_agent_body(self):
        c,r,w,posted,connect=self.make()
        r._inbound(r.frame(bytes.fromhex('37040102030407'),'S'),r.sock)
        command=c.commands.current
        c.client_dispatch._carrier_failed(dict(tag='SCRAMBLE',hit='error',id=0x437,
                               epoch=command['epoch'],token=command['token']))
        self.assertIsNone(posted[-1]['body'])
        self.assertEqual(posted[-1]['epoch'],command['epoch'])

    def test_late_key_failure_cannot_cancel_next_body(self):
        c,r,w,posted,connect=self.make()
        p=bytes.fromhex('37040102030407')
        c.commands.accept(p,'S')
        old=c.commands.current.copy()
        c.commands.accept(p,'S')
        c.commands.observe(dict(tag='SCRAMBLE',hit='consumed',epoch=old['epoch'],token=old['token']))
        before=len(posted)
        c.client_dispatch._carrier_failed(dict(tag='SCRAMBLE',hit='error',id=0x437,
                               epoch=old['epoch'],token=old['token']))
        self.assertEqual(len(posted),before)

    def test_map_reset_fences_chunk_already_popped_by_feeder(self):
        c,r,w,posted,connect=self.make()
        popped=threading.Event()
        class ObservedDeque(deque):
            def popleft(self):
                value=super().popleft()
                popped.set()
                return value
        feed=c.recv_path
        e=new_chunk('fixture:5121','old',[('B',b'\x01\x00\x01\x02')],0,None)
        e.update(epoch=feed.epoch,revision=feed.revision,generation=r.generation)
        feed.pending=ObservedDeque([e])
        with r.lock:
            worker=threading.Thread(target=feed._feed_ready)
            worker.start()
            self.assertTrue(popped.wait(1))
            c.commands.session(True,advance_epoch=False)
        worker.join(1)
        self.assertFalse(worker.is_alive())
        r.sock.sendall.assert_not_called()


if __name__=='__main__':unittest.main()
