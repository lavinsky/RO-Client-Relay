"""Pure offline XKore connection, framing and error-state tests."""
import random
import threading
import unittest
from unittest.mock import patch

import _boot
from relay.relay import Relay, PacketAligner


class FakeSocket:
    def __init__(self, fail=False):
        self.fail=fail
        self.sent=[]
        self.closed=False
        self.recv_items=[]
        self.timeout=None
        self.opts=[]
    def sendall(self, data):
        if self.fail:
            raise BrokenPipeError('synthetic client disconnect')
        self.sent.append(data)
    def close(self):
        self.closed=True
    def recv(self, size, flags):
        o=self.recv_items.pop(0)
        if isinstance(o,BaseException):raise o
        return o
    def settimeout(self, value):
        self.timeout=value
    def setsockopt(self,*a):
        self.opts.append(a)


def relay(fmt='xkore1', sock=None):
    r=Relay.__new__(Relay)
    r.lock=threading.Lock()
    r.fmt=fmt; r._in=b''
    r.sock=sock
    r.sent=r.dropped=0
    r.dump=None
    r.on_disconnect=None
    r.on_connect=None
    r.on_inbound=None
    r._connected_once=False
    r.aligner=None
    r.align=False
    r.host='127.0.0.1';r.port=2
    return r


class RelayEdgeTests(unittest.TestCase):
    def test_frame_max_and_exact_roundtrips(self):
        r=relay()
        for n in (0,1,2,255,256,65534,65535,65536,131071,131072):
            data=bytes((i*31)%256 for i in range(n))
            framed=r.frame(data,'R')
            payload=[]; pos=0
            while pos<len(framed):
                self.assertEqual(framed[pos:pos+1],b'R')
                size=int.from_bytes(framed[pos+1:pos+3],'little')
                self.assertLessEqual(size,65535)
                payload.append(framed[pos+3:pos+3+size])
                pos+=3+size
            self.assertEqual(pos,len(framed))
            self.assertEqual(b''.join(payload),data)
            self.assertEqual(len(payload), (n+65534)//65535)

    def test_deframe_every_split_point(self):
        data=b'S\x04\x00ABCDR\x02\x00hiS\x00\x00'
        for cut in range(len(data)+1):
            r=relay();got=[]
            r.on_inbound=lambda data,typ:got.append((typ,data))
            r._inbound(data[:cut]);r._inbound(data[cut:])
            self.assertEqual(got,[('S',b'ABCD'),('R',b'hi'),('S',b'')])
            self.assertEqual(r._in,b'')

    def test_frame_fuzz_randomized_fragmentation(self):
        rand=random.Random(400)
        for _ in range(90):
            frames=[(rand.choice('RS'),rand.randbytes(rand.randrange(25))) for i in range(rand.randrange(1,15))]
            bytestream=b''.join(k.encode()+len(p).to_bytes(2,'little')+p for k,p in frames)
            r=relay();got=[];r.on_inbound=lambda p,t:got.append((t,p))
            cursor=0
            while cursor<len(bytestream):
                chunk=rand.randrange(1,11)
                r._inbound(bytestream[cursor:cursor+chunk])
                cursor+=chunk
            self.assertEqual(got,frames)
            self.assertEqual(r._in,b'')

    def test_incomplete_frame_preserved_until_arrival(self):
        r=relay();r.on_inbound=lambda *a:None
        self.assertEqual(r._deframe(),[])
        r._in=b'S\xff\xff'+bytes(100)
        self.assertEqual(r._deframe(),[])
        self.assertEqual(len(r._in),103)

    def test_raw_mode_direct_payload(self):
        r=relay('raw');got=[]
        r.on_inbound=lambda p,t:got.append((t,p))
        r._inbound(b'abc');r._inbound(b'');r._inbound(b'def')
        self.assertEqual(got,[('S',b'abc'),('S',b'def')])
        self.assertEqual(r.frame(b'abcdef'),b'abcdef')

    def test_handler_exceptions_do_not_abort_batch(self):
        r=relay();done=[]
        def handler(payload,typ):
            done.append(payload)
            if len(done)==1:raise RuntimeError('handler failed')
        r.on_inbound=handler
        r._inbound(b'S\x01\x00aS\x01\x00b')
        self.assertEqual(done,[b'a',b'b'])

    def test_send_no_consumer_counts_drops(self):
        r=relay()
        r.send(b'abc')
        self.assertEqual(r.dropped,6)
        self.assertEqual(r.sent,0)

    def test_send_to_connected_consumer(self):
        sock=FakeSocket();r=relay(sock=sock)
        r.send(b'xyz')
        self.assertEqual(sock.sent,[b'R\x03\x00xyz'])
        self.assertEqual(r.sent,6)
        self.assertEqual(r.dropped,0)

    def test_send_failure_notifies_disconnect_once(self):
        sock=FakeSocket(fail=True);r=relay(sock=sock)
        lost=[]
        r.on_disconnect=lambda:lost.append('drop')
        r.send(b'abc')
        self.assertIsNone(r.sock)
        self.assertTrue(sock.closed)
        self.assertEqual(r.dropped,6)
        self.assertEqual(lost,['drop'])  # protects native-context invalidation callback
        r._drop_sock(sock)
        self.assertEqual(lost,['drop'])

    def test_drop_sock_does_not_disconnect_newer_socket(self):
        s1=FakeSocket();s2=FakeSocket();r=relay(sock=s2)
        seen=[];r.on_disconnect=lambda:seen.append(True)
        r._drop_sock(s1)
        self.assertIs(r.sock,s2)
        self.assertEqual(seen,[])
        r._drop_sock(s2)
        self.assertIsNone(r.sock)
        self.assertEqual(len(seen),1)

    def test_connection_reuse_resets_inbound_and_aligner(self):
        s=FakeSocket();r=relay(sock=None)
        class Aligner:
            def __init__(self):self.resets=0
            def reset(self):self.resets+=1
        align=Aligner();r.aligner=align
        callbacks=[];r.on_connect=lambda:callbacks.append('recapture')
        with patch('relay.relay.socket.create_connection',return_value=s):
            r._connect()
        self.assertEqual(callbacks,[])
        r._in=b'S\x02'
        r._drop_sock(s)
        with patch('relay.relay.socket.create_connection',return_value=FakeSocket()):
            r._connect()
        self.assertEqual(callbacks,['recapture'])
        self.assertEqual(r._in,b'')
        self.assertEqual(align.resets,2)


if __name__ == '__main__':
    unittest.main(verbosity=2)
