"""Wire feeder ordering and TCP identity tests, entirely in memory."""
import collections
import time
import unittest

import _boot
from relay.wire_feed import WireFeed, ClientSendFeed, new_chunk
from relay.packets import WireFilter


class FakeLog:
    def __init__(self):self.events=[]
    def write(self,m):self.events.append(m.copy())
class FakeRelay:
    def __init__(self):self.messages=[];self.send=[]
    def feed(self,p):self.messages.append(p)
    def feed_send(self,p):self.send.append(p)


def feeder(dec=None):
    r=FakeRelay(); log=FakeLog()
    return WireFeed(WireFilter({0x73:5},set()),r,log,lambda msg:None,dec=dec),r,log


class FeederEdgeTests(unittest.TestCase):
    def test_later_connection_same_server_must_not_close_previous_entry(self):
        f,_,_=feeder()
        sock='127.0.0.1:5121'
        f._queue({'sock':sock,'ts':1000},'connection-A',b'\x73\x00abc',None)
        f._queue({'sock':sock,'ts':2000},'connection-B',b'\x73\x00def',None)
        a,b=list(f.pending)
        self.assertIsNone(a['closed']) # distinct TCP identities, not just same remote port
        self.assertIsNone(b['closed'])

    def test_same_tcp_connection_next_recv_closes_previous(self):
        f,_,_=feeder()
        sock='127.0.0.1:5121'
        f._queue({'sock':sock,'ts':1000},'same',b'\x73\x00abc',None)
        f._queue({'sock':sock,'ts':2000},'same',b'\x73\x00def',None)
        a,b=list(f.pending)
        self.assertEqual(a['closed'],2000)
        self.assertIsNone(b['closed'])

    def test_ready_chunk_behind_unresolved_keeps_fifo_order(self):
        f,r,_=feeder()
        e=new_chunk('127.0.0.1:5121','c',
                    [('B',b'prefix'),('E',0x09ff,b'cipher',6),('B',b'suffix')],0,0)
        f.pending.append(e)
        f.pending.append(new_chunk('127.0.0.1:5121','c',[('B',b'next')],0,0))
        self.assertTrue(f._feed_ready())
        self.assertEqual(r.messages,[])
        e['res']={1:b'plain'}
        self.assertFalse(f._feed_ready())
        self.assertEqual(r.messages,[b'prefixplainsuffix',b'next'])

    def test_unverified_actor_drops_and_logs_reason(self):
        f,r,log=feeder()
        e=new_chunk('127.0.0.1:5121','c',[('B',b'A'),('E',0x09fd,b'bad',1)],0,0)
        e['res']={1:None}
        f.pending.append(e)
        self.assertFalse(f._feed_ready())
        self.assertEqual(r.messages,[b'A'])
        self.assertEqual(log.events[0]['tag'],'RECV-PLAIN-UNAVAILABLE')
        self.assertEqual(log.events[0]['id'],'09fd')
        self.assertNotIn('P',log.events[0])

    def test_cleartext_never_falsely_logged_as_decrypted(self):
        f,r,log=feeder()
        f.pending.append(new_chunk('127.0.0.1:5121','c',[('B',b'hello')],0,0))
        f._feed_ready()
        self.assertEqual(r.messages,[b'hello'])
        self.assertEqual(log.events,[])

    def test_split_for_decrypt_passes_actual_encrypted_packet_id(self):
        class DummyDec:
            base=None
            def __init__(self):self.calls=[]
            def note_chunk(self,conn,C,left):return 0,0x40
            def note_enc(self,conn,off,L,pid=None):self.calls.append((conn,off,L,pid))
            def start_quick_discover(self,*a):pass
        dec=DummyDec()
        f,_,_=feeder(dec=dec)
        f.wire.L[0x0229]=15
        encrypted=b'\x29\x02'+bytes(range(13))
        items,cstart,delta=f._split_for_decrypt('127.0.0.1:5121','connectionA',encrypted)
        self.assertEqual(items[0][0],'E')
        self.assertEqual(dec.calls,[('connectionA',0,15,0x0229)])

    def test_ringsnap_connection_only(self):
        f,_,_=feeder()
        a=new_chunk('server:5121','A',[('E',0x09ff,b'abc',0)],0,0)
        b=new_chunk('server:5121','B',[('E',0x09ff,b'abc',0)],0,0)
        f.pending.extend((a,b))
        f.on_ringsnap({'sock':'server:5121','conn':'A','base':'0x1000',
                       'data':b'abc', 'ts':10})
        self.assertEqual(len(a['snaps']),1)
        self.assertEqual(b['snaps'],[])
        a['closed']=20
        f.on_ringsnap({'sock':'server:5121','conn':'A','base':'0x1000',
                       'data':b'abc', 'ts':21})
        self.assertEqual(len(a['snaps']),1)

    def test_ringsnap_without_data_no_changes(self):
        f,_,_=feeder()
        a=new_chunk('server:5121','A',[('E',0x09ff,b'abc',0)],0,0)
        f.pending.append(a)
        f.on_ringsnap({'sock':'server:5121','conn':'A','base':'0x1000'})
        self.assertEqual(a['snaps'],[])

    def test_send_feed_discards_http_while_preserving_game(self):
        r=FakeRelay()
        c=ClientSendFeed(r,True)
        c.on_send({'sock':'127.0.0.1:5121','C':'37040102030407'})
        c.on_send({'sock':'127.0.0.1:5121','C':b'GET /secret'.hex()})
        c.on_send({'sock':'127.0.0.1:6900','C':'37040102030407'})
        c.on_send({'sock':'127.0.0.1:3000','C':b'GET /secret'.hex()})
        self.assertEqual(r.send,[bytes.fromhex('37040102030407')])


if __name__ == '__main__':
    unittest.main(verbosity=2)
