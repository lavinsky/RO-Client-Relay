"""Boundary and metamorphic tests for RO framing; synthetic bytes only."""
import random
import tempfile
import unittest
from pathlib import Path

import _boot
from relay.packets import (MoveTracker, WireFilter, load_lengths, pack_move,
                           unpack_move, unpack_pos2, packet_len)


def pkt(pid, size):
    return pid.to_bytes(2, 'little') + bytes((i * 37) % 256 for i in range(size - 2))


class PacketBoundaryTests(unittest.TestCase):
    def test_load_lengths_malformed_table(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / 'table'
            p.write_text("0073 2\n0087 0\n0088 1\n0099 -1\n00AB -2\nBADLINE\nXY 8\n"
                         "00CD 8 x\n00EF 12\n", encoding='ascii')
            self.assertEqual(load_lengths(p), {0x73:2, 0x99:-1, 0xcd:8, 0xef:12})

    def test_packet_len_boundaries(self):
        lens={0x100: 2, 0x101: -1}
        for frame, expected in [(b'\x00\x01',2),(b'\x01\x01',0),
                                (b'\x01\x01\x04',0),(b'\x01\x01\x00\x00',None),
                                (b'\x01\x01\x03\x00',None),
                                (b'\x01\x01\x04\x00',4),
                                (b'\x01\x01\xff\xff',65535),
                                (b'\xff\xfe',None)]:
            with self.subTest(frame=frame):
                self.assertEqual(packet_len(lens,frame,0), expected)

    def test_move_1024_exhaustive_corner_coordinates(self):
        rng=random.Random(31819)
        coords=[0,1,2,3,4,15,16,63,64,127,255,256,511,512,1022,1023]
        samples=[(x,y,d) for x in coords for y in coords for d in (0,1,7,15)]
        samples += [(rng.randrange(1024),rng.randrange(1024),rng.randrange(16))
                    for _ in range(3000)]
        for x,y,d in samples:
            self.assertEqual(unpack_move(pack_move(x,y,d)),(x,y,d))
        with self.assertRaises(ValueError):
            unpack_move(b'')
        with self.assertRaises(ValueError):
            unpack_move(b'\x01\x02')

    def test_0087_and_move_tracker_short_and_nonmove(self):
        tracker=MoveTracker()
        bad=b'\x87\x00'+bytes(9)
        self.assertIsNone(tracker.on_recv_packet('c',0x87,0,bad))
        self.assertIsNone(tracker.on_recv_packet('c',0x86,0,bad+b'x'))
        self.assertEqual(sum(tracker.stats.values()),0)
        self.assertEqual(unpack_pos2(bytes(6)),(0,0,0,0))

    def test_tokenizer_every_two_piece_cut(self):
        L={0x73:5,0x87:12,0x99:-1,0x9ff:-1}
        a=pkt(0x73,5); b=pkt(0x87,12)
        v=b'\x99\x00\x06\x00ZZ'; encrypted=b'\xff\x09\x09\x00hello'
        stream=a+v+encrypted+b
        expected=[('B',a+v),('E',0x9ff,encrypted,len(a+v)),('B',b)]
        for cut in range(len(stream)+1):
            w=WireFilter(L,set())
            events=w.push_items('c',stream[:cut],enc={0x9ff})
            events+=w.push_items('c',stream[cut:],enc={0x9ff})
            normalized=[]
            for ev in events:
                if ev[0]=='B' and normalized and normalized[-1][0]=='B':
                    normalized[-1]=('B',normalized[-1][1]+ev[1])
                else:
                    normalized.append(ev)
            self.assertEqual(normalized,expected,(cut,events))
            self.assertEqual(w.carried('c'),0)
        w=WireFilter(L,{0x73,0x99,0x87})
        events=w.push_items('c',stream,enc={0x9ff})
        self.assertEqual(events,[('E',0x9ff,encrypted,len(a+v))])

    def test_tokenizer_byte_at_a_time(self):
        L={0x73:5,0x87:12,0x99:-1}
        a=pkt(0x73,5);v=b'\x99\x00\x04\x00';b=pkt(0x87,12)
        w=WireFilter(L,set())
        data=a+v+b; chunks=[]
        for byte in data:
            chunks.extend(w.push_items('x',bytes([byte])))
        self.assertEqual(b''.join(c[1] for c in chunks if c[0]=='B'),data)
        self.assertEqual(w.carried('x'),0)

    def test_connection_fragments_do_not_cross(self):
        L={0x73:5,0x87:12}
        a=pkt(0x73,5);b=pkt(0x87,12);w=WireFilter(L,set())
        self.assertEqual(w.push_items('connA',a[:3]),[])
        self.assertEqual(w.push_items('connB',b),[('B',b)])
        self.assertEqual(w.carried('connA'),3)
        self.assertEqual(w.push_items('connA',a[3:]),[('B',a)])
        self.assertEqual(w.carried('connB'),0)

    def test_unknown_midstream_only_affects_one_connection(self):
        L={0x73:5}
        a=pkt(0x73,5);w=WireFilter(L,set())
        self.assertEqual(w.push_items('A',a+b'\xde\xadxx'),[('B',a+b'\xde\xadxx')])
        self.assertTrue(w.conns['A']['raw'])
        self.assertEqual(w.push_items('B',a),[('B',a)])
        self.assertFalse(w.conns['B']['raw'])
        self.assertEqual(w.push_items('A',b'fake'),[('B',b'fake')])

    def test_char_return_account_preamble_suppressed(self):
        L={0x73:5};w=WireFilter(L,set())
        w.observe_socket('map','127.0.0.1:5121')
        w.observe_socket('char2','127.0.0.1:6121')
        pre=b'\xde\xad\xbe\xef'; a=pkt(0x73,5)
        self.assertEqual(w.push_items('char2',pre[:2]),[])
        self.assertEqual(w.push_items('char2',pre[2:]+a),[('B',a)])
        self.assertEqual(w.push_items('char3',pre+a),[('B',pre+a)])

    def test_packet_offsets_ignore_drops(self):
        L={0x73:5,0x87:12};w=WireFilter(L,{0x73})
        got=[];w.on_packet=lambda *a:got.append(a)
        a=pkt(0x73,5);b=pkt(0x87,12)
        w.push_items('conn',a[:3])
        self.assertEqual(w.push_items('conn',a[3:]+b),[('B',b)])
        self.assertEqual([(t[1],t[2]) for t in got],[(0x73,0),(0x87,5)])


if __name__ == '__main__':
    unittest.main(verbosity=2)
