"""Encrypted actor checks without opening /proc memory or connecting to Frida."""
import collections
import random
import struct
import threading
import unittest
from unittest.mock import patch
import _boot
from relay.actors import ActorDecrypt, copy_validation, valid_actor, valid_actor_name
from relay.wire_feed import new_chunk


def plain_actor(name=b'Poring', aid=bytes([1,2,3,4])):
    P=bytearray(114)
    P[:4]=bytes.fromhex('ff097200')
    P[4]=5
    P[5:9]=aid
    P[13:15]=(200).to_bytes(2,'little')
    P[-24:]=name.ljust(24,bytes([0]))
    return bytes(P)


def fake_dec():
    d=ActorDecrypt.__new__(ActorDecrypt)
    d.base=0x1000;d.hi=0x5000;d.region=(0x1000,0x5000)
    d.chain={};d.stream={}
    d.spans=collections.defaultdict(lambda: collections.deque(maxlen=256))
    d.coff=collections.Counter();d.stats=collections.Counter()
    d.fed={};d.fails=0;d.lock=threading.Lock()
    return d


class ActorBoundaries(unittest.TestCase):
    def test_actor_min_length_and_speed_edges(self):
        P=plain_actor()
        self.assertTrue(valid_actor(P))
        for n in (0,4,13,14,59):
            self.assertFalse(valid_actor(P[:n]))
        for speed in (2001,65535):
            q=bytearray(P);q[13:15]=speed.to_bytes(2,'little')
            self.assertFalse(valid_actor(q),speed)
        for speed in (0,1,19,20,200,1000,2000):
            q=bytearray(P);q[13:15]=speed.to_bytes(2,'little')
            self.assertTrue(valid_actor(q),speed)

    def test_actor_type_and_invalid_name(self):
        P=plain_actor()
        for typ in (13,128,255):
            q=bytearray(P);q[4]=typ
            self.assertFalse(valid_actor(q))
        for name in (b'a\n',b'a\t',b'a\x01',b'\xa7',b'\xa5',b'Fake\xa7Name',b'Fake\xa5Name',bytes([0x93,0xb5,0xa7,0xa0])*5):
            q=bytearray(P)
            q[-24:]=name.ljust(24,bytes([0]))
            self.assertFalse(valid_actor(q))
        q=bytearray(P);q[-24:]=b'a\x00b'.ljust(24,bytes([0]))
        self.assertFalse(valid_actor(q))

    def test_accented_names_and_strict_padding(self):
        for name in ('João, o Ferreiro', 'Guardiã da Floresta',
                     'Éden - Funcionária', 'Capitão André', 'Kafra Employee'):
            with self.subTest(name=name):
                plain = plain_actor(name.encode('cp1252'))
                cipher = plain[:4] + b'\xe7' * (len(plain) - 4)
                self.assertTrue(valid_actor(plain))
                self.assertTrue(valid_actor_name(plain[-24:]))
                self.assertTrue(copy_validation(cipher, plain)['name_format_ok'])
                self.assertTrue(copy_validation(cipher, plain)['accepted'])
        for name in (b'', b' A', b'A ', b'A\x00B', b'A\x01', b'A\x81',
                     b'A\x8d', b'A\xa7', b'A\xa5', b'A\xa0'):
            with self.subTest(name=name):
                self.assertFalse(valid_actor_name(name.ljust(24, b'\x00')))
        self.assertFalse(valid_actor_name(b'A' * 25))

    def test_npc_name_ascii_punctuation_without_accepting_binary_data(self):
        # rAthena uses '#' as a separator in NPC display/internal names.
        for name in (b'Kafra Employee#prt1', b'Kafra#alde',
                     b'Cash Shop [VIP] @2', b'Sign: 50% + 1',
                     b'A_B=C|D\\E~F', 'João#praça'.encode('cp1252')):
            with self.subTest(name=name):
                plain = plain_actor(name)
                wire = plain[:4] + b'\xe7' * (len(plain) - 4)
                self.assertTrue(valid_actor_name(plain[-24:]))
                self.assertTrue(valid_actor(plain))
                self.assertTrue(copy_validation(wire, plain)['accepted'])
        for name in (b'A\x01', b'A\x7f', b'A\x81', b'A\xa7',
                     b'A\xa0', b'A\x00B'):
            with self.subTest(name=name):
                self.assertFalse(valid_actor_name(name.ljust(24, b'\x00')))

    def test_actor_09ff_copy_requires_same_header_and_modified_body(self):
        d=fake_dec(); plain=plain_actor()
        cipher=plain[:4]+bytes([0xee])*(len(plain)-4)
        self.assertTrue(d.copy_ok(cipher,plain))
        self.assertFalse(d.copy_ok(plain,plain))
        self.assertFalse(d.copy_ok(cipher,plain[:50]))
        self.assertFalse(d.copy_ok(cipher,bytes([0])*len(plain)))
        self.assertFalse(d.copy_ok(b'',plain))

    def test_fixed_0229_requires_unchanged_gid_and_id(self):
        d=fake_dec()
        pkt=bytes.fromhex('2902')+bytes([1,2,3,4])+bytes([5])*9
        p=pkt[:6]+bytes([6])*9
        self.assertEqual(len(pkt),15)
        self.assertTrue(d.copy_ok(pkt,p))
        self.assertFalse(d.copy_ok(pkt,pkt))
        self.assertFalse(d.copy_ok(pkt,p[:2]+bytes([0])*4+p[6:]))
        self.assertTrue(d.copy_ok(pkt,p[:2]+bytes([8,7,6,5])+p[6:]))  # ciphertext GID differs
        self.assertFalse(d.copy_ok(pkt,p[:-1]))
        self.assertFalse(d.copy_ok(pkt[:14],p[:14]))

    def test_partial_chunk_offsets_independent_by_connection(self):
        d=fake_dec()
        self.assertEqual(d.note_chunk('A',b'a'*25),(0,0x40))
        self.assertEqual(d.note_chunk('B',b'b'*10),(0,0x40))
        self.assertEqual(d.note_chunk('A',b'c'*7,left=2),(25,0x40+25))
        self.assertEqual(d.note_chunk('B',b'd'*3,left=0),(10,0x40))
        self.assertEqual(d.coff['A'],32)
        self.assertEqual(d.coff['B'],13)
        self.assertEqual(d.slot(0x40,15,5),0x1000+0x40+10)

    def test_stream_bounded_to_memory_limit(self):
        d=fake_dec()
        d.STREAM_KEEP=100
        d.note_chunk('c',bytes(range(200)))
        off,data=d.stream['c']
        self.assertEqual((off,len(data)),(100,100))
        self.assertEqual(data,bytes(range(100,200)))

    def test_encrypted_body_spans_fixed_and_variable(self):
        d=fake_dec()
        d.note_enc('c',100,15,pid=0x0229)
        d.note_enc('c',200,114,pid=0x09ff)
        self.assertEqual(list(d.spans['c']),[(102,115),(204,314)])

    def test_quick_discovery_mask_starts_after_two_clear_bytes_for_0229(self):
        d=fake_dec()
        d.base=None
        d.quick_busy=False
        tasks=[]
        class ThreadFake:
            def __init__(self, target, args, name, daemon):
                tasks.append((target,args))
            def start(self):pass
        items=[('E',0x0229,b'X'*15,5)]
        with patch('relay.actors.threading.Thread',ThreadFake):
            d.start_quick_discover('c',b'-'*30,items,cstart=0)
        self.assertTrue(d.quick_busy)
        self.assertEqual(tasks[0][1][2],[(7,20)])

    def test_same_decrypted_actor_duplicate_rejected_when_weak(self):
        d=fake_dec()
        P=plain_actor()
        with patch('relay.actors.time.time',side_effect=[100.0,101.0,111.0]):
            self.assertEqual(d._accept(P,'snap',False),P)
            self.assertIsNone(d._accept(P,'snap',False))
            self.assertEqual(d._accept(P,'snap',False),P)
        self.assertEqual(d.stats['dup-rejected'],1)

    def test_strong_evidence_allows_repeat(self):
        d=fake_dec();P=plain_actor()
        with patch('relay.actors.time.time',return_value=100):
            self.assertEqual(d._accept(P,'fresh',True),P)
            self.assertEqual(d._accept(P,'fresh',True),P)
        self.assertEqual(d.stats['ok-fresh'],2)

    def test_stale_before_image_only_marked_strong_with_matching_base(self):
        d=fake_dec()
        pkt=b'abcd'
        e=new_chunk('server:5121','c',[('E',0x09ff,pkt,4)],0,0x40)
        image=bytes(128)
        d.read=lambda a,n:bytes([1])*n
        d.before(e,(image,d.base))
        self.assertEqual(e['B'][0],image[0x44:0x48])
        self.assertTrue(e['Bsafe'])
        self.assertIn(0,e['Bsafe_items'])
        e2=new_chunk('server:5121','c',[('E',0x09ff,pkt,4)],0,0x40)
        d.before(e2,(image,d.base+64))
        self.assertEqual(e2['B'][0],bytes([1])*4)
        self.assertNotIn('Bsafe',e2)

    def test_no_ring_waits_before_discovery(self):
        d=fake_dec()
        d.base=None
        e=new_chunk('server:5121','c',[('E',0x09ff,b'abc',0)],0,0x40)
        d.resolve=lambda *a,**kw: b'copy'
        self.assertIsNone(d.settle(e,e['t']+0.001,0.15))
        self.assertEqual(d.settle(e,e['t']+0.04,0.15),{0:b'copy'})


if __name__=='__main__':
    unittest.main(verbosity=2)
