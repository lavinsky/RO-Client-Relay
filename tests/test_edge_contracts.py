"""Deterministic config/protocol/safety/log/sendwatch contracts, no live connections."""
import io
import json
import random
import tempfile
import threading
import unittest
from pathlib import Path
from unittest.mock import patch
from types import SimpleNamespace

import _boot
from relay.cli import parse_args, parse_ids
from relay.protocol import (ring_msg,sendwatch_msg,scramble_msg,scramble_set_msg,
                            sendcall_msg,sendcall_emit_msg,move_dispatch_msg,conn_of)
from relay.sendwatch import SendWatch, send_queue_range, plaintext_guess, packet_at
from relay.safety import sanitize, client_packet_to_feed
from relay.console import CaptureLog
from relay.agent import Agent, pick_port, pid_of_port


class ConfigContracts(unittest.TestCase):
    def make_conf(self,s):
        self.d=tempfile.TemporaryDirectory()
        self.addCleanup(self.d.cleanup)
        path=Path(self.d.name)/'test.ini';path.write_text(s)
        return str(path)

    def test_missing_configuration_uses_cli_defaults(self):
        p=self.make_conf('')
        a=parse_args(['--config',p])
        self.assertFalse(a.synth_input)
        self.assertEqual(a.synth_backend,'ydotool')
        self.assertFalse(a.inject)
        self.assertFalse(a.egress_queue)

    def test_ini_and_cli_precedence_and_bool_variants(self):
        combos=[('true',True),('FALSE',False),('yes',True),('NO',False),
                ('on',True),('off',False),('1',True),('0',False)]
        for val,expected in combos:
            with self.subTest(val=val):
                path=self.make_conf('[capture]\nsynth-input = '+val+'\n')
                a=parse_args(['--config',path])
                self.assertEqual(a.synth_input,expected)
                a=parse_args(['--config',path,'--no-synth-input'])
                self.assertFalse(a.synth_input)
                a=parse_args(['--config',path,'--synth-input'])
                self.assertTrue(a.synth_input)

    def test_bad_ini_is_ignored(self):
        p=self.make_conf('[capture]\nsynth-input = invalid\negress-queue = false\n'
                         'synth-debounce-ms = letters\n')
        a=parse_args(['--config',p])
        self.assertFalse(a.synth_input)
        self.assertFalse(a.egress_queue)
        self.assertEqual(a.synth_debounce_ms,500)

    def test_valid_gamescope_selection_and_no_ydotool_fallback(self):
        p=self.make_conf('[capture]\nsynth-input = yes\nsynth-backend=gamescope-eis\n'
                         'synth-eis-socket-file = /run/user/1000/file\n')
        a=parse_args(['--config',p])
        self.assertTrue(a.synth_input)
        self.assertEqual(a.synth_backend,'gamescope-eis')
        self.assertEqual(a.synth_eis_socket_file,'/run/user/1000/file')

    def test_id_parser_robust_to_blanks_and_duplicate(self):
        self.assertEqual(parse_ids('035f, 035F, 09ff ,,,junk,0073'),{0x035f,0x09ff,0x73})

    def test_default_config_still_intentional(self):
        a=parse_args([])
        self.assertTrue(a.inject)
        self.assertTrue(a.inject_call)
        self.assertTrue(a.synth_input)
        self.assertEqual(a.synth_backend,'gamescope-eis')
        self.assertFalse(a.egress_queue)
        self.assertFalse(a.sendcall_demand)
        self.assertTrue(a.itemuse_input)


class ProtocolContracts(unittest.TestCase):
    def test_ring_span_zero_and_positive(self):
        self.assertEqual(ring_msg('c',0x123),{'type':'ring','sock':'c','base':'0x123'})
        self.assertEqual(ring_msg('c',0x123,99)['span'],99)
        self.assertNotIn('span',ring_msg('c',0x123,0))

    def test_sendwatch_disable_and_valid_ranges(self):
        self.assertEqual(sendwatch_msg(),{'type':'sendwatch'})
        self.assertEqual(sendwatch_msg(32,64,(5121,))['ports'],[5121])

    def test_scramble_config_and_disarm(self):
        self.assertEqual(scramble_msg(),{'type':'scramble'})
        m=scramble_msg(0x10,pid=0x437,body='aabb',dry=False,lo=1,hi=2,ids=[0x437],trace=12)
        self.assertEqual(m['off'],0x10)
        self.assertEqual(m['body'],'aabb')
        self.assertFalse(m['dry'])
        self.assertEqual(m['traceMax'],12)
        self.assertEqual(m['ids'],[0x437])
        self.assertEqual(scramble_set_msg(0x438,body='') ,{'type':'scramble-set','id':0x438,'body':''})

    def test_native_dispatch_modes(self):
        self.assertEqual(move_dispatch_msg(disarm=True),{'type':'native-dispatch','disarm':True})
        self.assertEqual(move_dispatch_msg(recapture=True),{'type':'native-dispatch','recapture':True})
        arm=move_dispatch_msg(arm=True,dispatcher='0xd473b0',site='0x4dcba0')
        self.assertEqual((arm['dispatcher'],arm['site']),(0xd473b0,0x4dcba0))
        self.assertEqual(move_dispatch_msg(1023,0)['args'],{'x':1023,'y':0})
        self.assertEqual(move_dispatch_msg(arm=True,disarm=True),{'type':'native-dispatch','disarm':True})

    def test_sendcall_enabled_and_disabled(self):
        self.assertEqual(sendcall_msg(),{'type':'sendcall'})
        self.assertEqual(sendcall_msg(0x10,cast_ms=1500,demand=True)['demand'],True)
        self.assertEqual(sendcall_emit_msg('ab')['data'],'ab')

    def test_connection_selection(self):
        self.assertEqual(conn_of({'sock':'s','conn':'c'}),'c')
        self.assertEqual(conn_of({'sock':'s'}),'s')


class SafetyAndLogs(unittest.TestCase):
    def test_login_user_password_never_fed(self):
        login=b'\x64\x00'+bytes(range(4))+b'private-user'.ljust(24,b'\0')+b'private-secret'.ljust(24,b'\0')+b'\x07'
        for sock in ('localhost:6900','localhost:3000'):
            clean=client_packet_to_feed(sock,login)
            self.assertEqual(clean[6:54],bytes(48))
            self.assertNotIn(b'private',clean)
            self.assertIsNone(client_packet_to_feed(sock,b'\x64\x00'+bytes(10)))

    def test_http_redaction_works_on_login_or_game_socket(self):
        for sock in ('127.0.0.1:6900','127.0.0.1:5121'):
            for proto in (b'POST /key', b'GET /auth', b'HTTP/1.1 200', b'PUT /auth'):
                self.assertIsNone(client_packet_to_feed(sock,proto))
                m={'sock':sock,'tag':'RECV-WIRE','C':proto.hex(),'P':proto.hex()}
                sanitize(m)
                self.assertNotIn(proto.hex(),m['C'])
                self.assertNotIn(proto.hex(),m['P'])

    def test_receive_from_login_port_never_logs_auth_material(self):
        secret=bytes([17,0])+b'auth-token-password'
        m={'tag':'RECV-WIRE','sock':'127.0.0.1:6900','C':secret.hex(),'P':secret.hex()}
        sanitize(m)
        self.assertNotIn(secret.hex(),m['C'])
        self.assertNotIn(secret.hex(),m['P'])

    def test_capture_log_strips_binary_and_ptr(self):
        with tempfile.TemporaryDirectory() as d:
            p=Path(d)/'log'
            with patch('relay.console.show'):
                log=CaptureLog(p)
                record={'tag':'SEND','sock':'localhost:6900',
                        'C':b'usersecret'.hex(),'data':b'rawsecret','ptr':'0xdead'}
                log.write(record)
                log.f.close()
            out=json.loads(p.read_text())
            self.assertNotIn('data',out)
            self.assertNotIn('ptr',out)
            self.assertNotIn('usersecret'.encode().hex(),out['C'])

    def test_capture_log_atomic_multithread(self):
        with tempfile.TemporaryDirectory() as d:
            p=Path(d)/'log'
            with patch('relay.console.show'):
                log=CaptureLog(p)
                def submit(k):
                    for i in range(40):
                        log.write({'tag':'noop','id':'x','seq':k*1000+i})
                jobs=[threading.Thread(target=submit,args=(k,)) for k in range(8)]
                for t in jobs:t.start()
                for t in jobs:t.join(timeout=2)
                self.assertTrue(all(not t.is_alive() for t in jobs))
                log.f.close()
            lines=[json.loads(t) for t in p.read_text().splitlines()]
            self.assertEqual(len(lines),320)
            self.assertEqual(len({a['seq'] for a in lines}),320)
            self.assertTrue(all('ts' in a for a in lines))


class SendwatchContracts(unittest.TestCase):
    def test_packet_at_window_alignment(self):
        self.assertEqual(packet_at('0011223344','0x1001','0x1000'),'11223344')
        self.assertEqual(packet_at('0011223344',None,'0x1000'),'0011223344')

    def test_no_encryption_run_never_guesses(self):
        c='37040102030407'
        for hits in ([],[{'pc':'p','win':c}],[{'pc':'a','win':c},{'pc':'b','win':c}]):
            self.assertIsNone(plaintext_guess({'hits':hits},c))

    def test_malformed_write_watch_never_crashes_recovery(self):
        c='37040102030407'
        malformed=[
            {},
            {'hits':'bad-type'},
            {'hits':[{},{}]},
            {'hits':[{'pc':'1'}, {'pc':'1'}]},
            {'hits':[{'pc':'1','win':'zz'}, {'pc':'1','win':'xx'}]},
            {'hits':[{'pc':'1','win':c}, {'pc':'1','win':c}]},
        ]
        for watch in malformed:
            with self.subTest(watch=watch):
                self.assertIsNone(plaintext_guess(watch,c,buf='not-hex',base='0x1000'))

    def test_unverified_action_is_dropped(self):
        s=SendWatch()
        for pid,body in [(0x437,b'\x01\x02\x03\x04\x07'),
                         (0x438,bytes(8))]:
            P=pid.to_bytes(2,'little')+body
            self.assertIsNone(s.resolve({'C':P.hex()},P,None))
        self.assertEqual(sum(s.stats.values()),2)

    def test_plain_packet_not_transformed(self):
        s=SendWatch()
        for pid in (0x73,0x85,0x94):
            P=pid.to_bytes(2,'little')+b'hi'
            self.assertEqual(s.resolve({'C':P.hex()},P,None),P)
        self.assertEqual(sum(s.stats.values()),0)

    def test_queue_range_selection_and_fallback(self):
        self.assertIsNone(send_queue_range('auto',None,True))
        self.assertEqual(send_queue_range('100-200',(5,10),True)[:2],(256,512))
        self.assertEqual(send_queue_range('auto',(128,256),True)[:2],(128,256))
        self.assertIsNotNone(send_queue_range('auto',None,False))


if __name__=='__main__':
    unittest.main(verbosity=2)
