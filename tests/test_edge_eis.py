"""State machine and input safety for libei, with a fully fake libei library."""
import os
import socket
import tempfile
import unittest
from unittest.mock import patch
from pathlib import Path

import _boot
from relay.gamescope_eis import GamescopeEIS, GamescopeEISError, resolve_socket


class FakeEI:
    TYPES={1:b'EI_EVENT_CONNECT',2:b'EI_EVENT_SEAT_ADDED',
           3:b'EI_EVENT_DEVICE_ADDED',4:b'EI_EVENT_DEVICE_RESUMED',
           5:b'EI_EVENT_DEVICE_PAUSED',6:b'EI_EVENT_DEVICE_REMOVED',
           7:b'EI_EVENT_DISCONNECT'}
    def __init__(self,events=(),setup_result=0):
        self.events=list(events);self.setup_result=setup_result
        self.keys=[];self.frames=[];self.binds=[];self.unrefs=[]
        self.emulations=[];self.dispatches=0
        self.failure=None
    def new(self,*a):return 11
    def name(self,*a):pass
    def setup(self,*a):return self.setup_result
    def fd(self,*a):return 0
    def dispatch(self,*a):
        self.dispatches+=1
        if self.failure=='dispatch':
            raise OSError('fake EIS transport failure')
    def get_event(self,*a):
        return self.events.pop(0) if self.events else None
    def event_type(self,n):return self.TYPES[n]
    def ev_kind(self,event):return event[0]
    def ev_seat(self,event):return event[1]
    def ev_device(self,event):return event[1]
    def ev_unref(self,event):pass
    def bind(self,*args):self.binds.append(args)
    def has_cap(self,dev,cap):return bool(cap==4 and dev==30)
    def device_ref(self,dev):return dev
    def device_unref(self,dev):self.unrefs.append(('device',dev))
    def emulate(self,dev,seq):self.emulations.append((dev,seq))
    def key(self,dev,code,pressed):
        self.keys.append((dev,code,pressed))
        if pressed and self.failure=='keydown':raise OSError('fake keydown failure')
        if not pressed and self.failure=='keyup':raise OSError('fake keyup failure')
    def now(self,ctx):return 12345
    def frame(self,dev,t):self.frames.append((dev,t))
    def unref(self,ctx):self.unrefs.append(('ctx',ctx))


class EISBoundaryTests(unittest.TestCase):
    def test_path_file_permissions_and_type(self):
        with tempfile.TemporaryDirectory() as d:
            with socket.socket(socket.AF_UNIX) as s:
                p=os.path.join(d,'gamescope-4-ei');s.bind(p)
                locator=os.path.join(d,'locator')
                Path(locator).write_text('gamescope-4-ei\n')
                os.chmod(locator,0o600)
                with patch.dict(os.environ,{'XDG_RUNTIME_DIR':d}):
                    self.assertEqual(resolve_socket(path_file=locator),p)
                    with self.assertRaises(GamescopeEISError):
                        resolve_socket('anything',locator)
                for mode in (0o640,0o604,0o666):
                    os.chmod(locator,mode)
                    with self.subTest(mode=mode),self.assertRaises(GamescopeEISError):
                        resolve_socket(path_file=locator)

    def test_reject_non_socket_and_missing_env(self):
        with tempfile.TemporaryDirectory() as d:
            p=os.path.join(d,'gamescope-1-ei')
            Path(p).write_text('not a socket')
            with self.assertRaises(GamescopeEISError):
                resolve_socket(p)
            with patch.dict(os.environ,{'XDG_RUNTIME_DIR':''}):
                with self.assertRaises(GamescopeEISError):
                    resolve_socket('gamescope-1-ei')
            with self.assertRaises(GamescopeEISError):
                resolve_socket('')

    def test_reject_host_compositor_socket_even_if_explicit(self):
        with tempfile.TemporaryDirectory() as d:
            with socket.socket(socket.AF_UNIX) as s:
                host=os.path.join(d,'kwin-eis-socket')
                s.bind(host)
                with self.assertRaises(GamescopeEISError):
                    resolve_socket(host)
                alias=os.path.join(d,'gamescope-9-ei')
                os.symlink(host,alias)
                with self.assertRaises(GamescopeEISError):
                    resolve_socket(alias)

    def test_reject_control_characters(self):
        with self.assertRaises(GamescopeEISError):
            resolve_socket('gamescope\n-0-ei')
        with self.assertRaises(GamescopeEISError):
            resolve_socket('gamescope\x00-0-ei')

    def make_connected(self,api=None):
        obj=GamescopeEIS(socket='gamescope-0-ei')
        obj.api=api or FakeEI()
        obj.ctx=11;obj.dev=30;obj.ready=True
        return obj

    def test_event_negotiation_real_keyboard_capability(self):
        api=FakeEI(events=[(2,20),(3,30),(4,30)])
        obj=self.make_connected(api)
        obj.dev=None;obj.ready=False
        obj._drain_events()
        self.assertTrue(obj.ready)
        self.assertEqual(obj.dev,30)
        self.assertEqual(api.binds[0][1].value,4)
        self.assertEqual(api.emulations,[(30,0)])
        obj.close()
        self.assertIn(('device',30),api.unrefs)

    def test_other_device_never_used_for_keyboard(self):
        api=FakeEI(events=[(3,31),(4,31)])
        obj=self.make_connected(api)
        obj.dev=None;obj.ready=False
        obj._drain_events()
        self.assertIsNone(obj.dev)
        self.assertFalse(obj.ready)

    def test_pause_and_remove_disarm_keyboard(self):
        api=FakeEI(events=[(5,30)])
        obj=self.make_connected(api)
        obj._drain_events()
        self.assertFalse(obj.ready)
        api.events.append((6,30))
        obj._drain_events()
        self.assertIsNone(obj.dev)

    def test_disconnect_raises(self):
        api=FakeEI(events=[(7,0)])
        obj=self.make_connected(api)
        with self.assertRaisesRegex(GamescopeEISError,'disconnected'):
            obj._drain_events()

    def test_send_key_frames_and_release_even_on_failure(self):
        api=FakeEI()
        obj=self.make_connected(api)
        obj._drain_events=lambda:None
        self.assertEqual(obj.send_key(110,hold_ms=0),0)
        self.assertEqual(api.keys,[(30,110,True),(30,110,False)])
        self.assertEqual(api.frames,[(30,12345),(30,12345)])
        obj.close()
        self.assertFalse(obj.ready)

    def test_failed_send_closes_stale_context(self):
        api=FakeEI();api.failure='keydown'
        obj=self.make_connected(api)
        obj._drain_events=lambda:None
        with self.assertRaises(OSError):
            obj.send_key(110,hold_ms=0)
        self.assertFalse(obj.ready)
        self.assertIsNone(obj.dev)
        self.assertIsNone(obj.ctx)
        self.assertEqual(api.keys,[(30,110,True),(30,110,False)])

    def test_failed_connection_closes_context(self):
        api=FakeEI(setup_result=-9)
        obj=GamescopeEIS(socket='gamescope-0-ei')
        with patch('relay.gamescope_eis.resolve_socket',return_value='/tmp/fake'), \
             patch('relay.gamescope_eis._LibEI',return_value=api):
            with self.assertRaisesRegex(GamescopeEISError,'refused'):
                obj.send_key(110,hold_ms=0)
        self.assertFalse(obj.ready)
        self.assertIsNone(obj.ctx)

    def test_no_device_ready_fails_without_key_event(self):
        api=FakeEI()
        obj=GamescopeEIS(socket='gamescope-0-ei',connect_timeout=0)
        with patch('relay.gamescope_eis.resolve_socket',return_value='/tmp/fake'), \
             patch('relay.gamescope_eis._LibEI',return_value=api):
            with self.assertRaisesRegex(GamescopeEISError,'timeout'):
                obj.send_key(110,hold_ms=0)
        self.assertEqual(api.keys,[])
        self.assertFalse(obj.ready)


if __name__=='__main__':
    unittest.main(verbosity=2)
