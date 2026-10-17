"""Offline session ordering and fragmented XKore frames."""
import pathlib
import sys
import threading
import unittest
from unittest.mock import Mock, patch
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))
from relay.xkore_transport import Relay


class Sessions(unittest.TestCase):
    def make(self, **kwargs):
        with patch.object(threading.Thread, 'start'):
            return Relay('offline', 0, **kwargs)

    def test_delayed_start_is_idempotent(self):
        with patch.object(threading.Thread, 'start') as start:
            r = Relay('offline', 0, autostart=False)
            start.assert_not_called()
            r.start()
            r.start()
            start.assert_called_once_with()

    def test_stale_generation_cannot_send_or_contaminate_alignment(self):
        r = self.make(lengths={1: 2})
        r.sock = Mock()
        r.generation = 2
        r.feed(b'old', generation=1)
        r.send(b'old', generation=1)
        r.feed_send(b'old', generation=1)
        r.sock.sendall.assert_not_called()
        self.assertEqual(r.aligner.acc, b'')
        r.send(b'current', generation=2)
        r.sock.sendall.assert_called_once_with(r.frame(b'current'))

    def test_successful_connect_has_no_backoff_before_inbound(self):
        r = self.make(autostart=False)
        sock = Mock()
        def connect():
            r.sock = sock
        with patch.object(r, '_connect', side_effect=connect), \
                patch('relay.xkore_transport.time.sleep') as sleep, \
                patch('relay.xkore_transport.select.select', return_value=([sock], [], [])), \
                patch.object(r, '_check_dead', side_effect=StopIteration):
            with self.assertRaises(StopIteration):
                r._connect_loop()
        sleep.assert_not_called()

    def test_initial_connect_resets_before_publish(self):
        seen = []
        r = self.make(on_connect=lambda: seen.append((r.sock, r._in)))
        r._in = b'partial'
        sock = Mock()
        with patch('relay.xkore_transport.socket.create_connection', return_value=sock):
            r._connect()
        self.assertEqual(seen, [(None, b'')])
        self.assertEqual(r.generation, 1)

    def test_fragmented_concatenated_and_stale(self):
        r = self.make()
        r.sock = old = Mock()
        seen = []
        r.on_inbound = lambda data, typ: seen.append((data, typ))
        framed = r.frame(b'one', 'S') + r.frame(b'two', 'R')
        for chunk in (framed[:1], framed[1:4], framed[4:]):
            r._inbound(chunk, old)
        self.assertEqual(seen, [(b'one', 'S'), (b'two', 'R')])
        r._inbound(b'S\x08', old)
        r._drop_sock(old)
        r.sock = Mock()
        r._inbound(framed, old)
        self.assertEqual(r._in, b'')
        self.assertEqual(len(seen), 2)

    def test_send_failure_disconnect_once(self):
        callback = Mock()
        r = self.make(on_disconnect=callback)
        r.sock = sock = Mock()
        sock.sendall.side_effect = OSError('offline')
        r.send(b'payload')
        r._drop_sock(sock)
        callback.assert_called_once_with()
        self.assertIsNone(r.sock)

    def test_eof_cancels_received_tail_before_dispatch(self):
        callback = Mock()
        r = self.make(on_disconnect=callback)
        r.sock = sock = Mock()
        sock.recv.side_effect = [r.frame(b'pending', 'S'), b'']
        r.on_inbound = Mock()
        r._check_dead()
        r.on_inbound.assert_not_called()
        callback.assert_called_once_with()


if __name__ == '__main__':
    unittest.main()
