import os
import socket
import tempfile
import unittest
import unittest.mock

import _boot
from relay.observer import PacketObserver, MAX_HISTORY


def receive_exact(sock, amount):
    out = bytearray()
    while len(out) < amount:
        out += sock.recv(amount - len(out))
    return bytes(out)


class ObserverTests(unittest.TestCase):
    def test_framing_is_always_xkore1_and_chunks_at_u16_limit(self):
        self.assertEqual(PacketObserver.frame(b'abc'), b'R\x03\x00abc')
        payload = bytes([0x5A]) * 70000
        framed = PacketObserver.frame(payload)
        first = int.from_bytes(framed[1:3], 'little')
        self.assertEqual(first, 0xFFFF)
        second_at = 3 + first
        self.assertEqual(framed[second_at:second_at+1], b'R')
        second = int.from_bytes(framed[second_at+1:second_at+3], 'little')
        self.assertEqual(first + second, len(payload))

    def test_local_permissions_and_per_phase_replay(self):
        with tempfile.TemporaryDirectory() as root:
            os.chmod(root, 0o700)
            pathname = os.path.join(root, 'feed.sock')
            broker = PacketObserver(pathname)
            try:
                self.assertEqual(os.stat(pathname).st_mode & 0o777, 0o600)
                broker.begin_session('login-cookie-a')
                broker.publish(b'R\x02\x00\x11\x22', 'login')
                broker.publish(b'R\x02\x00\x33\x44', 'char')
                peer = socket.socket(socket.AF_UNIX)
                peer.settimeout(2)
                peer.connect(pathname)
                peer.sendall(b'L')
                self.assertEqual(receive_exact(peer, 5), b'R\x02\x00\x11\x22')
                broker.publish(b'R\x02\x00\xaa\xbb', 'map')
                broker.publish(b'R\x02\x00\x55\x66', 'login')
                self.assertEqual(receive_exact(peer, 5), b'R\x02\x00\x55\x66')
                peer.close()
                char = socket.socket(socket.AF_UNIX)
                char.settimeout(2)
                char.connect(pathname)
                char.sendall(b'C')
                self.assertEqual(receive_exact(char, 5), b'R\x02\x00\x33\x44')
                char.close()
            finally:
                broker.close()
            self.assertFalse(os.path.exists(pathname))

    def test_lowercase_phase_subscribes_live_without_history_replay(self):
        with tempfile.TemporaryDirectory() as root:
            os.chmod(root, 0o700)
            pathname = os.path.join(root, 'feed.sock')
            broker = PacketObserver(pathname)
            try:
                broker.begin_session('epoch-live')
                broker.publish(b'R\x02\x00\x01\x02', 'map')
                peer = socket.socket(socket.AF_UNIX)
                peer.settimeout(0.15)
                peer.connect(pathname)
                peer.sendall(b'm')
                with self.assertRaises(socket.timeout):
                    peer.recv(1)
                broker.publish(b'R\x02\x00\x03\x04', 'map')
                self.assertEqual(receive_exact(peer, 5), b'R\x02\x00\x03\x04')
                peer.close()
            finally:
                broker.close()

    def test_new_login_resets_history_and_stale_client(self):
        with tempfile.TemporaryDirectory() as root:
            os.chmod(root, 0o700)
            broker = PacketObserver(os.path.join(root, 'feed.sock'))
            try:
                broker.begin_session('epoch-1')
                broker.publish(b'R\x02\x00\x01\x02', 'map')
                broker.begin_session('epoch-2')
                self.assertEqual(list(broker.history['map']), [])
                self.assertTrue(broker.replay_valid)
                broker.publish(b'R\x02\x00\x03\x04', 'map')
                self.assertEqual(list(broker.history['map']), [b'R\x02\x00\x03\x04'])
                broker.publish(b'R' + b'\x00' * MAX_HISTORY, 'map')
                self.assertFalse(broker.replay_valid)
                self.assertEqual(list(broker.history['map']), [])
            finally:
                broker.close()

    def test_rejects_directory_not_owned_by_current_user(self):
        with tempfile.TemporaryDirectory() as root:
            os.chmod(root, 0o700)
            with unittest.mock.patch('relay.observer.os.getuid', return_value=os.getuid() + 1):
                with self.assertRaisesRegex(ValueError, 'user-owned'):
                    PacketObserver(os.path.join(root, 'feed.sock'))

    def test_close_does_not_unlink_replacement_socket(self):
        with tempfile.TemporaryDirectory() as root:
            os.chmod(root, 0o700)
            pathname = os.path.join(root, 'feed.sock')
            broker = PacketObserver(pathname)
            os.unlink(pathname)
            replacement = socket.socket(socket.AF_UNIX)
            try:
                replacement.bind(pathname)
                broker.close()
                self.assertTrue(os.path.exists(pathname))
            finally:
                replacement.close()
                if os.path.exists(pathname):
                    os.unlink(pathname)

    def test_late_session_event_after_close_is_ignored(self):
        with tempfile.TemporaryDirectory() as root:
            os.chmod(root, 0o700)
            broker = PacketObserver(os.path.join(root, 'feed.sock'))
            broker.begin_session('epoch-1')
            broker.publish(b'R\x01\x00x', 'map')
            broker.close()
            broker.begin_session('late-epoch')
            broker.publish(b'R\x01\x00y', 'map')
            self.assertTrue(broker.closed)
            self.assertFalse(broker.replay_valid)
            self.assertEqual(broker.history_size, 0)
            self.assertEqual(broker.history, {})

    def test_rejects_nonprivate_directory_and_unsafe_phase(self):
        with tempfile.TemporaryDirectory() as root:
            os.chmod(root, 0o755)
            with self.assertRaises(ValueError):
                PacketObserver(os.path.join(root, 'unsafe.sock'))
            os.chmod(root, 0o700)
            broker = PacketObserver(os.path.join(root, 'feed.sock'))
            try:
                with socket.socket(socket.AF_UNIX) as sock:
                    sock.connect(broker.pathname)
                    sock.sendall(b'X')
                broker.publish(b'R\x02\x00\x01\x02', 'not-a-phase')
                self.assertEqual(broker.history_size, 0)
            finally:
                broker.close()


if __name__ == '__main__':
    unittest.main()
