"""Verify map/character position packets survive the relay's full receive path.

Offline synthetic fixtures only: does not assert that uaRO emitted any of these
packets in a real session, nor that OpenKore parsed them successfully.
"""
import unittest
from unittest.mock import Mock

import _boot
from relay.cli import DEFAULT_LENGTHS, parse_args
from relay.capture_runtime import Capture
from relay.packet_pipeline import WireFeed, WireFilter, load_lengths, pack_move
from relay.xkore_transport import Relay


MAP_NAME = b'morocc.gat'.ljust(16, b'\x00')
MAP_IP = bytes((127, 0, 0, 1))
MAP_PORT = (5121).to_bytes(2, 'little')


def at(x, y):
    return x.to_bytes(2, 'little') + y.to_bytes(2, 'little')


def pkt(pid, body):
    return pid.to_bytes(2, 'little') + body


class PositionPacketDelivery(unittest.TestCase):
    def setUp(self):
        lengths = load_lengths(DEFAULT_LENGTHS)
        for pid, size in ((0x0071, 28), (0x0073, 11), (0x0087, 12),
                          (0x0091, 22), (0x0092, 28), (0x02EB, 13),
                          (0x0A4B, 22), (0x0A4C, 28), (0x0AC7, 156)):
            self.assertEqual(lengths[pid], size, f'missing or wrong map packet length {pid:04x}')
        self.wire = WireFilter(lengths, {0x09FD, 0x09FF})
        self.relay = Relay('offline', 0, autostart=False)
        self.relay.sock = Mock()
        self.relay.generation = 1
        self.feed = WireFeed(self.wire, self.relay, Mock(), lambda _: None, dec=None)
        self.feed.reset_session(epoch=1, generation=1)

    def incoming(self, data, *, conn='map', sock='127.0.0.1:5121'):
        self.feed.on_recv(dict(tag='RECV', sock=sock, conn=conn,
                               C=data.hex(), len=len(data), ts=1234))
        self.assertFalse(self.feed._feed_ready())

    def fragmented(self, data, *, conn='map', sock='127.0.0.1:5121'):
        # TCP can split headers, coordinate words and packet bodies arbitrarily.
        sizes = (1, 2, 3, 1, 5, 2, 11, 4, 1, 7, 3, 19)
        start = 0
        for size in sizes:
            if start >= len(data):
                break
            self.incoming(data[start:start + size], conn=conn, sock=sock)
            start += size
        if start < len(data):
            self.incoming(data[start:], conn=conn, sock=sock)

    def delivered(self):
        frames = [call.args[0] for call in self.relay.sock.sendall.call_args_list]
        for frame in frames:
            self.assertEqual(frame[:1], b'R')
            self.assertEqual(int.from_bytes(frame[1:3], 'little'), len(frame) - 3)
        return b''.join(frame[3:] for frame in frames)

    def test_character_server_map_reference_and_map_login_coordinates(self):
        char_map = pkt(0x0071, bytes((1, 2, 3, 4)) + MAP_NAME + MAP_IP + MAP_PORT)
        map_loaded = pkt(0x0073, (1234).to_bytes(4, 'little') +
                         pack_move(153, 93) + bytes((14, 15)))
        self.assertEqual((len(char_map), len(map_loaded)), (28, 11))
        self.fragmented(char_map, conn='char', sock='127.0.0.1:6121')
        self.fragmented(map_loaded)
        self.assertEqual(self.delivered(), char_map + map_loaded)
        self.assertEqual(self.delivered()[-5:-2], pack_move(153, 93))

    def test_map_changes_and_player_move_preserve_coordinates_and_order(self):
        map_change = pkt(0x0091, MAP_NAME + at(153, 93))
        moved = pkt(0x0087, (42).to_bytes(4, 'little') +
                    bytes.fromhex('fc8d6d0d304f'))
        airship_map_change = pkt(0x0A4B, MAP_NAME + at(154, 94))
        self.fragmented(map_change + moved + airship_map_change)
        self.assertEqual(self.delivered(), map_change + moved + airship_map_change)

    def test_extended_map_loaded_and_two_server_move_variants(self):
        map_loaded = pkt(0x02EB, (5432).to_bytes(4, 'little') +
                         pack_move(153, 93) + bytes((14, 15)) + (0).to_bytes(2, 'little'))
        switched = pkt(0x0092, MAP_NAME + at(153, 93) + MAP_IP + MAP_PORT)
        extended = pkt(0x0AC7, MAP_NAME + at(153, 93) +
                       MAP_IP + MAP_PORT + bytes(128))
        airship = pkt(0x0A4C, MAP_NAME + at(153, 93) + MAP_IP + MAP_PORT)
        self.assertEqual(tuple(map(len, (map_loaded, switched, extended, airship))),
                         (13, 28, 156, 28))
        self.fragmented(map_loaded + switched + extended + airship)
        self.assertEqual(self.delivered(), map_loaded + switched + extended + airship)

    def test_unrecoverable_actor_does_not_drop_following_position_packet(self):
        encrypted_actor = pkt(0x09FF, (8).to_bytes(2, 'little') + b'\x01\x02\x03\x04')
        map_loaded = pkt(0x0073, (1234).to_bytes(4, 'little') +
                         pack_move(153, 93) + bytes((14, 15)))
        self.fragmented(encrypted_actor + map_loaded)
        self.assertEqual(self.delivered(), map_loaded)

    def test_session_change_discards_old_partial_packet_not_new_coordinates(self):
        old = pkt(0x0091, MAP_NAME + at(1, 2))
        self.incoming(old[:5], conn='old-map')
        self.assertEqual(self.delivered(), b'')
        self.feed.reset_session(epoch=2, generation=1)
        new = pkt(0x0091, MAP_NAME + at(153, 93))
        self.fragmented(new, conn='new-map')
        self.assertEqual(self.delivered(), new)


    def test_capture_worker_session_dispatch_preserves_map_position(self):
        # Unlike the other fixtures, this enters via Capture.dispatch: this
        # exercises active-session checks and the actual RECV routing path.
        opts = parse_args(['--config', '/missing/offline.ini', '--inject',
                           '--inject-call', '--move-dispatch', '--action-merge',
                           '--scramble-bp', '18eff2', '--scramble-reg', 'auto',
                           '--no-decrypt-actors', '--no-synth-input'])
        capture = Capture(opts, None, self.relay, self.wire, Mock(), lambda _: None)
        capture.commands.session(True)
        self.assertTrue(capture.commands.active)
        initial = pkt(0x0073, (1).to_bytes(4, 'little') +
                      pack_move(153, 93) + bytes((0, 0)))
        event = dict(tag='RECV', epoch=capture.commands.epoch,
                     sock='127.0.0.1:5121', conn='cookie:map', len=len(initial),
                     C=initial.hex(), ts=1234)
        capture.dispatch(event)
        self.assertFalse(capture.recv_path._feed_ready())
        self.assertEqual(self.delivered(), initial)


if __name__ == '__main__':
    unittest.main()
