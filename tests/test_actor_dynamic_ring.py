"""Dynamic ring discovery must never trust a persisted address."""
import collections
import tempfile
import threading
import time
import unittest
from unittest.mock import patch
import _boot
from relay.actors import ActorDecrypt, copy_validation


def actor(name=b'Fabre', gid=b'ABCD'):
    b = bytearray(108)
    b[:4] = bytes.fromhex('ff096c00')
    b[4] = 5
    b[5:9] = gid
    b[13:15] = (200).to_bytes(2, 'little')
    b[-24:] = name.ljust(24, bytes(1))
    return bytes(b)


class DynamicRingTests(unittest.TestCase):
    def test_stale_cache_not_accepted_on_startup(self):
        with tempfile.TemporaryDirectory() as tmp:
            with patch('relay.actors.ProcessMemory') as memory:
                dec = ActorDecrypt(999999)
                self.assertIsNone(dec.region)
                self.assertIsNone(dec.base)
                self.assertEqual(dec.stats['ring-discovered'], 0)
                memory.assert_called_once_with(999999)

    def _memory(self, dec, mapping_lo, ringbase, blob, mapping_hi=None):
        hi = mapping_hi or mapping_lo + 0x5000
        memory = bytearray(hi-mapping_lo)
        offset = ringbase + 0x40 - mapping_lo
        memory[offset:offset+len(blob)] = blob
        dec.read = lambda addr, n: (bytes(memory[addr-mapping_lo:addr-mapping_lo+n])
                                    if mapping_lo <= addr < hi else b'')
        return [(mapping_lo, hi, 'rw')]

    def test_ring_mapping_gate_allows_wine_anonymous_rwx_and_rejects_code(self):
        from unittest.mock import mock_open
        with patch('relay.actors.ProcessMemory'):
            dec = ActorDecrypt(999999)
        # Real uaRO ring: Wine's anonymous RWX mapping is legitimate.
        sample = '231f0000-234a2000 rwxp 00000000 00:00 0\n'
        with patch('builtins.open', mock_open(read_data=sample)):
            self.assertTrue(dec._ring_mapping_allowed(0x23410000, 0x23414080))
            self.assertFalse(dec._ring_mapping_allowed(0x23410001, 0x23414080))
        # Historical false discovery inside anonymous PE image: unaligned.
        sample = '00401000-01607000 rwxp 00000000 00:00 0\n'
        with patch('builtins.open', mock_open(read_data=sample)):
            self.assertFalse(dec._ring_mapping_allowed(0x66b20d, 0x66f20d))
        # File-backed mappings cannot contain the ephemeral RX ring.
        sample = '20000000-20010000 rwxp 00000000 00:01 17 /tmp/executable\n'
        with patch('builtins.open', mock_open(read_data=sample)):
            self.assertFalse(dec._ring_mapping_allowed(0x20001000, 0x20005000))
        sample = '20000000-20010000 rw-p 00000000 00:00 0\n'
        with patch('builtins.open', mock_open(read_data=sample)):
            self.assertTrue(dec._ring_mapping_allowed(0x20001000, 0x20005000))
            self.assertFalse(dec._ring_mapping_allowed(0x2000f000, 0x20011000))

    def test_quick_discover_from_current_chunk_and_throttle(self):
        with patch('relay.actors.ProcessMemory'):
            dec = ActorDecrypt(999999)
        C = bytes(range(64)) + actor() + bytes(range(64))
        mask = [(68, 64 + 108)]
        plain = actor(b'Poring')
        ring = C[:68] + plain[4:] + C[64 + 108:]
        maps = self._memory(dec, 0x1000, 0x1000, ring)
        found = []
        dec.on_ring = lambda x: found.append(x)
        with patch('relay.actors.regions', return_value=maps), patch.object(dec, '_ring_mapping_allowed', return_value=True):
            self.assertTrue(dec.quick_discover('conn', C, mask, [(64,C[64:172])]))
        self.assertEqual(dec.base, 0x1000)
        self.assertEqual(found, [0x1000])
        self.assertEqual(dec.stats['ring-discovered'], 1)

    def test_isolated_09ff_with_only_four_clear_bytes_discovers_ring(self):
        with patch('relay.actors.ProcessMemory'):
            dec = ActorDecrypt(999999)
        wire = actor(b'Cipher')[:4] + bytes([0xe7]) * 104
        plaintext = actor(b'Poring')
        maps = self._memory(dec, 0x2000, 0x2700, plaintext)
        with patch('relay.actors.regions', return_value=maps), patch.object(dec, '_ring_mapping_allowed', return_value=True):
            self.assertTrue(dec.quick_discover('conn', wire, [(4, 108)], [(0, wire)]))
        self.assertEqual(dec.base, 0x2700)
        self.assertEqual(dec.stats['ring-quick-actor-verified'], 1)

    def test_sparse_header_without_verified_plaintext_must_not_pick_ring(self):
        with patch('relay.actors.ProcessMemory'):
            dec = ActorDecrypt(999999)
        wire = actor()[:4] + bytes([0xe7]) * 104
        maps = self._memory(dec, 0x2000, 0x2500, wire)
        with patch('relay.actors.regions', return_value=maps), patch.object(dec, '_ring_mapping_allowed', return_value=True):
            self.assertFalse(dec.quick_discover('conn', wire, [(4, 108)], [(0, wire)]))
        self.assertIsNone(dec.base)

    def test_sparse_09fd_also_discovers_valid_actor(self):
        with patch('relay.actors.ProcessMemory'):
            dec = ActorDecrypt(999999)
        wire = bytearray(actor(b'Zipper')) + bytes(6)
        wire[:4] = bytes.fromhex('fd097200')
        plaintext = bytearray(actor(b'Peach')) + bytes(6)
        plaintext[-24:] = b'Peach'.ljust(24, b'\x00')
        plaintext[:4] = wire[:4]
        wire[4:] = bytes([0xeb]) * (len(wire) - 4)
        maps = self._memory(dec, 0x3000, 0x3700, plaintext)
        with patch('relay.actors.regions', return_value=maps), patch.object(dec, '_ring_mapping_allowed', return_value=True):
            self.assertTrue(dec.quick_discover('conn', bytes(wire), [(4,114)], [(0,bytes(wire))]))
        self.assertEqual(dec.base, 0x3700)

    def test_full_discover_infers_internal_base_not_mapping_start(self):
        with patch('relay.actors.ProcessMemory'):
            dec = ActorDecrypt(999999)
        wire = actor(b'Cipher')[:4] + bytes([0xe3])*104
        plaintext = actor(b'Peach')
        mapping_lo, ringbase, mapping_hi = 0x1000, 0x2800, 0x6000
        mem = bytearray(mapping_hi - mapping_lo)
        mem[ringbase + 0x40 - mapping_lo:ringbase + 0x40 - mapping_lo+108] = plaintext
        dec.read = lambda addr,n: bytes(mem[addr-mapping_lo:addr-mapping_lo+n])
        # Valid neighbor context outside the encrypted actor body.
        dec.stream['A'] = [0, wire]
        dec.spans['A'].append((4,108))
        dec._ctx = lambda buf, i, conn, off, L: (24, 0)
        with patch('relay.actors.regions', return_value=[(mapping_lo,mapping_hi,'rw')]), patch.object(dec, '_ring_mapping_allowed', return_value=True):
            self.assertTrue(dec.discover('A',wire,0,0))
        self.assertEqual(dec.base, ringbase)
        self.assertEqual(dec.region, (ringbase,mapping_hi))

    def test_full_discover_uses_bounded_reads_and_finds_cross_window_packet(self):
        with patch('relay.actors.ProcessMemory'):
            dec = ActorDecrypt(999999)
        wire = actor(b'Cipher')[:4] + bytes([0xe3]) * 104
        plaintext = actor(b'Boundary')
        mapping_lo = 0x1000
        mapping_hi = mapping_lo + dec.SCAN_WINDOW * 2 + 0x2000
        slot = mapping_lo + dec.SCAN_WINDOW - 50
        ringbase = slot - dec.HDR
        mem = bytearray(mapping_hi - mapping_lo)
        rel = slot - mapping_lo
        mem[rel:rel + len(plaintext)] = plaintext
        reads = []

        def read(addr, size):
            reads.append(size)
            start = addr - mapping_lo
            return bytes(mem[start:start + size])

        dec.read = read
        dec.stream['A'] = [0, wire]
        dec.spans['A'].append((4, 108))
        dec._ctx = lambda buf, i, conn, off, L: (24, 0)
        with patch('relay.actors.regions', return_value=[(mapping_lo, mapping_hi, 'rw')]), \
                patch.object(dec, '_ring_mapping_allowed', return_value=True):
            self.assertTrue(dec.discover('A', wire, 0, 0))
        self.assertEqual(dec.base, ringbase)
        self.assertTrue(reads)
        self.assertLessEqual(max(reads), dec.SCAN_WINDOW)
        self.assertGreater(len(reads), 1)

    def test_first_and_last_slot_read_preserved_without_plaintext(self):
        from relay.wire_feed import new_chunk
        with patch('relay.actors.ProcessMemory'):
            dec = ActorDecrypt(999999)
        dec.base, dec.hi, dec.region = 0x1000, 0x8000, (0x1000, 0x8000)
        plain = actor(b'Peach')
        wire = plain[:4] + bytes([0xee]) * 104
        e = new_chunk('server:5121', 'A', [('E', 0x09ff, wire, 0)], 0, 0x40)
        e['B'][0] = wire
        data = iter((wire, plain, plain))
        dec.read = lambda addr, n: next(data)
        t = e['t']
        self.assertIsNone(dec.settle(e, t + 0.001, 0.30, settle_wait=0.03))
        self.assertIsNone(dec.settle(e, t + 0.010, 0.30, settle_wait=0.03))
        result = dec.settle(e, t + 0.050, 0.30, settle_wait=0.03)
        self.assertEqual(result, {0: plain})
        self.assertFalse(e['first_read'][0]['copy_ok'])
        self.assertTrue(e['last_read'][0]['copy_ok'])
        self.assertEqual(e['first_read'][0]['bytes_read'], 108)
        self.assertLess(e['first_read'][0]['ms'], e['last_read'][0]['ms'])
        self.assertEqual(e['candidate_seen'][0], True)
        self.assertNotIn('plaintext', str(e['first_read']))

    def test_immobile_actor_walk_speed_zero_and_under_twenty(self):
        with patch('relay.actors.ProcessMemory'):
            dec = ActorDecrypt(999999)
        for speed in (0, 1, 19, 20, 1000, 2000):
            for pid, length in ((0x09ff, 108), (0x09fd, 114)):
                with self.subTest(speed=speed, pid=hex(pid)):
                    plain = bytearray(actor(b'Immobile')) + bytearray(length - 108)
                    plain[0:4] = pid.to_bytes(2, 'little') + length.to_bytes(2, 'little')
                    plain[13:15] = speed.to_bytes(2, 'little')
                    wire = bytes(plain[:4]) + bytes([0xe7]) * (length - 4)
                    self.assertTrue(dec.copy_ok(wire, bytes(plain)))
                    result = copy_validation(wire, bytes(plain))
                    self.assertTrue(result['walk_speed_ok'])
                    self.assertTrue(result['accepted'])
        plain[13:15] = (2001).to_bytes(2, 'little')
        self.assertFalse(dec.copy_ok(wire, bytes(plain)))
        self.assertFalse(copy_validation(wire, bytes(plain))['walk_speed_ok'])

    def test_copy_validation_matches_existing_rules_without_leaking_bytes(self):
        with patch('relay.actors.ProcessMemory'):
            dec = ActorDecrypt(999999)
        wire = actor()[:4] + b'\xe4' * 104
        good = actor(b'Peach')
        variants = {
            'good': good,
            'unchanged': wire,
            'wrong_header': b'\x00' + good[1:],
            'wrong_size': good[:-1],
            'bad_type': good[:4] + b'\xff' + good[5:],
            'bad_speed': good[:13] + (2001).to_bytes(2, 'little') + good[15:],
            'bad_name': good[:-24] + b'A\x00B' + bytes(21),
            'bad_high_byte_name': good[:-24] + b'Fake\xa7\xa5'.ljust(24, b'\0'),
        }
        for label, sample in variants.items():
            with self.subTest(label=label):
                details = copy_validation(wire, sample)
                self.assertEqual(details['accepted'], dec.copy_ok(wire, sample))
                self.assertTrue(all(v is None or isinstance(v, bool)
                                    for k,v in details.items() if k != 'walk_speed_value'))
        self.assertTrue(copy_validation(wire, variants['good'])['accepted'])
        self.assertEqual(copy_validation(wire, variants['good'])['walk_speed_value'], 200)
        self.assertEqual(copy_validation(wire, variants['bad_speed'])['walk_speed_value'], 2001)
        for label in ('unchanged','wrong_header','wrong_size','bad_type','bad_speed','bad_name','bad_high_byte_name'):
            self.assertFalse(copy_validation(wire, variants[label])['accepted'], label)
        fixed = bytes.fromhex('290263ef2000') + bytes.fromhex('010203040506070809')
        decrypted = fixed[:6] + bytes(9)
        self.assertEqual(copy_validation(fixed, decrypted)['accepted'], dec.copy_ok(fixed, decrypted))
        self.assertIsNone(copy_validation(fixed, decrypted)['walk_speed_ok'])

    def test_actor_delay_default_300ms(self):
        from relay.cli import parse_args
        self.assertEqual(parse_args(['--config', '/nonexistent', '--no-inject']).actor_delay, .30)

    def test_invalidated_ring_can_be_rediscovered(self):
        with patch('relay.actors.ProcessMemory'):
            dec = ActorDecrypt(999999)
        dec.base = 0x1000
        dec.hi = 0x5000
        dec.region = (dec.base, dec.hi)
        dec.fails = dec.REDISCOVER_AFTER - 1
        dec.stream['conn'] = [0, bytes(200)]
        dec.spans = collections.defaultdict(lambda: collections.deque(maxlen=256))
        dec._best = lambda *args, **kwargs: []
        dec.read = lambda at, n: bytes(n)
        pkt = actor()
        dec.resolve('conn', 0x09ff, pkt, 0, 0, exp_d=0x40, live=True)
        self.assertIsNone(dec.base)
        self.assertIsNone(dec.region)
        self.assertEqual(dec.stats['ring-invalidated'], 1)
        self.assertEqual(dec.fails, 0)
        self.assertFalse(dec.quick_busy)
        with patch('relay.actors.threading.Thread') as thread:
            dec.start_quick_discover('conn', pkt, [('E',0x09ff,pkt,0)], 0)
            self.assertTrue(dec.quick_busy)
            thread.return_value.start.assert_called_once()


if __name__ == '__main__':
    unittest.main(verbosity=2)
