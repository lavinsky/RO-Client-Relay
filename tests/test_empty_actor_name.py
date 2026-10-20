"""Empty-name 09FF may only come from a causally bounded, fresh ring slot."""
import unittest
from unittest.mock import patch
import _boot
from relay.actors import (ActorDecrypt, actor_name_rejection, copy_validation,
                          fresh_empty_name_actor)
from relay.wire_feed import WireFeed, new_chunk


def wire_and_plain(packet_id=0x09ff, *, name=b'\x00' * 24, object_type=5, gid=b'ABCD'):
    length = 108
    plain = bytearray(length)
    plain[:4] = packet_id.to_bytes(2, 'little') + length.to_bytes(2, 'little')
    plain[4] = object_type
    plain[5:9] = gid
    plain[13:15] = (200).to_bytes(2, 'little')
    plain[-24:] = name
    wire = bytes(plain[:4]) + b'\xe9' * (length - 4)
    return wire, bytes(plain)


def prepared(wire, plain, *, safe=True, changed=True, epoch=1):
    with patch('relay.actors.ProcessMemory'):
        dec = ActorDecrypt(123456)
    dec.base, dec.hi, dec.region, dec.ring_epoch = 0x1000, 0x4000, (0x1000, 0x4000), epoch
    e = new_chunk('map:5121', 'A', [('E', int.from_bytes(wire[:2], 'little'), wire, 0)], 0, 0x40)
    prior = wire if changed else plain
    pre = bytearray(0x40 + len(wire))
    pre[0x40:] = prior
    dec.before(e, (bytes(pre), dec.base) if safe else None)
    dec.read = lambda address, length: plain
    dec.resolve = lambda *args, **kwargs: None
    return dec, e


class EmptyNameRecovery(unittest.TestCase):
    def test_categorical_telemetry_no_raw_name(self):
        self.assertEqual(actor_name_rejection(bytes(24)), 'empty')
        self.assertEqual(actor_name_rejection(b'A\0B' + bytes(21)), 'invalid-padding')
        self.assertEqual(actor_name_rejection(b'A\x81' + bytes(22)), 'invalid-encoding')
        self.assertEqual(actor_name_rejection(b'A\xa7' + bytes(22)), 'forbidden-character')
        self.assertEqual(actor_name_rejection(b'A '.ljust(24, bytes(1))), 'edge-whitespace')
        self.assertEqual(actor_name_rejection(b'Jo\xe3o'.ljust(24, bytes(1))), 'ok')

    def test_strict_copy_and_ring_discovery_still_reject_empty(self):
        wire, plain = wire_and_plain()
        self.assertFalse(copy_validation(wire, plain)['accepted'])
        self.assertTrue(fresh_empty_name_actor(wire, plain))
        dec, e = prepared(wire, plain)
        self.assertFalse(dec.copy_ok(wire, plain))
        self.assertEqual(e['B'][0], wire)

    def test_kafra_with_hash_uses_normal_verified_slot(self):
        name = b'Kafra Employee#prt1'.ljust(24, b'\x00')
        wire, plain = wire_and_plain(name=name)
        dec, e = prepared(wire, plain)
        self.assertTrue(dec.copy_ok(wire, plain))
        t = e['t']
        self.assertIsNone(dec.settle(e, t + .001, .30, settle_wait=.03))
        self.assertEqual(dec.settle(e, t + .045, .30, settle_wait=.03), {0: plain})
        self.assertEqual(e['reasons'][0], 'ok')
        self.assertEqual(dec.stats['ok-fresh'], 1)
        self.assertEqual(dec.stats['ok-fresh-empty-name'], 0)

    def test_fresh_empty_name_on_predicted_slot_accepted(self):
        wire, plain = wire_and_plain()
        dec, e = prepared(wire, plain)
        t = e['t']
        self.assertIsNone(dec.settle(e, t + .001, .30, settle_wait=.03))
        result = dec.settle(e, t + .045, .30, settle_wait=.03)
        self.assertEqual(result, {0: plain})
        self.assertEqual(e['reasons'][0], 'ok-empty-name-fresh')
        self.assertEqual(dec.stats['ok-fresh-empty-name'], 1)
        self.assertEqual(e['name_rejection'][0], 'empty')

    def test_verified_empty_name_is_logged_and_fed_in_original_order(self):
        wire, plain = wire_and_plain()
        dec, e = prepared(wire, plain)
        t = e['t']
        dec.settle(e, t + .001, .30, settle_wait=.03)
        e['res'] = dec.settle(e, t + .045, .30, settle_wait=.03)
        class Log:
            events = None
            def __init__(self):
                self.events = []
            def write(self, event):
                self.events.append(event)
        class Relay:
            def __init__(self):
                self.data = []
            def feed(self, payload):
                self.data.append(payload)
        log, relay = Log(), Relay()
        feeder = WireFeed(None, relay, log, lambda message: None, dec=dec)
        feeder.pending.append(e)
        self.assertFalse(feeder._feed_ready())
        self.assertEqual(relay.data, [plain])
        recovery = next(event for event in log.events if event.get('tag') == 'ACTOR-RECOVERY')
        self.assertEqual(recovery['status'], 'recovered')
        self.assertEqual(recovery['reason'], 'ok-empty-name-fresh')
        self.assertEqual(recovery['name_rejection'], 'empty')

    def test_unsafe_preimage_cannot_trigger_fallback(self):
        wire, plain = wire_and_plain()
        dec, e = prepared(wire, plain, safe=False)
        self.assertEqual(dec.settle(e, e['t'] + .35, .30, settle_wait=0), {0: None})
        self.assertNotIn('ok-empty-name-fresh', e['reasons'][0])

    def test_unchanged_preimage_cannot_trigger_fallback(self):
        wire, plain = wire_and_plain()
        dec, e = prepared(wire, plain, changed=False)
        self.assertEqual(dec.settle(e, e['t'] + .35, .30, settle_wait=0), {0: None})

    def test_mismatched_ring_epoch_cannot_trigger_fallback(self):
        wire, plain = wire_and_plain()
        dec, e = prepared(wire, plain)
        dec.ring_epoch += 1
        self.assertEqual(dec.settle(e, e['t'] + .35, .30, settle_wait=0), {0: None})

    def test_next_recv_excludes_post_recv_live_read(self):
        wire, plain = wire_and_plain()
        dec, e = prepared(wire, plain)
        t = e['t']
        e['ev'][0].append(((t + .025)*1000, plain))
        e['closed'] = (t + .010) * 1000
        self.assertEqual(dec.settle(e, t + .050, .30), {0: None})

    def test_racing_next_recv_excludes_late_read(self):
        wire, plain = wire_and_plain()
        dec, e = prepared(wire, plain)
        t = e['t']
        def receive_while_reading(address, length):
            e['closed'] = (t + .005) * 1000
            return plain
        dec.read = receive_while_reading
        self.assertEqual(dec.settle(e, t + .010, .30, settle_wait=0), {0: None})
        self.assertEqual(dec.stats['ok-fresh-empty-name'], 0)

    def test_same_ring_base_with_new_epoch_is_not_fresh(self):
        wire, plain = wire_and_plain()
        dec, e = prepared(wire, plain)
        dec.ring_epoch += 1
        self.assertEqual(dec.settle(e, e['t']+.35, .30, settle_wait=0), {0: None})

    def test_only_empty_name_09ff_may_be_relaxed(self):
        for kwargs in ({'packet_id': 0x09fd}, {'name': b'Bad\x01' + bytes(20)},
                       {'object_type': 13}, {'gid': bytes(4)}):
            with self.subTest(**kwargs):
                wire, plain = wire_and_plain(**kwargs)
                self.assertFalse(fresh_empty_name_actor(wire, plain))
                dec, e = prepared(wire, plain)
                self.assertEqual(dec.settle(e, e['t']+.35, .30, settle_wait=0), {0: None})


if __name__ == '__main__':
    unittest.main()
