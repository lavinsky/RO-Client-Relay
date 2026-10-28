import json
import os
import struct
import tempfile
import unittest

import _boot  # noqa: F401
from relay.client_discovery_fallback import (
    dynamic_fallback_plan,
    profile_for_executable,
    rank_behavioral_dispatchers,
    stable_edges,
)
from relay.client_profile import ClientFingerprint


def make_pe(path):
    data = bytearray(0x400)
    data[:2] = b'MZ'
    struct.pack_into('<I', data, 0x3C, 0x80)
    data[0x80:0x84] = b'PE\0\0'
    struct.pack_into('<HHI', data, 0x84, 0x14C, 0, 123)
    optional = 0x84 + 20
    struct.pack_into('<H', data, optional, 0x10B)
    struct.pack_into('<I', data, optional + 28, 0x400000)
    struct.pack_into('<I', data, optional + 56, 0x9000)
    with open(path, 'wb') as f:
        f.write(data)


class DiscoveryFallbackTests(unittest.TestCase):
    def test_stable_edges_require_repetition(self):
        runs = [
            ['0x10>u0x20', '0x30>u0x40'],
            ['0x10>u0x20'],
            ['0x10>u0x20', '0x50>u0x60'],
        ]
        self.assertEqual(stable_edges(runs), {(0x10, 0x20)})

    def test_behavioral_ranking_subtracts_idle_and_finds_shared_target(self):
        idle = ['0x1>u0x90']
        traces = {
            'baseline': [idle, idle, idle],
            'move': [
                idle + ['0x10>u0x500', '0x11>u0x111'],
                idle + ['0x10>u0x500'],
                idle + ['0x10>u0x500'],
            ],
            'attack': [
                idle + ['0x20>u0x500'],
                idle + ['0x20>u0x500'],
                idle + ['0x20>u0x500', '0x21>u0x222'],
            ],
            'skill_target': [
                idle + ['0x30>u0x500'],
                idle + ['0x30>u0x500'],
                idle + ['0x30>u0x500'],
            ],
        }
        ranked = rank_behavioral_dispatchers(traces)
        self.assertTrue(ranked)
        self.assertEqual(ranked[0]['target_rva'], 0x500)
        self.assertEqual(ranked[0]['action_count'], 3)
        self.assertEqual(ranked[0]['caller_count'], 3)
        self.assertNotIn(0x90, [c['target_rva'] for c in ranked])

    def test_exact_profile_is_a_safe_fallback(self):
        with tempfile.TemporaryDirectory() as root:
            exe = os.path.join(root, 'client.exe')
            make_pe(exe)
            fp = ClientFingerprint.from_file(exe)
            with open(os.path.join(root, 'known.json'), 'w', encoding='utf-8') as f:
                json.dump({
                    'name': 'known build',
                    'fingerprint': {'sha256': fp.sha256},
                    'native': {'game_mode': {'send_msg_rva': '0x1234'}},
                }, f)
            profile = profile_for_executable(exe, root)
            self.assertIsNotNone(profile)
            self.assertEqual(profile.name, 'known build')
            self.assertEqual(profile.native_int('game_mode', 'send_msg_rva'), 0x1234)

    def test_plan_fails_closed_when_virtualization_hides_dispatcher(self):
        plan = dynamic_fallback_plan()
        self.assertEqual(plan['mode'], 'behavioral-passive')
        self.assertEqual(plan['last_resort']['mode'], 'per-action-adapters')
        self.assertIn('never auto-call', plan['promotion_rule'])


if __name__ == '__main__':
    unittest.main()
