import json
import os
import tempfile
import unittest

import _boot  # noqa: F401
from relay.cli import parse_args
from relay.discovery_wizard import DiscoveryWizard, DiscoveryWizardError
from relay.protocol import module_info_msg, trace_msg


class DiscoveryWizardTests(unittest.TestCase):
    def test_protocol_tokens_for_async_correlation(self):
        self.assertEqual(module_info_msg('client.exe', 'abc')['token'], 'abc')
        m = trace_msg(500, 0x400000, 0x500000, interno=True, token='xyz')
        self.assertEqual(m['token'], 'xyz')
        self.assertTrue(m['interno'])
        self.assertEqual((m['ualo'], m['uahi']), ('0x400000', '0x500000'))

    def test_full_wizard_collects_persists_and_ranks(self):
        with tempfile.TemporaryDirectory() as root:
            out = os.path.join(root, 'traces.json')
            printed = []
            wizard = DiscoveryWizard(
                post=lambda _m: None,
                module='protected.exe',
                out_path=out,
                runs=2,
                trace_ms=200,
                arm_delay_ms=0,
                input_fn=lambda: '',
                sleep_fn=lambda _s: None,
                print_fn=printed.append,
            )

            def fake_post(msg):
                token = msg.get('token')
                if msg['type'] == 'module-info':
                    wizard.on_message({
                        'tag': 'MODULE-INFO', 'token': token, 'module': 'protected.exe',
                        'base': '0x400000', 'end': '0x600000', 'size': 0x200000,
                    })
                    return
                self.assertEqual(msg['type'], 'trace')
                calls = ['0x1>u0x90']
                for label, caller in (
                    ('move', '0x10'), ('attack', '0x20'),
                    ('skill_target', '0x30'), ('use_item', '0x40'),
                ):
                    if label in token:
                        calls.append(f'{caller}>u0x500')
                        break
                wizard.on_message({
                    'tag': 'TRACE', 'token': token, 'ms': 200,
                    'bytes': 64, 'chamadas': calls,
                })

            wizard.post = fake_post
            result, result_path = wizard.run()
            self.assertEqual(result['candidates'][0]['target_rva'], 0x500)
            self.assertEqual(result['candidates'][0]['action_count'], 4)
            self.assertTrue(result['promotion_required'])
            self.assertTrue(os.path.exists(out))
            self.assertTrue(result_path.exists())
            with open(out, encoding='utf-8') as f:
                saved = json.load(f)
            self.assertEqual(set(saved), {'baseline', 'move', 'attack', 'skill_target', 'use_item'})
            self.assertTrue(all(len(runs) == 2 for runs in saved.values()))

    def test_unknown_build_profile_mismatch_is_deferred_to_wizard(self):
        with tempfile.TemporaryDirectory() as root:
            exe = os.path.join(root, 'unknown.exe')
            data = bytearray(0x400)
            data[:2] = b'MZ'
            import struct
            struct.pack_into('<I', data, 0x3C, 0x80)
            data[0x80:0x84] = b'PE\0\0'
            struct.pack_into('<HHI', data, 0x84, 0x14C, 0, 1)
            optional = 0x84 + 20
            struct.pack_into('<H', data, optional, 0x10B)
            struct.pack_into('<I', data, optional + 28, 0x400000)
            struct.pack_into('<I', data, optional + 56, 0x9000)
            with open(exe, 'wb') as f:
                f.write(data)
            args = parse_args(['--discovery-wizard', 'auto', '--client-exe', exe])
            self.assertIsNone(args.client_profile_data)
            self.assertTrue(args.client_profile_error)

    def test_agent_error_fails_closed(self):
        wizard = DiscoveryWizard(
            post=lambda _m: None,
            module='protected.exe', out_path='unused.json', runs=2,
            trace_ms=200, arm_delay_ms=0, input_fn=lambda: '', sleep_fn=lambda _s: None,
        )

        def fake_post(msg):
            wizard.on_message({'tag': 'MODULE-INFO', 'token': msg['token'], 'erro': 'module not mapped'})

        wizard.post = fake_post
        with self.assertRaises(DiscoveryWizardError):
            wizard.resolve_module()

    def test_invalid_settings_are_rejected(self):
        with self.assertRaises(ValueError):
            DiscoveryWizard(lambda _m: None, 'x.exe', 'x.json', runs=1)
        with self.assertRaises(ValueError):
            DiscoveryWizard(lambda _m: None, 'x.exe', 'x.json', trace_ms=10)


if __name__ == '__main__':
    unittest.main()
