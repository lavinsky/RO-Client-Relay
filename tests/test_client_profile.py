import json
import os
import struct
import tempfile
import unittest

import _boot  # noqa: F401
from relay.client_profile import ClientFingerprint, ClientProfile, ProfileError
from relay.cli import parse_args
from relay.writeback import WriteBack


def make_pe(path, *, timestamp=123, image_base=0x400000, size_of_image=0x9000):
    data = bytearray(0x400)
    data[:2] = b'MZ'
    struct.pack_into('<I', data, 0x3C, 0x80)
    data[0x80:0x84] = b'PE\0\0'
    struct.pack_into('<HHI', data, 0x84, 0x14C, 3, timestamp)
    optional = 0x84 + 20
    struct.pack_into('<H', data, optional, 0x10B)
    struct.pack_into('<I', data, optional + 28, image_base)
    struct.pack_into('<I', data, optional + 56, size_of_image)
    with open(path, 'wb') as f:
        f.write(data)


class ClientProfileTests(unittest.TestCase):
    def test_fingerprint_reads_pe_metadata(self):
        with tempfile.TemporaryDirectory() as root:
            exe = os.path.join(root, 'client.exe')
            make_pe(exe)
            fp = ClientFingerprint.from_file(exe)
            self.assertEqual(fp.size, 0x400)
            self.assertEqual(fp.machine, 0x14C)
            self.assertEqual(fp.pe_timestamp, 123)
            self.assertEqual(fp.image_base, 0x400000)
            self.assertEqual(fp.size_of_image, 0x9000)
            self.assertEqual(len(fp.sha256), 64)

    def test_profile_verifies_and_rejects_other_build(self):
        with tempfile.TemporaryDirectory() as root:
            exe = os.path.join(root, 'client.exe')
            make_pe(exe)
            fp = ClientFingerprint.from_file(exe)
            profile_path = os.path.join(root, 'profile.json')
            with open(profile_path, 'w', encoding='utf-8') as f:
                json.dump({
                    'name': 'fixture',
                    'fingerprint': {
                        'sha256': fp.sha256,
                        'machine': '0x14c',
                        'image_base': '0x400000',
                    },
                    'native': {},
                }, f)
            profile = ClientProfile.load(profile_path)
            self.assertEqual(profile.verify_executable(exe), fp)

            make_pe(exe, timestamp=456)
            with self.assertRaises(ProfileError):
                profile.verify_executable(exe)

    def test_default_profile_supplies_native_offsets_without_core_hardcodes(self):
        args = parse_args([])
        self.assertEqual(args.sendpacket_rva, '816640')
        self.assertEqual(args.sendpacket_module, 'uaRO.exe')
        self.assertEqual(args.scramble_bp, '18eff2')
        self.assertEqual(args.move_dispatch_ptr, '')
        self.assertEqual(args.move_dispatch_site, '')

        wb = WriteBack.__new__(WriteBack)
        wb.opts = args
        game_mode = args.client_profile_data.native_group('game_mode')
        self.assertEqual(game_mode['actions']['attack']['send_msg_id'], 137)
        self.assertEqual(game_mode['actions']['move']['send_msg_id'], 138)
        self.assertEqual(game_mode['actions']['skill_target']['send_msg_id'], 69)
        self.assertEqual(game_mode['actions']['skill_ground']['send_msg_id'], 70)
        self.assertEqual(game_mode['actions']['use_item']['send_msg_id'], 27)

        native = wb._move_dispatch_native()
        self.assertEqual(native['dispatcherRva'], 0x9473B0)
        self.assertEqual(native['safePointRva'], 0xDCBA0)
        self.assertEqual(native['managerRva'], 0xE13338)
        self.assertEqual(native['retAnchorRva'], 0x947E61)
        self.assertEqual(native['receiverOffset'], 0x10A90)
        self.assertEqual(native['receiverVslot'], 6)
        self.assertEqual(native['dispatcherVslot'], 2)

        gepard = wb._gepard_dispatch_native()
        self.assertEqual(gepard['entryOffset'], 0xF07FEF)
        self.assertEqual(gepard['callsiteOffset'], 0xA23D78)
        self.assertEqual(gepard['safePointRva'], 0xDCBA0)
        self.assertEqual(gepard['sendMsgRva'], 0x886740)
        self.assertEqual(gepard['gameModeVtableRva'], 0xC904B8)
        self.assertEqual(gepard['moveSendMsgId'], 138)

    def test_invalid_pe_and_profile_fail_closed(self):
        with tempfile.TemporaryDirectory() as root:
            bad = os.path.join(root, 'bad.exe')
            with open(bad, 'wb') as f:
                f.write(b'not a pe')
            with self.assertRaises(ProfileError):
                ClientFingerprint.from_file(bad)

            profile_path = os.path.join(root, 'profile.json')
            with open(profile_path, 'w', encoding='utf-8') as f:
                f.write('{"name":"missing fingerprint"}')
            with self.assertRaises(ProfileError):
                ClientProfile.load(profile_path)


if __name__ == '__main__':
    unittest.main()
