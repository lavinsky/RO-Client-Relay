"""Console verbosity is presentation-only; JSONL remains complete."""
import contextlib
import io
import json
import os
import tempfile
import unittest
import _boot
from relay.cli import parse_args
from relay.console import CaptureLog, _FilteredStdout, concise_line, show

class ConsoleVerboseTests(unittest.TestCase):
    def test_config_and_cli_override(self):
        self.assertFalse(parse_args([]).verbose)
        self.assertTrue(parse_args(['--verbose']).verbose)
        self.assertFalse(parse_args(['--verbose', '--no-verbose']).verbose)

    def test_line_filter(self):
        self.assertFalse(concise_line('[inject] inbound id=0x0437 len=7 -> SendPacket'))
        self.assertFalse(concise_line("[inject] skip typ='R' len=7 (need an 'S' packet with an id)"))
        self.assertTrue(concise_line('[!] critical warning'))
        self.assertTrue(concise_line('[relay] connection dropped; will reconnect'))
        self.assertTrue(concise_line('[egress] drop 0x035f (stale)'))
        self.assertTrue(concise_line('[actor] decrypted recv ring: 0x1000-0x2000'))

    def test_stream_fragmentation(self):
        output = io.StringIO()
        filt = _FilteredStdout(output)
        filt.write('[inject] inbound abc')
        filt.write('\n[!] important\n')
        self.assertEqual(output.getvalue(), '[!] important\n')

    def test_jsonl_unchanged_in_quiet_mode(self):
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, 'log.jsonl')
            with contextlib.redirect_stdout(io.StringIO()) as output:
                log = CaptureLog(path, verbose=False)
                log.write({'tag':'RECV-WIRE','id':'09ff','C':'09ffdeadbeef','len':6})
                log.write({'tag':'RECV-PLAIN-UNAVAILABLE','id':'09ff'})
                log.f.close()
            with open(path) as captured:
                lines = [json.loads(line) for line in captured]
            self.assertEqual(len(lines), 2)
            self.assertEqual(lines[0]['C'], '09ffdeadbeef')
            self.assertNotIn('deadbeef', output.getvalue())
            self.assertIn('indisponível', output.getvalue())

if __name__ == '__main__':
    unittest.main()
