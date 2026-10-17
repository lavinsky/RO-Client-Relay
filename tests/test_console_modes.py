"""Console verbosity, color policy and redaction without terminal access."""
import contextlib
import io
import os
import pathlib
import sys
import unittest
import tempfile
from types import SimpleNamespace
from unittest.mock import patch
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))
from relay import console


class ConsoleModes(unittest.TestCase):
    def test_capture_log_never_persists_ack_bodies(self):
        for mode in ('normal', 'verbose'):
            with tempfile.NamedTemporaryFile() as f, contextlib.redirect_stdout(io.StringIO()):
                console.configure(SimpleNamespace(console_mode=mode, no_color=True))
                log = console.CaptureLog(f.name)
                log.write(dict(tag='SCRAMBLE',hit='wrote',id=0x437,
                               body='credential',wrote='credential',C='credential'))
                log.write(dict(tag='SENDCALL',hit='sent',data='credential'))
                log.close()
                self.assertNotIn('credential', pathlib.Path(f.name).read_text())

    def render(self, mode, no_color=False, tty=False):
        output = io.StringIO()
        output.isatty = lambda: tty
        message = dict(tag='SEND', id='0064', len=55, C='6400deadbeef', sock='local:6900')
        with contextlib.redirect_stdout(output):
            console.configure(SimpleNamespace(console_mode=mode, no_color=no_color))
            console.show(message)
        self.assertEqual(message['C'], '6400deadbeef')
        return output.getvalue()

    def render_event(self, no_color=False, tty=False, level='stage'):
        output = io.StringIO()
        output.isatty = lambda: tty
        with contextlib.redirect_stdout(output):
            console.configure(SimpleNamespace(console_mode='normal', no_color=no_color))
            console.event('command queued', level)
        return output.getvalue()

    def test_ack_metadata_only_in_both_modes(self):
        for mode in ('normal', 'verbose'):
            for tag, hit in [('SCRAMBLE', 'armed'), ('SCRAMBLE', 'consumed'),
                             ('SCRAMBLE', 'error'), ('SENDCALL', 'sent'),
                             ('MOVE-DISPATCH', 'dispatched'), ('SESSION', 'reset'),
                             ('LATENCY', 'native')]:
                output = io.StringIO()
                with contextlib.redirect_stdout(output):
                    console.configure(SimpleNamespace(console_mode=mode, no_color=True))
                    console.show(dict(tag=tag, hit=hit, id=0x0437, token=5, epoch=2,
                                      elapsed_ms=3, C='deadbeef', P='secret',
                                      body='password', data='credential', e='private'))
                self.assertEqual(output.getvalue(),
                                 f'[{tag}] {hit} id=1079 token=5 epoch=2 elapsed_ms=3\n')

    def test_normal_suppresses_routine_packets(self):
        self.assertEqual(self.render('normal'), '')

    def test_green_requires_explicit_wire_level(self):
        with patch.dict(os.environ, {}, clear=True):
            self.assertNotIn('\033[32m', self.render_event(tty=True))
            self.assertIn('\033[32m', self.render_event(tty=True, level='wire'))

    def test_normal_metadata_and_verbose_redaction(self):
        self.assertNotIn('deadbeef', self.render('normal'))
        self.assertIn('redacted', self.render('verbose'))
        self.assertNotIn('deadbeef', self.render('verbose'))

    def test_color_policy(self):
        with patch.dict(os.environ, {}, clear=True):
            self.assertIn('\033[', self.render_event(tty=True))
            self.assertNotIn('\033[', self.render_event())
            self.assertNotIn('\033[', self.render_event(no_color=True, tty=True))
        with patch.dict(os.environ, {'NO_COLOR': ''}):
            self.assertNotIn('\033[', self.render_event(tty=True))


if __name__ == '__main__':
    unittest.main()
