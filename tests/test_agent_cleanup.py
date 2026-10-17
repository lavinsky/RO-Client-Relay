"""Offline regressions for native acknowledgement and Frida teardown safety."""
import contextlib
import io
import pathlib
import sys
import unittest
from types import SimpleNamespace

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))

from relay.client_dispatch import CommandPipeline
from relay.frida_bridge import Agent


class InvalidOperationError(Exception):
    """Offline stand-in for the Frida exception thrown after script detach."""


class TeardownTests(unittest.TestCase):
    def make_agent(self, dispose, unload):
        agent = Agent.__new__(Agent)  # no Frida process or network connection
        agent._frida = SimpleNamespace(InvalidOperationError=InvalidOperationError)
        agent.script = SimpleNamespace(
            exports_sync=SimpleNamespace(dispose=dispose),
            unload=unload,
        )
        return agent

    def test_dispose_happens_before_script_unload(self):
        calls = []
        agent = self.make_agent(
            lambda: calls.append('dispose'),
            lambda: calls.append('unload'),
        )
        agent.unload()
        self.assertEqual(calls, ['dispose', 'unload'])

    def test_dispose_failure_still_unloads_without_leaking_exception_text(self):
        calls = []

        def dispose():
            calls.append('dispose')
            raise RuntimeError('private fixture data')

        agent = self.make_agent(dispose, lambda: calls.append('unload'))
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            agent.unload()
        self.assertEqual(calls, ['dispose', 'unload'])
        self.assertIn('RuntimeError', output.getvalue())
        self.assertNotIn('private fixture data', output.getvalue())

    def test_unload_after_detach_is_safe(self):
        calls = []

        def unload():
            calls.append('unload')
            raise InvalidOperationError('already detached')

        agent = self.make_agent(lambda: calls.append('dispose'), unload)
        agent.unload()
        self.assertEqual(calls, ['dispose', 'unload'])


class ReadinessTests(unittest.TestCase):
    def test_duplicate_armed_ack_cannot_repeat_synthetic_key(self):
        dispatches, keypresses, logs = [], [], []
        pipeline = CommandPipeline(
            lambda cmd: (dispatches.append(cmd), True)[1],
            lambda epoch, active: None,
            logs.append,
            armed=lambda event: (keypresses.append(event['token']), True)[1],
        )
        pipeline.session(True)
        first, second = bytes.fromhex('37040102030407'), bytes.fromhex('38040a001c0001020304')
        self.assertTrue(pipeline.accept(first, 'S'))
        self.assertTrue(pipeline.accept(second, 'S'))
        token, epoch = pipeline.current['token'], pipeline.epoch
        armed = dict(tag='SCRAMBLE', hit='armed', id=0x0437, token=token, epoch=epoch)
        self.assertTrue(pipeline.observe(dict(armed)))
        self.assertTrue(pipeline.observe(dict(armed)))
        self.assertEqual(keypresses, [token])
        self.assertEqual(len(dispatches), 1)
        self.assertEqual(pipeline.summary()['post_to_armed_ms']['n'], 1)
        pipeline.observe(dict(tag='INPUT', hit='released', token=token, epoch=epoch))
        self.assertEqual(len(dispatches), 1)
        pipeline.observe(dict(tag='SCRAMBLE', hit='consumed', token=token, epoch=epoch))
        self.assertEqual(len(dispatches), 2)
        self.assertEqual(dispatches[1]['payload'], second)


if __name__ == '__main__':
    unittest.main()
