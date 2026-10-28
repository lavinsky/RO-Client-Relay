import os
import tempfile
import unittest

import _boot  # noqa: F401
from relay.agent import _acquire_port_lock


class AgentSingletonTests(unittest.TestCase):
    def test_same_port_cannot_be_locked_twice_and_releases(self):
        old = os.environ.get('XDG_RUNTIME_DIR')
        with tempfile.TemporaryDirectory() as root:
            os.environ['XDG_RUNTIME_DIR'] = root
            first = _acquire_port_lock(27053)
            try:
                with self.assertRaises(SystemExit):
                    _acquire_port_lock(27053)
            finally:
                first.close()
            second = _acquire_port_lock(27053)
            second.close()
        if old is None:
            os.environ.pop('XDG_RUNTIME_DIR', None)
        else:
            os.environ['XDG_RUNTIME_DIR'] = old

    def test_different_ports_can_coexist(self):
        old = os.environ.get('XDG_RUNTIME_DIR')
        with tempfile.TemporaryDirectory() as root:
            os.environ['XDG_RUNTIME_DIR'] = root
            a = _acquire_port_lock(27052)
            b = _acquire_port_lock(27053)
            a.close(); b.close()
        if old is None:
            os.environ.pop('XDG_RUNTIME_DIR', None)
        else:
            os.environ['XDG_RUNTIME_DIR'] = old


if __name__ == '__main__':
    unittest.main()
