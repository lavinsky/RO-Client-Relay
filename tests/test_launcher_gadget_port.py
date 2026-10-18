"""Offline regression: the launcher must not force a stale Gadget port."""
import os
import pathlib
import subprocess
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
LAUNCHER = ROOT / "research" / "action_0437_0438" / "run_action_merge.sh"


class GadgetPortLauncherTests(unittest.TestCase):
    def launcher_args(self, *args):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            fake_python = root / "fake-frida-python"
            fake_python.write_text('#!/bin/sh\nprintf "CAPTURE_ARGS:"\nprintf "<%s>" "$@"\nprintf "\\n"\n')
            fake_python.chmod(0o755)
            fake_tail = root / "tail"
            fake_tail.write_text("#!/bin/sh\nexit 0\n")
            fake_tail.chmod(0o755)
            env = os.environ.copy()
            env["FRIDA_PY"] = str(fake_python)
            env["PATH"] = str(root) + os.pathsep + env.get("PATH", "")
            result = subprocess.run(["bash", str(LAUNCHER), *args],
                                    env=env, text=True, capture_output=True, timeout=10)
            self.assertEqual(result.returncode, 0, result.stderr)
            lines = [line for line in result.stdout.splitlines()
                     if line.startswith("CAPTURE_ARGS:")]
            self.assertEqual(len(lines), 1, result.stdout)
            return lines[0]

    def test_default_lets_agent_auto_detect_port(self):
        args = self.launcher_args()
        self.assertNotIn("<--port>", args)
        # Operational defaults now live in relay_capture.conf, not launcher CLI flags.
        import sys
        sys.path.insert(0, str(ROOT))
        from relay.cli import parse_args
        opts = parse_args([])
        self.assertTrue(opts.move_dispatch)
        self.assertTrue(opts.action_merge)
        self.assertTrue(opts.synth_input)
        self.assertTrue(opts.egress_queue)
        self.assertNotIn("<--move-dispatch>", args)
        # Egress queue is optional in the local launcher; test only Gadget discovery.

    def test_explicit_port_override_is_preserved(self):
        args = self.launcher_args("--port", "27053")
        self.assertIn("<--port><27053>", args)


if __name__ == "__main__":
    unittest.main()
