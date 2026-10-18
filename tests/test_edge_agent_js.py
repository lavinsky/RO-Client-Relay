"""Agent message contracts and JS parse validation. No Frida attach or process memory."""
import io
import shutil
import subprocess
import sys
import unittest
from contextlib import redirect_stdout
from unittest.mock import patch, mock_open
import _boot
from relay.agent import Agent, AGENT_JS, gadget_ports, pick_port, pid_of_port


class AgentAndJSContracts(unittest.TestCase):
    def test_frida_agent_js_parses_without_runtime(self):
        node=shutil.which('node')
        if not node:
            self.skipTest('node not installed; Frida script syntax cannot be checked')
        r=subprocess.run([node,'--check',AGENT_JS],capture_output=True,text=True,timeout=20)
        self.assertEqual(r.returncode,0,r.stderr)

    def test_agent_message_bytes_attach_only_on_send(self):
        delivered=[]
        a=Agent.__new__(Agent)
        a._on_message=delivered.append
        m={'type':'send','payload':{'tag':'RECV','sock':'host:5121'}}
        a._message(m,b'abc')
        self.assertEqual(delivered[0]['data'],b'abc')
        with redirect_stdout(io.StringIO()):
            a._message({'type':'error','description':'mock syntax issue'},None)
        self.assertEqual(len(delivered),1)

    def test_gadget_discovery_filters_range_and_pids(self):
        mock_lines=('LISTEN 0 4096 127.0.0.1:27052 0.0.0.0:* users:(("foo",pid=131,fd=7))\n'
                    'LISTEN 0 4096 127.0.0.1:27101 0.0.0.0:* users:(("bar",pid=132,fd=7))\n'
                    'LISTEN 0 4096 127.0.0.1:27053 0.0.0.0:* users:(("uaRO",pid=133,fd=7))\n')
        with patch('relay.agent.subprocess.run',return_value=type('Proc',(),{'stdout':mock_lines})()), \
             patch('builtins.open',mock_open(read_data=b'/games/uaRO.exe\x00--arg\x00')):
            ports=gadget_ports()
        self.assertEqual([(port,pid) for port,pid,_ in ports],[(27052,131),(27053,133)])

    def test_pick_port_chooses_exact_game_process(self):
        with patch('relay.agent.gadget_ports',return_value=[
            (27052,41,'/other/uaRO.exe-helper'),
            (27053,42,'Z:\\games\\uaRO.exe'),
            (27054,43,'/other/uaRO2.exe')]):
            self.assertEqual(pick_port('uaRO.exe'),27053)
        with patch('relay.agent.gadget_ports',return_value=[(27052,1,'other.exe')]):
            with self.assertRaises(SystemExit):
                pick_port('uaRO.exe')

    def test_port_pid_identity(self):
        with patch('relay.agent.gadget_ports',return_value=[(27052,44,'a'),(27053,45,'b')]):
            self.assertEqual(pid_of_port(27053),45)
            self.assertIsNone(pid_of_port(27100))


if __name__=='__main__':
    unittest.main(verbosity=2)
