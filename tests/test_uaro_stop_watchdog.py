"""Watchdog parsing and safe command-line validation, without signaling a process."""
import importlib.util
from pathlib import Path
from unittest.mock import patch

path = Path(__file__).resolve().parents[1] / 'scripts/watch-uaro-stop.py'
spec = importlib.util.spec_from_file_location('uaro_stop_watchdog', path)
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)

with patch.object(mod.Path, 'read_text', side_effect=['1808818 (uaRO.exe) T 0 0 0', 'uaRO.exe\n']):
    assert mod.process_state(1808818) == ('T', 'uaRO.exe')
with patch.object(mod.Path, 'read_text', side_effect=FileNotFoundError):
    assert mod.process_state(1808818) == (None, None)
print('uaRO stop watchdog parsing PASS')
