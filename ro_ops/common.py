"""Helpers somente-leitura compartilhados (raiz do repo, git, sha256, /proc)."""
import hashlib
import subprocess
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def utc_now():
    return datetime.now(timezone.utc).isoformat()


def git(*args, cwd=ROOT):
    """stdout de git ou None (git ausente/erro). Nunca levanta."""
    try:
        r = subprocess.run(["git", *args], cwd=cwd, capture_output=True, text=True, timeout=20)
    except (OSError, subprocess.SubprocessError):
        return None
    return r.stdout if r.returncode == 0 else None


def sha256_bytes(data):
    return hashlib.sha256(data).hexdigest()


def proc_starttime(pid, proc_root="/proc"):
    """starttime (ticks, campo 22 de stat) identifica a instancia do PID; None se ausente."""
    try:
        stat = Path(proc_root, str(pid), "stat").read_text()
        return int(stat[stat.rindex(")") + 2:].split()[19])
    except (OSError, ValueError, IndexError):
        return None
