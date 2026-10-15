"""env-check (read-only): pre-requisitos locais medidos. NUNCA conclui exclusividade da janela:
ausencia de processo/lock nao e autorizacao (COORDINATION.md, Cliente compartilhado)."""
import importlib.util
import os
import shutil
import sys

from . import contract as C
from .common import ROOT, git


def _default_probes():
    ptrace = None
    try:
        ptrace = open("/proc/sys/kernel/yama/ptrace_scope").read().strip()
    except OSError:
        pass
    return {"python": sys.version_info[:3], "ss": shutil.which("ss") is not None,
            "git_head": (git("rev-parse", "HEAD") or "").strip() or None,
            "proc_readable": os.access("/proc/self/stat", os.R_OK),
            "frida_module": importlib.util.find_spec("frida") is not None,
            "ptrace_scope": ptrace}


def env_check(probes=None):
    p = probes if probes is not None else _default_probes()
    checks = {}

    def check(key, ok, required=True):
        checks[key] = {"result": "unknown" if ok is None else ("pass" if ok else "fail"), "required": required}

    py = p.get("python")
    check("python>=3.11", None if py is None else tuple(py) >= (3, 11))
    check("ss_available", p.get("ss"))
    check("proc_readable", p.get("proc_readable"))
    check("git_head", None if p.get("git_head") is None else True)
    check("frida_module", p.get("frida_module"), required=False)   # so o driver vivo exige
    req = [v["result"] for v in checks.values() if v["required"]]
    status = (C.UNDETERMINED if "unknown" in req else C.UNVERIFIED if "fail" in req else C.VERIFIED)
    data = {"repo_root": str(ROOT), "git_head": p.get("git_head"), "checks": checks,
            "ptrace_scope": p.get("ptrace_scope"),
            "exclusivity": "not_determined", "authorization": "none_granted_by_this_command"}
    caveats = ["exclusividade da janela NAO verificada: ausencia de processo/lock nao e autorizacao",
               "confirmacao explicita do responsavel (instancia e escopo) e necessaria antes de qualquer coleta",
               "so pre-requisitos locais offline; nao testa cliente, gadget, servidor nem Frida",
               "frida_module e informativo: a checagem so detecta presenca, nao compatibilidade de versao"]
    if status != C.VERIFIED:
        caveats.append("pre-requisito falhou ou nao pode ser medido: ver data.checks")
    return C.make("env-check", status, data, caveats)
