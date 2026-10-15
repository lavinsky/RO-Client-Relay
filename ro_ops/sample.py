"""sample-thread (read-only): reutiliza research/movement_035f/sample_thread.py (stat/wchan/syscall,
sem kstkeip). Nenhuma logica de leitura/classificacao e duplicada aqui; so mapeia para o contrato."""
import importlib.util

from . import contract as C
from .common import ROOT

_SRC = ROOT / "research/movement_035f/sample_thread.py"


def load_sampler():
    spec = importlib.util.spec_from_file_location("ro_ops_sample_thread", _SRC)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _status(label):
    if label.startswith(("progressing", "spinning_userspace", "waiting/blocked", "terminated_or_exception")):
        return C.VERIFIED
    if label == "absent":
        return C.UNVERIFIED
    return C.UNDETERMINED   # running_userspace_stalled, mixed/indeterminate, no_samples


def sample(pid, tid, interval_ms=30, duration_ms=3000, sampler=None):
    if pid <= 0 or tid <= 0:
        raise C.UsageError("pid/tid devem ser positivos")
    if not (10 <= interval_ms <= 1000) or not (interval_ms <= duration_ms <= 60000):
        raise C.UsageError("limites: 10<=ms<=1000, ms<=duration-ms<=60000")
    st = sampler or load_sampler()
    series = st.sample_series(pid, tid, interval_ms, duration_ms)
    label = st.classify(series)
    present = [s for s in series if s.get("present")]
    ut = [s["utime"] for s in present if s.get("utime") is not None]
    states = {}
    for s in present:
        states[s["state"]] = states.get(s["state"], 0) + 1
    data = {"pid": pid, "tid": tid, "interval_ms": interval_ms, "samples": len(series),
            "present_samples": len(present), "classification": label, "kind": label.split("(")[0],
            "states": states, "utime_delta_ticks": (ut[-1] - ut[0]) if len(ut) >= 2 else None,
            "wchans": sorted({s["wchan"] for s in present if s.get("wchan") not in (None, "", "0")}),
            "syscall_nrs": sorted({s["syscall_nr"] for s in present if s.get("syscall_nr") is not None})}
    caveats = ["classificacao e observacional (amostragem em /proc); nao prova deadlock nem causa",
               "perda do observador so se infere comparando com a sessao do driver (nao feito aqui)",
               "'R' em userspace tambem e o estado normal ocioso (laco de render) deste cliente"]
    if data["kind"] == "terminated_or_exception":
        caveats.append("thread sumiu: nao distingue saida normal, excecao ou perda de observacao")
    if _status(label) == C.UNDETERMINED:
        caveats.append(f"classificacao '{label}' nao decide entre rivais; exigir PC/diagnostico adicional")
    if _status(label) == C.UNVERIFIED:
        caveats.append("thread nunca observada: pid/tid errados ou ja inexistentes")
    return C.make("sample-thread", _status(label), data, caveats)
