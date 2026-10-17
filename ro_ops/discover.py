"""discover (read-only): gadget Frida do cliente via relay.frida_bridge (sem reescrever o parsing de `ss`)
+ main_tid lido em /proc. Identidades (pid/porta/tid) sao reconsultadas a CADA execucao."""
import os

from . import contract as C
from .common import proc_starttime


def _default_ports_fn():
    from relay.frida_bridge import gadget_ports
    return gadget_ports


def _default_pid_of_port_fn():
    from relay.frida_bridge import pid_of_port
    return pid_of_port


def _matches(argv0, name):
    a = argv0.replace("\\", "/").lower()
    return a == name.lower() or a.endswith("/" + name.lower())


def main_tid(pid, proc_root="/proc"):
    """Thread lider Linux (tid == pid) se presente em /proc/<pid>/task; None se ilegivel."""
    try:
        tids = {int(t) for t in os.listdir(f"{proc_root}/{pid}/task") if t.isdigit()}
    except OSError:
        return None, None
    return (pid if pid in tids else None), len(tids)


def discover(name="uaRO.exe", ports_fn=None, pid_of_port_fn=None, proc_root="/proc"):
    caveats = [
        "identidades de runtime valem so para esta execucao; reinicio/relogin as invalida; nao cachear",
        "descoberta nao autoriza experimento nem prova exclusividade da janela",
        "main_tid e a thread lider Linux (tid==pid); a thread principal Win32/Wine pode diferir (nao verificado)",
        "ss -p so enxerga processos visiveis ao usuario atual",
    ]
    try:
        ports = (ports_fn or _default_ports_fn())()
    except (OSError, ImportError) as e:
        return C.make("discover", C.UNDETERMINED, {"error": type(e).__name__},
                      caveats + ["listagem de gadgets falhou (ss/import); ausencia nao e inferida"])
    cands = [{"port": p, "pid": pid, "argv0": a} for p, pid, a in ports if _matches(a, name)]
    data = {"target": name, "gadgets_listening": len(ports), "candidates": cands}
    if not cands:
        return C.make("discover", C.UNVERIFIED, data,
                      caveats + [f"nenhum gadget em processo '{name}' observado nesta execucao"])
    if len(cands) > 1:
        return C.make("discover", C.UNDETERMINED, data,
                      caveats + ["multiplos gadgets candidatos: nenhum escolhido; informar instancia ao responsavel"])
    c = cands[0]
    again = (pid_of_port_fn or _default_pid_of_port_fn())(c["port"])
    if again != c["pid"]:
        return C.make("discover", C.UNDETERMINED, data,
                      caveats + ["pid_of_port divergiu da listagem (corrida/reuso de porta)"])
    tid, nthreads = main_tid(c["pid"], proc_root)
    start = proc_starttime(c["pid"], proc_root)
    data.update(port=c["port"], pid=c["pid"], main_tid=tid, thread_count=nthreads, starttime_ticks=start)
    if tid is None:
        return C.make("discover", C.UNDETERMINED, data, caveats + ["/proc/<pid>/task ilegivel ou sem tid lider"])
    return C.make("discover", C.VERIFIED, data, caveats)
