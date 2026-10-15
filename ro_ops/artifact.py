"""new-artifact (private-write): cria diretorio 0700 NOVO do pesquisador com PROVENANCE.txt
(PID, HEAD git, sha256 das sondas, timestamp), espelhando tools_sha256/_hash_copy de CIFRA/MOVER.
Nunca escreve em docs/, relay/, agent/, config ou sondas."""
import os
import shutil
import stat
from pathlib import Path

from . import contract as C
from .common import ROOT, git, proc_starttime, sha256_bytes, utc_now

MAX_PROBE_BYTES = 1 << 20


def check_target(path, *, must_exist):
    """Resolve e valida o alvo de escrita. Dentro do repo so research/<trilha>/...; fora, qualquer
    diretorio proprio do usuario. Rejeita symlink e raiz do repo."""
    p = Path(path)
    if p.is_symlink():
        raise C.UsageError("symlink recusado")
    p = p.resolve() if must_exist or p.exists() else p.parent.resolve() / p.name
    try:
        rel = p.relative_to(ROOT)
    except ValueError:
        rel = None
    if rel is not None and not (len(rel.parts) >= 2 and rel.parts[0] == "research"):
        raise C.UsageError("escrita no repo so em research/<trilha>/ (nunca docs/, relay/, agent/, config, sondas)")
    if must_exist and not p.is_dir():
        raise C.UsageError("diretorio inexistente")
    if not must_exist and p.exists():
        raise C.UsageError("alvo ja existe; new-artifact nunca sobrescreve")
    if not p.parent.is_dir():
        raise C.UsageError("diretorio pai inexistente")
    return p


def _probe(path):
    p = Path(path)
    if p.is_symlink() or not p.is_file():
        raise C.UsageError(f"sonda invalida: {path}")
    p = p.resolve()
    try:
        rel = p.relative_to(ROOT)
    except ValueError:
        raise C.UsageError("sondas devem estar dentro do repositorio")
    if rel.parts[0] == "relay" and len(rel.parts) > 1 and rel.parts[1] == "resources":
        raise C.UsageError("relay/resources/ e artefato externo")
    data = p.read_bytes()
    if len(data) > MAX_PROBE_BYTES:
        raise C.UsageError("sonda acima do limite de 1 MiB")
    return p, rel, data


def new_artifact(directory, pid=None, probes=(), proc_root="/proc"):
    target = check_target(directory, must_exist=False)
    loaded = [_probe(x) for x in probes]
    names = [p.name for p, _, _ in loaded]
    if len(set(names)) != len(names):
        raise C.UsageError("sondas com o mesmo nome base")
    head = (git("rev-parse", "HEAD") or "").strip() or None
    rels = [str(r) for _, r, _ in loaded]
    porcelain = git("status", "--porcelain", "--", *rels) if rels and head else ("" if head else None)
    diff = git("diff", "HEAD", "--", *rels) if rels and head else ("" if head else None)
    start = proc_starttime(pid, proc_root) if pid is not None else None

    target.mkdir(mode=0o700)
    os.chmod(target, 0o700)
    manifest = []
    for p, rel, data in loaded:
        shutil.copy2(p, target / p.name)
        manifest.append((str(rel), sha256_bytes(data)))
    lines = ["# PROVENANCE (ro_ops new-artifact); sem credenciais, trafego ou dados crus",
             f"created_utc: {utc_now()}",
             f"repository_head: {head or 'UNKNOWN'}",
             f"working_tree_probes: {'UNKNOWN' if porcelain is None else ('dirty' if porcelain.strip() else 'clean')}",
             f"probes_diff_sha256: {sha256_bytes(diff.encode()) if diff is not None else 'UNKNOWN'}",
             f"pid: {pid if pid is not None else 'not_given'}",
             f"pid_starttime_ticks: {start if start is not None else 'not_observed'}",
             "runtime_identity_note: valida so para a sessao em que foi registrada; reinicio/relogin invalida"]
    lines += [f"tools_sha256: {h}  {r}" for r, h in manifest]
    fd = os.open(target / "PROVENANCE.txt", os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
    with os.fdopen(fd, "w") as f:
        f.write("\n".join(lines) + "\n")

    caveats = ["PROVENANCE registra o que foi medido neste momento; nao prova que a sonda executada e a copiada",
               "diretorio dentro do repo pode ser versionavel: conferir .gitignore antes de qualquer add"]
    statuses = []
    if head is None:
        statuses.append(C.UNDETERMINED); caveats.append("HEAD git nao determinado")
    if porcelain is None and rels:
        statuses.append(C.UNDETERMINED); caveats.append("estado do working tree das sondas nao determinado")
    if pid is not None and start is None:
        statuses.append(C.UNVERIFIED); caveats.append("pid informado nao observado em /proc")
    if pid is None:
        caveats.append("nenhum PID registrado")
    data = {"directory": str(target), "mode": oct(stat.S_IMODE(target.stat().st_mode)),
            "files": ["PROVENANCE.txt"] + names, "probes": len(loaded), "repository_head": head}
    return C.make("new-artifact", C.worst(*statuses), data, caveats)
