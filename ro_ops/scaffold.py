"""scaffold-state (private-write): cria STATE.md/HANDOFF.md a partir dos templates canonicos em
diretorio de pesquisador existente (research/<trilha>/). Nunca sobrescreve arquivo existente."""
import os
from pathlib import Path

from . import contract as C
from .artifact import check_target
from .common import utc_now

TEMPLATES = Path(__file__).resolve().parent / "templates"
FILES = ("STATE.md", "HANDOFF.md")


def scaffold(directory, role="PESQUISADOR", round_id="ID-A-DEFINIR"):
    for v in (role, round_id):
        if not v or len(v) > 64 or not all(c.isalnum() or c in "-_ ." for c in v):
            raise C.UsageError("role/id: ate 64 caracteres [A-Za-z0-9 -_.]")
    target = check_target(directory, must_exist=True)
    subs = {"{{ROLE}}": role, "{{ID}}": round_id, "{{DATE}}": utc_now()[:10]}
    created, skipped = [], []
    for name in FILES:
        text = (TEMPLATES / name).read_text(encoding="utf-8")
        for k, v in subs.items():
            text = text.replace(k, v)
        try:
            fd = os.open(target / name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
        except FileExistsError:
            skipped.append(name)
            continue
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(text)
        created.append(name)
    caveats = ["templates sao esqueleto: nenhum campo cientifico foi preenchido nem verificado",
               "campos 'A PREENCHER' permanecem pendentes ate o pesquisador registra-los"]
    status = C.VERIFIED
    if skipped:
        status = C.UNVERIFIED
        caveats.append(f"existentes e preservados (nao sobrescritos): {', '.join(skipped)}")
    return C.make("scaffold-state", status, {"directory": str(target), "created": created, "skipped": skipped}, caveats)
