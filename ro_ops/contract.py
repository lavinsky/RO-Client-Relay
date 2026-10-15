"""Contrato unico de saida: {cmd, status, data, caveats}. Nenhum comando afirma mais do que mediu."""
import json

VERIFIED, UNVERIFIED, UNDETERMINED, ERROR = "verified", "unverified", "undetermined", "error"
STATUSES = (VERIFIED, UNVERIFIED, UNDETERMINED, ERROR)
EXIT_CODES = {VERIFIED: 0, UNVERIFIED: 10, UNDETERMINED: 20, ERROR: 1}

# Separacao de classes: cada subcomando pertence a exatamente uma.
READ_ONLY, PRIVATE_WRITE = "read-only", "private-write"
COMMAND_CLASS = {"discover": READ_ONLY, "sample-thread": READ_ONLY, "env-check": READ_ONLY,
                 "new-artifact": PRIVATE_WRITE, "scaffold-state": PRIVATE_WRITE}

# Credenciais/trafego nunca entram em saida ou artefato.
FORBIDDEN_KEYS = ("password", "passwd", "token", "secret", "credential", "cookie",
                  "payload", "packet", "traffic", "raw_bytes")


class UsageError(Exception):
    """Erro de uso (argumentos/escopo invalido): status error, exit 1."""


def _scan(obj, path="data"):
    if isinstance(obj, dict):
        for k, v in obj.items():
            if any(f in str(k).lower() for f in FORBIDDEN_KEYS):
                raise ValueError(f"forbidden key in output: {path}.{k}")
            _scan(v, f"{path}.{k}")
    elif isinstance(obj, (list, tuple)):
        for i, v in enumerate(obj):
            _scan(v, f"{path}[{i}]")


def make(cmd, status, data=None, caveats=None):
    if status not in STATUSES:
        raise ValueError(f"invalid status: {status!r}")
    data = dict(data or {})
    caveats = [str(c) for c in (caveats or [])]
    if status in (UNVERIFIED, UNDETERMINED) and not caveats:
        raise ValueError(f"status {status} requires caveats listing what was not verified")
    if cmd in COMMAND_CLASS:
        data.setdefault("class", COMMAND_CLASS[cmd])
    _scan(data)
    return {"cmd": cmd, "status": status, "data": data, "caveats": caveats}


def error(cmd, message, caveats=None):
    return make(cmd, ERROR, {"message": str(message)}, caveats or ["nothing was measured"])


def exit_code(result):
    return EXIT_CODES[result["status"]]


def worst(*statuses):
    """Combina medicoes parciais: undetermined > unverified > verified; undetermined nunca vira positivo."""
    for s in (ERROR, UNDETERMINED, UNVERIFIED):
        if s in statuses:
            return s
    return VERIFIED


def emit(result, stream):
    stream.write(json.dumps(result, ensure_ascii=False, sort_keys=True) + "\n")
    return exit_code(result)
