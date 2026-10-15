"""CLI: argparse + emissao do contrato JSON e exit codes (0 verified, 10 unverified, 20 undetermined,
1 erro de uso). Uso: python3 -m ro_ops.cli <subcomando>. Todo o resto vive nos modulos."""
import argparse
import sys

from . import contract as C


class _Parser(argparse.ArgumentParser):
    def error(self, message):
        raise C.UsageError(message)


def build_parser():
    ap = _Parser(prog="ro_ops", description=__doc__)
    sub = ap.add_subparsers(dest="cmd", required=True, parser_class=_Parser)
    d = sub.add_parser("discover", help="gadget do cliente + main_tid (read-only)")
    d.add_argument("--name", default="uaRO.exe")
    s = sub.add_parser("sample-thread", help="amostra /proc de uma thread (read-only)")
    s.add_argument("--pid", type=int, required=True)
    s.add_argument("--tid", type=int, required=True)
    s.add_argument("--ms", type=int, default=30)
    s.add_argument("--duration-ms", type=int, default=3000)
    sub.add_parser("env-check", help="pre-requisitos locais (read-only)")
    a = sub.add_parser("new-artifact", help="dir 0700 + PROVENANCE.txt (private-write)")
    a.add_argument("--dir", required=True)
    a.add_argument("--pid", type=int)
    a.add_argument("--probe", action="append", default=[])
    c = sub.add_parser("scaffold-state", help="STATE.md/HANDOFF.md em research/<trilha>/ (private-write)")
    c.add_argument("--dir", required=True)
    c.add_argument("--role", default="PESQUISADOR")
    c.add_argument("--id", default="ID-A-DEFINIR")
    return ap


def run(args, deps):
    if args.cmd == "discover":
        from .discover import discover
        return discover(args.name, **deps.get("discover", {}))
    if args.cmd == "sample-thread":
        from .sample import sample
        return sample(args.pid, args.tid, args.ms, args.duration_ms, **deps.get("sample", {}))
    if args.cmd == "env-check":
        from .env import env_check
        return env_check(**deps.get("env", {}))
    if args.cmd == "new-artifact":
        from .artifact import new_artifact
        return new_artifact(args.dir, args.pid, args.probe, **deps.get("artifact", {}))
    from .scaffold import scaffold
    return scaffold(args.dir, args.role, args.id)


def main(argv=None, stdout=None, deps=None):
    out = stdout or sys.stdout
    argv = sys.argv[1:] if argv is None else list(argv)
    name = argv[0] if argv and not argv[0].startswith("-") else "ro_ops"
    try:
        result = run(build_parser().parse_args(argv), deps or {})
    except C.UsageError as e:
        result = C.error(name, e, ["erro de uso: nada foi medido nem escrito"])
    except SystemExit as e:                      # --help
        return int(e.code or 0)
    except Exception as e:                       # falha inesperada nunca vira positivo
        result = C.error(name, type(e).__name__, ["falha inesperada: nada pode ser afirmado"])
    return C.emit(result, out)


if __name__ == "__main__":
    sys.path.insert(0, str(__import__("pathlib").Path(__file__).resolve().parents[1]))
    sys.exit(main())
