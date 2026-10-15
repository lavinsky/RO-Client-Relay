"""Entry point: `python3 -m ro_ops <subcomando>` a partir da raiz do repo.

Executar `python3 ro_ops/cli.py` diretamente falha (import relativo sem pacote-pai);
use sempre a invocação de módulo, que resolve o pacote corretamente.
"""
import sys

from ro_ops.cli import main

if __name__ == "__main__":
    sys.exit(main())
