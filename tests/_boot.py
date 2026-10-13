"""Bootstrap comum dos testes offline (rodam como scripts: `python tests/test_*.py`).

Torna a raiz do repo importável (para `import relay...`) e carrega o módulo de entrada como `g`
(onde ficam os re-exports usados pelos testes). `FIXTURES` aponta para os dados gravados."""
import importlib.util
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)
FIXTURES = os.path.join(HERE, 'fixtures')
DATA = os.path.join(REPO, 'data')

if REPO not in sys.path:
    sys.path.insert(0, REPO)

_spec = importlib.util.spec_from_file_location('g', os.path.join(REPO, 'relay_capture_linux.py'))
g = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(g)
