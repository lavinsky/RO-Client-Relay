"""Teste offline de relay/config.py: a config INI vira defaults do argparse com a precedência
defaults embutidos < arquivo < linha de comando, com coerção de tipo (bool/int/float/str),
chaves com traço ou sublinhado, e tratamento tolerante de chave desconhecida / valor inválido /
arquivo ausente. Simula um relay_capture.conf real escrito à mão."""
import argparse
import os
import tempfile

import _boot  # noqa: F401  (põe o repo no sys.path)
from relay.config import _config_value, load_config_defaults


def novo_parser():
    p = argparse.ArgumentParser()
    p.add_argument('--relay-format', default='xkore1')
    p.add_argument('--relay-port', type=int, default=2350)
    p.add_argument('--settle', type=float, default=0.15)
    p.add_argument('--inject', action='store_true')
    p.add_argument('--inject-persist', action=argparse.BooleanOptionalAction, default=False)
    return p

# --- _config_value: coerção por tipo da opção -------------------------------------------------
p = novo_parser()
por_nome = {a.dest: a for a in p._actions}
assert _config_value(por_nome['relay_port'], '2350') == 2350 and isinstance(_config_value(por_nome['relay_port'], '7'), int)
assert _config_value(por_nome['settle'], '0.25') == 0.25
assert _config_value(por_nome['relay_format'], 'raw') == 'raw'
for v in ('1', 'true', 'YES', 'on', 'True'):
    assert _config_value(por_nome['inject'], v) is True, v
for v in ('0', 'false', 'No', 'off'):
    assert _config_value(por_nome['inject'], v) is False, v
try:
    _config_value(por_nome['inject'], 'talvez'); assert False, 'deveria recusar bool inválido'
except ValueError:
    pass
print('_config_value ok')

# --- precedência: defaults embutidos < arquivo < CLI ------------------------------------------
def escreve_conf(texto):
    fd, caminho = tempfile.mkstemp(suffix='.conf'); os.close(fd)
    with open(caminho, 'w') as f:
        f.write(texto)
    return caminho

conf = escreve_conf(
    '[capture]\n'
    'relay-port = 9999\n'          # com traço
    'settle = 0.5\n'
    'inject = true\n'
    'inject_persist = yes\n'       # com sublinhado
    'coisa-inexistente = 1\n'      # chave desconhecida: ignorada com aviso
    'relay-format = \n'            # string vazia é válida
)

# sem config: ficam os defaults embutidos
p = novo_parser()
a = p.parse_args([])
assert a.relay_port == 2350 and a.settle == 0.15 and a.inject is False and a.inject_persist is False

# arquivo sobrepõe os defaults embutidos
p = novo_parser()
load_config_defaults(p, conf)
a = p.parse_args([])
assert a.relay_port == 9999 and a.settle == 0.5 and a.inject is True and a.inject_persist is True, vars(a)

# a CLI sobrepõe o arquivo
p = novo_parser()
load_config_defaults(p, conf)
a = p.parse_args(['--relay-port', '2350', '--no-inject-persist'])
assert a.relay_port == 2350 and a.inject_persist is False and a.settle == 0.5, vars(a)
print('precedência defaults < arquivo < CLI ok')

# --- robustez: valor inválido ignorado, arquivo ausente ignorado ------------------------------
ruim = escreve_conf('[capture]\nrelay-port = abc\nsettle = 0.9\n')   # port inválido: ignorado, settle vale
p = novo_parser(); load_config_defaults(p, ruim)
a = p.parse_args([])
assert a.relay_port == 2350 and a.settle == 0.9, vars(a)

p = novo_parser(); load_config_defaults(p, '/caminho/que/nao/existe.conf')   # não lança
assert p.parse_args([]).relay_port == 2350

sem_secao = escreve_conf('[outra]\nrelay-port = 1\n')                 # sem [capture]: ignorado
p = novo_parser(); load_config_defaults(p, sem_secao)
assert p.parse_args([]).relay_port == 2350

for c in (conf, ruim, sem_secao):
    os.unlink(c)
print('robustez (valor ruim / arquivo ausente / sem seção) ok')
print('ALL PASS')
