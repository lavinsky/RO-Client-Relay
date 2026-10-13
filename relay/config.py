"""Carregar a config INI (seção [capture]) como defaults do argparse, para o script rodar sem opções.

Precedência: defaults embutidos < arquivo de config < linha de comando. As chaves são os nomes
longos das opções (traços ou sublinhados). Arquivo ausente/ilegível é ignorado."""
import argparse
import configparser
import os

from . import ROOT

DEFAULT_CONFIG = os.path.join(ROOT, 'relay_capture.conf')


def _config_value(act, val):
    """Converte a string da config para o tipo da opção (bool / int / float / str)."""
    if isinstance(act, (argparse._StoreTrueAction, argparse._StoreFalseAction,
                        argparse.BooleanOptionalAction)):
        s = val.strip().lower()
        if s in ('1', 'true', 'yes', 'on'):
            return True
        if s in ('0', 'false', 'no', 'off'):
            return False
        raise ValueError(val)
    if act.type in (int, float):
        return act.type(val)
    return val


def load_config_defaults(parser, path):
    """Usa a seção [capture] do INI como defaults do parser."""
    cp = configparser.ConfigParser(inline_comment_prefixes=('#', ';'))
    try:
        if not cp.read(path) or not cp.has_section('capture'):
            return
    except configparser.Error as e:
        print(f'[!] ignoring config {path}: {e}')
        return
    by_name = {opt[2:].replace('-', '_'): act          # --relay-format -> relay_format
               for act in parser._actions for opt in act.option_strings if opt.startswith('--')}
    defaults = {}
    for key, val in cp.items('capture'):
        act = by_name.get(key.replace('-', '_'))
        if act is None:
            print(f'[!] config: unknown setting "{key}" (ignored)')
            continue
        try:
            defaults[act.dest] = _config_value(act, val)
        except ValueError:
            print(f'[!] config: bad value for "{key}": {val!r} (ignored)')
    if defaults:
        parser.set_defaults(**defaults)
        print(f'[*] config: loaded {len(defaults)} settings from {path} (CLI options override these)')
