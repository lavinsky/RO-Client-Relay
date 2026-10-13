#!/usr/bin/env bash
# setup.sh - prepara esta máquina para rodar o relay de depuração do cliente uaRO.
#
# Faz o trabalho chato de uma vez: cria o venv do Python, instala o frida (versão fixada em
# requirements.txt) e baixa o frida-gadget de 32 bits que CASA essa versão, deixando-o em
# relay/resources/ junto do .config que o gadget lê. No fim, imprime a opção de inicialização
# do Steam e os próximos passos.
#
# Uso:   ./setup.sh [DIR_DO_VENV]        (padrão: ~/.venv-frida)
# Reentrante: pular o que já está pronto; passe --force-gadget para rebaixar o gadget.
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
VENV="${1:-$HOME/.venv-frida}"
RES="$HERE/relay/resources"
GADGET_SO="$RES/frida-gadget-32.so"
GADGET_CFG="$RES/frida-gadget-32.config"
FORCE_GADGET=0
[ "${1:-}" = "--force-gadget" ] && { FORCE_GADGET=1; VENV="$HOME/.venv-frida"; }
[ "${2:-}" = "--force-gadget" ] && FORCE_GADGET=1

say() { printf '\033[1m[setup]\033[0m %s\n' "$*"; }
die() { printf '\033[31m[setup] %s\033[0m\n' "$*" >&2; exit 1; }

# 1) venv + frida -------------------------------------------------------------------------------
command -v python3 >/dev/null || die "python3 não encontrado"
if [ ! -x "$VENV/bin/python" ]; then
    say "criando venv em $VENV"
    python3 -m venv "$VENV"
fi
say "instalando dependências (requirements.txt)"
"$VENV/bin/python" -m pip install --quiet --upgrade pip
"$VENV/bin/python" -m pip install --quiet -r "$HERE/requirements.txt"
FRIDA_VER="$("$VENV/bin/python" -c 'import frida; print(frida.__version__)')"
say "frida $FRIDA_VER instalado em $VENV"

# 2) frida-gadget de 32 bits que casa a versão --------------------------------------------------
mkdir -p "$RES"
if [ "$FORCE_GADGET" = 1 ] || [ ! -f "$GADGET_SO" ]; then
    URL="https://github.com/frida/frida/releases/download/${FRIDA_VER}/frida-gadget-${FRIDA_VER}-linux-x86.so.xz"
    say "baixando o gadget 32 bits: $URL"
    tmp="$(mktemp)"
    if command -v curl >/dev/null; then curl -fL --progress-bar "$URL" -o "$tmp"
    elif command -v wget >/dev/null; then wget -q --show-progress "$URL" -O "$tmp"
    else die "nem curl nem wget disponíveis para baixar o gadget"; fi
    say "descompactando -> $GADGET_SO"
    "$VENV/bin/python" - "$tmp" "$GADGET_SO" <<'PY'
import lzma, sys
with lzma.open(sys.argv[1]) as f, open(sys.argv[2], 'wb') as o:
    o.write(f.read())
PY
    rm -f "$tmp"
else
    say "gadget já presente: $GADGET_SO (use --force-gadget para rebaixar)"
fi

# 3) config do gadget (o frida lê o .config de mesmo nome ao lado do .so) ------------------------
if [ ! -f "$GADGET_CFG" ]; then
    say "escrevendo $GADGET_CFG"
    cat > "$GADGET_CFG" <<'JSON'
{
  "interaction": {
    "type": "listen",
    "address": "127.0.0.1",
    "port": 27052,
    "on_port_conflict": "pick-next",
    "on_load": "resume"
  }
}
JSON
fi

chmod +x "$HERE/run.sh" 2>/dev/null || true

# 4) próximos passos ----------------------------------------------------------------------------
cat <<EOF

$(say "pronto.")

1) No Steam, defina a opção de inicialização do jogo (LD_PRELOAD do gadget):

     LD_PRELOAD=$GADGET_SO %command%

2) Suba o consumidor (OpenKore) em XKore 1 (ver README, seção "Consumidor (OpenKore)").

3) Com o cliente aberto, rode o relay:

     $HERE/run.sh

   (sem opções usa relay_capture.conf; qualquer --flag é repassada ao capturador.)
EOF
