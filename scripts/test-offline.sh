#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
shopt -s nullglob
tests=(tests/test_*.py)
if (( ${#tests[@]} == 0 )); then
  echo "Nenhum teste tests/test_*.py encontrado" >&2
  exit 2
fi
for t in "${tests[@]}"; do
  echo "[offline] $t"
  python3 "$t"
done
echo "[offline] PASS (${#tests[@]} scripts)"
