#!/usr/bin/env python3
"""Verificação offline e conservadora do inventário de controle Gepard."""
from pathlib import Path

root = Path(__file__).resolve().parents[1]
table = (root / "data/uaro_recvpackets.txt").read_text(encoding="utf-8")
inventory = (root / "docs/GEPARD_CONTROL_PACKETS.md").read_text(encoding="utf-8")
decisions = (root / "docs/RESEARCH_DECISIONS.md").read_text(encoding="utf-8")
for value in ("8280 128", "4754 -1", "5395 -1", "C392 -1"):
    assert value in table.splitlines(), f"Tabela sem {value}"
for marker in ("0x8280", "0x8285", "SC_GEPARD_INIT", "CS_GEPARD_INIT_ACK",
               "OBSERVADO", "HIPÓTESE", "0x0438"):
    assert marker in inventory, f"Registro sem {marker}"
assert "xKore 0" in decisions and "0x035F" in decisions
print("RESEARCH DOCS PASS (presença e consistência básica; não verifica hipóteses)")
